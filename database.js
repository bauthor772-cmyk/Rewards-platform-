// ================================================================
// database.js — PostgreSQL connection pool
//
// Exports:
//   query(text, params)         — single parameterised statement
//   getClient()                 — raw checked-out client
//   withTransaction(callback)   — auto-commit / auto-rollback wrapper
//   testConnection()            — called once at server startup
//   closePool()                 — called during graceful shutdown
//   pool                        — raw pg.Pool (for libraries that need it)
// ================================================================

'use strict';

require('dotenv').config();

const { Pool } = require('pg');
const winston  = require('winston');


// ── Module-level logger ──────────────────────────────────────────
// Covers pool-level events only.
// The main application logger lives in server.js.
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      silent: process.env.NODE_ENV === 'test',
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          const extras = Object.keys(meta).length
            ? ' ' + JSON.stringify(meta)
            : '';
          return `${timestamp} [${level}] [DB] ${message}${extras}`;
        })
      ),
    }),
  ],
});


// ── Pool configuration ───────────────────────────────────────────
const SSL_ENABLED = process.env.DB_SSL === 'true';

const poolConfig = {
  host    : process.env.DB_HOST     || 'localhost',
  port    : parseInt(process.env.DB_PORT || '5432', 10),
  database: process.env.DB_NAME     || 'content_rewards',
  user    : process.env.DB_USER     || 'postgres',
  password: process.env.DB_PASSWORD || '',

  min: parseInt(process.env.DB_POOL_MIN || '2',  10),
  max: parseInt(process.env.DB_POOL_MAX || '10', 10),

  idleTimeoutMillis      : parseInt(process.env.DB_IDLE_TIMEOUT_MS        || '30000', 10),
  connectionTimeoutMillis: parseInt(process.env.DB_CONNECTION_TIMEOUT_MS  || '5000',  10),

  ssl: SSL_ENABLED ? { rejectUnauthorized: false } : false,
};

const pool = new Pool(poolConfig);


// ── Pool event handlers ──────────────────────────────────────────

pool.on('connect', async (client) => {
  logger.debug('New client connected to pool', {
    host    : poolConfig.host,
    database: poolConfig.database,
  });

  // Critical: set UTC timezone on every physical connection so that
  // DATE(viewed_at) in the anti-fraud unique index always resets at
  // UTC midnight, regardless of the operating system locale.
  const statementTimeoutMs = parseInt(
    process.env.DB_STATEMENT_TIMEOUT_MS || '10000', 10
  );

  try {
    await client.query(`SET timezone = 'UTC'`);
    await client.query(`SET statement_timeout = ${statementTimeoutMs}`);
  } catch (err) {
    logger.warn('Could not apply per-connection settings', {
      error: err.message,
    });
  }
});

pool.on('acquire', () => {
  logger.debug('Client acquired from pool');
});

pool.on('remove', () => {
  logger.debug('Client removed from pool');
});

pool.on('error', (err) => {
  // Fires when an idle client encounters a network error.
  // pg-pool discards the broken client and creates a fresh one.
  // Do NOT call process.exit() here.
  logger.error('Unexpected error on idle pool client', {
    error: err.message,
    code : err.code,
  });
});


// ================================================================
// EXPORTED HELPERS
// ================================================================

/**
 * Execute a single parameterised SQL statement.
 *
 * Checks a client from the pool, runs the query, and immediately
 * returns the client. Safe to call for every independent statement.
 *
 * @param  {string} text        SQL with $1 … $N placeholders
 * @param  {Array}  [params]    Parameter values
 * @returns {Promise<import('pg').QueryResult>}
 *
 * @example
 * const result = await db.query(
 *   'SELECT id, username FROM users WHERE id = $1',
 *   [userId]
 * );
 */
async function query(text, params) {
  const start = Date.now();

  try {
    const result   = await pool.query(text, params);
    const duration = Date.now() - start;

    logger.debug('Query executed', {
      sql     : text.length > 150 ? text.substring(0, 150) + '…' : text,
      duration: `${duration}ms`,
      rows    : result.rowCount,
    });

    return result;
  } catch (err) {
    logger.error('Query failed', {
      sql  : text.length > 150 ? text.substring(0, 150) + '…' : text,
      error: err.message,
      code : err.code,
    });
    throw err;
  }
}


/**
 * Check out a dedicated client from the pool.
 *
 * Use when statements must share a single connection (advisory
 * locks, LISTEN/NOTIFY, manual transaction control).
 *
 * IMPORTANT: always call client.release() in a finally block.
 * A leaked client will eventually starve the pool.
 *
 * @returns {Promise<import('pg').PoolClient>}
 */
async function getClient() {
  const client = await pool.connect();

  // Wrap release() to guard against double-release bugs
  const originalRelease = client.release.bind(client);
  let released = false;

  client.release = (destroy) => {
    if (released) {
      logger.warn('client.release() called more than once — ignoring');
      return;
    }
    released = true;
    logger.debug('Client released back to pool');
    originalRelease(destroy);
  };

  return client;
}


/**
 * Execute a callback inside an automatically managed transaction.
 *
 * Issues BEGIN before the callback, COMMIT on success, ROLLBACK on
 * any thrown error. Always releases the client back to the pool.
 *
 * The callback receives the checked-out PoolClient so it can issue
 * multiple statements on the same connection.
 *
 * @param  {function(import('pg').PoolClient): Promise<*>} callback
 * @returns {Promise<*>} The value returned by the callback
 *
 * @example
 * const result = await db.withTransaction(async (client) => {
 *   await client.query('UPDATE users SET balance = balance - $1 WHERE id = $2', [10, userId]);
 *   await client.query('INSERT INTO audit_log (action) VALUES ($1)', ['debit']);
 *   return { ok: true };
 * });
 */
async function withTransaction(callback) {
  const client = await getClient();

  try {
    await client.query('BEGIN');
    logger.debug('Transaction started');

    const result = await callback(client);

    await client.query('COMMIT');
    logger.debug('Transaction committed');

    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
      logger.warn('Transaction rolled back', { error: err.message });
    } catch (rollbackErr) {
      logger.error('ROLLBACK itself failed', { error: rollbackErr.message });
    }
    throw err;
  } finally {
    client.release();
  }
}


/**
 * Verify the pool can reach the database.
 * Called once at server startup; throws on failure so the server
 * exits rather than listening on a broken connection.
 *
 * @returns {Promise<void>}
 */
async function testConnection() {
  const result = await query(
    `SELECT NOW() AS server_time,
            current_database() AS db_name,
            version()          AS pg_version`
  );

  const row = result.rows[0];
  logger.info('Database connection verified', {
    serverTime: row.server_time,
    database  : row.db_name,
    postgres  : row.pg_version.split(',')[0],
  });
}


/**
 * Gracefully drain and close all pool connections.
 * Called during SIGTERM / SIGINT shutdown.
 *
 * @returns {Promise<void>}
 */
async function closePool() {
  logger.info('Draining database connection pool…');
  await pool.end();
  logger.info('Database pool closed cleanly');
}


// ── Exports ──────────────────────────────────────────────────────
module.exports = {
  query,
  getClient,
  withTransaction,
  testConnection,
  closePool,
  pool,
};
