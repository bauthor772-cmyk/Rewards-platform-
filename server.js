// ================================================================
// server.js — Main Express application entry point
//
// Route groups mounted under API_PREFIX (/api/v1):
//
//   Auth          POST /auth/register
//                 POST /auth/login
//
//   User          GET  /users/me
//                 PATCH /users/me
//                 GET  /users/me/earnings   (milestone progress included)
//
//   Views         POST /views/track         (10-gate anti-fraud pipeline)
//
//   Withdrawals   POST /withdrawals
//                 GET  /withdrawals
//
//   Campaigns     GET  /campaigns
//                 POST /campaigns
//                 PATCH /campaigns/:id/status
//
//   Admin         GET  /admin/stats
//                 GET  /admin/withdrawals
//                 PATCH /admin/withdrawals/:id
//                 PATCH /admin/views/:id/flag
//                 GET  /admin/fraud-signals
//                 GET  /admin/users
//                 PATCH /admin/users/:id/status
// ================================================================

'use strict';

require('dotenv').config();

const express     = require('express');
const helmet      = require('helmet');
const cors        = require('cors');
const morgan      = require('morgan');
const compression = require('compression');
const rateLimit   = require('express-rate-limit');
const {
  body,
  param,
  query: qv,
  validationResult,
} = require('express-validator');
const bcrypt         = require('bcryptjs');
const jwt            = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const winston        = require('winston');
const fs             = require('fs');
const path           = require('path');

const db = require('./database');


// ================================================================
// CONSTANTS
// ================================================================

const PORT        = parseInt(process.env.PORT         || '3000', 10);
const NODE_ENV    = process.env.NODE_ENV              || 'development';
const API         = `/api/${process.env.API_VERSION   || 'v1'}`;

const JWT_SECRET          = process.env.JWT_SECRET          || 'insecure_dev_secret_replace_me';
const JWT_EXPIRES_IN      = process.env.JWT_EXPIRES_IN      || '7d';
const JWT_REFRESH_SECRET  = process.env.JWT_REFRESH_SECRET  || 'insecure_refresh_replace_me';

const MIN_WATCH_SECONDS  = parseInt(process.env.MIN_WATCH_SECONDS      || '30',   10);
const MIN_WITHDRAWAL     = parseFloat(process.env.MIN_WITHDRAWAL_AMOUNT || '5.00');
const WITHDRAWAL_FEE_PCT = parseFloat(process.env.WITHDRAWAL_FEE_PERCENT || '2.5');
const MAX_VIEWS_PER_IP   = parseInt(process.env.MAX_VIEWS_PER_IP_PER_DAY || '5',  10);
const MILESTONE_MULT     = parseFloat(process.env.MILESTONE_BONUS_MULTIPLIER || '1.5');

const MILESTONE_THRESHOLDS = (
  process.env.MILESTONE_THRESHOLDS || '10,50,100,500,1000,5000,10000'
)
  .split(',')
  .map((s) => parseInt(s.trim(), 10))
  .filter((n) => Number.isFinite(n) && n > 0)
  .sort((a, b) => a - b);


// ================================================================
// LOGGER
// ================================================================

const LOG_DIR = path.dirname(process.env.LOG_FILE || 'logs/app.log');
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      silent: NODE_ENV === 'test',
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          const extras = Object.keys(meta).length
            ? ' ' + JSON.stringify(meta)
            : '';
          return `${timestamp} [${level}] ${message}${extras}`;
        })
      ),
    }),
    new winston.transports.File({
      filename: process.env.LOG_FILE       || 'logs/app.log',
      maxsize : 10 * 1024 * 1024,
      maxFiles: 7,
      tailable: true,
    }),
    new winston.transports.File({
      filename: process.env.LOG_ERROR_FILE || 'logs/error.log',
      level   : 'error',
      maxsize : 10 * 1024 * 1024,
      maxFiles: 7,
      tailable: true,
    }),
  ],
});


// ================================================================
// EXPRESS APP
// ================================================================

const app = express();

// Trust the first proxy hop (Nginx, Railway, Render, etc.)
// so req.ip returns the real client IP, not the proxy IP.
app.set('trust proxy', 1);


// ================================================================
// MIDDLEWARE STACK
// ================================================================

app.use(helmet());

// ── CORS ──────────────────────────────────────────────────────
const allowedOrigins = (process.env.CORS_ORIGIN || 'http://localhost:5173')
  .split(',')
  .map((o) => o.trim());

app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error(`CORS: origin '${origin}' is not allowed`));
  },
  methods        : (process.env.CORS_METHODS || 'GET,POST,PUT,PATCH,DELETE,OPTIONS').split(','),
  allowedHeaders : ['Content-Type', 'Authorization'],
  exposedHeaders : ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
  credentials    : true,
  optionsSuccessStatus: 204,
}));

app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

if (NODE_ENV !== 'test') {
  app.use(
    morgan('combined', {
      stream: { write: (msg) => logger.http(msg.trim()) },
    })
  );
}

// ── Rate limiters ─────────────────────────────────────────────

const globalLimiter = rateLimit({
  windowMs       : parseInt(process.env.RATE_LIMIT_WINDOW_MS    || '900000', 10),
  max            : parseInt(process.env.RATE_LIMIT_MAX_REQUESTS  || '100',    10),
  standardHeaders: true,
  legacyHeaders  : false,
  message        : { success: false, message: 'Too many requests. Please slow down.' },
});
app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs       : parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS || '900000', 10),
  max            : parseInt(process.env.AUTH_RATE_LIMIT_MAX       || '20',     10),
  standardHeaders: true,
  legacyHeaders  : false,
  message        : { success: false, message: 'Too many auth attempts. Try again later.' },
});

const viewLimiter = rateLimit({
  windowMs       : parseInt(process.env.VIEW_RATE_LIMIT_WINDOW_MS || '86400000', 10),
  max            : parseInt(process.env.VIEW_RATE_LIMIT_MAX       || '50',       10),
  standardHeaders: true,
  legacyHeaders  : false,
  keyGenerator   : (req) => `view:${getClientIP(req)}:${req.body?.campaignId || 'none'}`,
  message        : { success: false, message: 'Daily view limit reached from this IP.' },
});


// ================================================================
// UTILITY FUNCTIONS
// ================================================================

function getClientIP(req) {
  if (req.ip) return req.ip;
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.socket?.remoteAddress || '0.0.0.0';
}

function sendSuccess(res, data, status = 200) {
  return res.status(status).json({ success: true, ...data });
}

function sendError(res, status, message, details = undefined) {
  const payload = { success: false, message };
  if (details !== undefined) payload.details = details;
  return res.status(status).json(payload);
}

function hasValidationErrors(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    sendError(res, 422, 'Validation failed', errors.array());
    return true;
  }
  return false;
}

/**
 * Inspect request headers for bot / automation signals.
 * Returns { flagged: boolean, reason: string | null }
 */
function detectBotSignals(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase().trim();

  if (!ua) {
    return { flagged: true, reason: 'Missing User-Agent header' };
  }

  const botPatterns = [
    'headlesschrome', 'phantomjs', 'selenium', 'webdriver',
    'puppeteer', 'playwright', 'python-requests', 'python-urllib',
    'go-http-client', 'java/', 'wget/', 'curl/', 'libwww-perl',
    'scrapy', 'mechanize', 'httpclient', 'okhttp', 'axios/',
  ];

  for (const pattern of botPatterns) {
    if (ua.includes(pattern)) {
      return { flagged: true, reason: `Suspicious User-Agent: ${pattern}` };
    }
  }

  if (!req.headers['accept']) {
    return { flagged: true, reason: 'Missing Accept header' };
  }

  if (!req.headers['accept-language']) {
    return { flagged: true, reason: 'Missing Accept-Language header' };
  }

  return { flagged: false, reason: null };
}

/**
 * Return every MILESTONE_THRESHOLDS value crossed by incrementing
 * from previousCount to newCount (i.e. previousCount + 1).
 *
 * @param {number} previousCount  credited views BEFORE this one
 * @param {number} newCount       credited views AFTER this one
 * @param {number} costPerView    campaign cost_per_view (USD)
 * @param {string} campaignId
 * @param {string} userId
 * @returns {Array<{ threshold, bonusAmount, campaignId, userId }>}
 */
function getMilestonesCrossed(previousCount, newCount, costPerView, campaignId, userId) {
  const crossed = [];
  for (const threshold of MILESTONE_THRESHOLDS) {
    if (previousCount < threshold && newCount >= threshold) {
      crossed.push({
        threshold,
        bonusAmount: parseFloat((costPerView * MILESTONE_MULT).toFixed(6)),
        campaignId,
        userId,
      });
    }
  }
  return crossed;
}


// ================================================================
// JWT MIDDLEWARE
// ================================================================

function authenticate(req, res, next) {
  const header = req.headers['authorization'] || '';
  if (!header.startsWith('Bearer ')) {
    return sendError(res, 401, 'Authentication required. Provide a Bearer token.');
  }

  const token = header.slice(7).trim();
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return sendError(res, 401, 'Token expired. Please log in again.');
    }
    return sendError(res, 401, 'Invalid token.');
  }
}

function authorize(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return sendError(res, 403, 'You do not have permission to perform this action.');
    }
    next();
  };
}


// ================================================================
// HEALTH CHECK  (public)
// ================================================================

app.get('/health', async (req, res) => {
  try {
    const result = await db.query('SELECT NOW() AS now');
    return sendSuccess(res, {
      status: 'ok',
      dbTime: result.rows[0].now,
      uptime: process.uptime(),
      env   : NODE_ENV,
    });
  } catch (err) {
    logger.error('Health check failed', { error: err.message });
    return sendError(res, 503, 'Database unavailable.');
  }
});


// ================================================================
// AUTH ROUTES
// ================================================================

/**
 * POST /api/v1/auth/register
 * Body: { email, username, password, role?, full_name? }
 */
app.post(
  `${API}/auth/register`,
  authLimiter,
  [
    body('email')
      .isEmail().withMessage('A valid email is required.')
      .normalizeEmail(),
    body('username')
      .isAlphanumeric().withMessage('Username must be alphanumeric.')
      .isLength({ min: 3, max: 50 }).withMessage('Username must be 3–50 characters.'),
    body('password')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters.')
      .matches(/[A-Z]/).withMessage('Password must include an uppercase letter.')
      .matches(/[0-9]/).withMessage('Password must include a number.'),
    body('role')
      .optional()
      .isIn(['creator', 'advertiser']).withMessage("Role must be 'creator' or 'advertiser'."),
    body('full_name')
      .optional()
      .isLength({ max: 150 }).trim().escape(),
  ],
  async (req, res) => {
    if (hasValidationErrors(req, res)) return;

    const {
      email,
      username,
      password,
      role      = 'creator',
      full_name = null,
    } = req.body;

    try {
      const duplicate = await db.query(
        `SELECT id
         FROM   users
         WHERE  (LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($2))
           AND  deleted_at IS NULL
         LIMIT  1`,
        [email, username]
      );

      if (duplicate.rowCount > 0) {
        return sendError(res, 409, 'Email or username is already in use.');
      }

      const passwordHash      = await bcrypt.hash(password, 12);
      const verificationToken = uuidv4();
      const tokenExpires      = new Date(Date.now() + 24 * 60 * 60 * 1000);

      const result = await db.query(
        `INSERT INTO users
           (email, password_hash, username, role, full_name,
            verification_token, verification_token_expires)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, email, username, role, full_name, created_at`,
        [email, passwordHash, username, role, full_name, verificationToken, tokenExpires]
      );

      const newUser = result.rows[0];
      logger.info('User registered', { userId: newUser.id, role: newUser.role });

      return sendSuccess(
        res,
        {
          message: 'Account created. Please verify your email.',
          user   : {
            id      : newUser.id,
            email   : newUser.email,
            username: newUser.username,
            role    : newUser.role,
          },
        },
        201
      );
    } catch (err) {
      logger.error('Registration error', { error: err.message });
      return sendError(res, 500, 'Registration failed. Please try again.');
    }
  }
);


/**
 * POST /api/v1/auth/login
 * Body: { email, password }
 */
app.post(
  `${API}/auth/login`,
  authLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty().withMessage('Password is required.'),
  ],
  async (req, res) => {
    if (hasValidationErrors(req, res)) return;

    const { email, password } = req.body;
    const ipAddress           = getClientIP(req);
    const INVALID_MSG         = 'Invalid email or password.';

    try {
      const result = await db.query(
        `SELECT id, email, username, role, password_hash,
                is_active, is_verified, failed_login_count,
                locked_until, balance
         FROM   users
         WHERE  LOWER(email) = LOWER($1) AND deleted_at IS NULL
         LIMIT  1`,
        [email]
      );

      if (result.rowCount === 0) {
        return sendError(res, 401, INVALID_MSG);
      }

      const user = result.rows[0];

      if (user.locked_until && new Date(user.locked_until) > new Date()) {
        return sendError(
          res, 423,
          `Account locked until ${new Date(user.locked_until).toUTCString()}.`
        );
      }

      if (!user.is_active) {
        return sendError(res, 403, 'Account is deactivated. Contact support.');
      }

      const passwordMatch = await bcrypt.compare(password, user.password_hash);

      if (!passwordMatch) {
        const newFailCount = user.failed_login_count + 1;
        const lockedUntil  = newFailCount >= 5
          ? new Date(Date.now() + 30 * 60 * 1000)
          : null;

        await db.query(
          `UPDATE users
           SET    failed_login_count = $1, locked_until = $2
           WHERE  id = $3`,
          [newFailCount, lockedUntil, user.id]
        );

        logger.warn('Failed login attempt', {
          userId   : user.id,
          attempt  : newFailCount,
          ipAddress,
        });

        return sendError(res, 401, INVALID_MSG);
      }

      await db.query(
        `UPDATE users
         SET    failed_login_count = 0,
                locked_until       = NULL,
                last_login_at      = NOW(),
                last_login_ip      = $1
         WHERE  id = $2`,
        [ipAddress, user.id]
      );

      const accessToken = jwt.sign(
        { id: user.id, email: user.email, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      logger.info('User logged in', { userId: user.id, ipAddress });

      return sendSuccess(res, {
        token    : accessToken,
        expiresIn: JWT_EXPIRES_IN,
        user     : {
          id        : user.id,
          email     : user.email,
          username  : user.username,
          role      : user.role,
          balance   : parseFloat(user.balance),
          isVerified: user.is_verified,
        },
      });
    } catch (err) {
      logger.error('Login error', { error: err.message });
      return sendError(res, 500, 'Login failed. Please try again.');
    }
  }
);


// ================================================================
// USER / CREATOR ROUTES
// ================================================================

/**
 * GET /api/v1/users/me
 */
app.get(`${API}/users/me`, authenticate, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, email, username, role, full_name, avatar_url, bio,
              country_code, balance, total_earned, total_withdrawn,
              is_verified, is_active, last_login_at, created_at
       FROM   users
       WHERE  id = $1 AND deleted_at IS NULL`,
      [req.user.id]
    );

    if (result.rowCount === 0) return sendError(res, 404, 'User not found.');
    return sendSuccess(res, { user: result.rows[0] });
  } catch (err) {
    logger.error('Get profile error', { error: err.message });
    return sendError(res, 500, 'Could not retrieve profile.');
  }
});


/**
 * PATCH /api/v1/users/me
 * Body (all optional): { full_name, bio, country_code, avatar_url }
 */
app.patch(
  `${API}/users/me`,
  authenticate,
  [
    body('full_name').optional().isLength({ max: 150 }).trim().escape(),
    body('bio').optional().isLength({ max: 1000 }).trim(),
    body('country_code')
      .optional()
      .isAlpha().isLength({ min: 2, max: 2 }).toUpperCase(),
    body('avatar_url').optional().isURL().isLength({ max: 2048 }),
  ],
  async (req, res) => {
    if (hasValidationErrors(req, res)) return;

    const { full_name, bio, country_code, avatar_url } = req.body;

    try {
      const result = await db.query(
        `UPDATE users
         SET    full_name    = COALESCE($1, full_name),
                bio          = COALESCE($2, bio),
                country_code = COALESCE($3, country_code),
                avatar_url   = COALESCE($4, avatar_url)
         WHERE  id = $5 AND deleted_at IS NULL
         RETURNING id, email, username, full_name, bio, country_code, avatar_url`,
        [full_name ?? null, bio ?? null, country_code ?? null, avatar_url ?? null, req.user.id]
      );

      if (result.rowCount === 0) return sendError(res, 404, 'User not found.');
      return sendSuccess(res, { user: result.rows[0] });
    } catch (err) {
      logger.error('Update profile error', { error: err.message });
      return sendError(res, 500, 'Could not update profile.');
    }
  }
);


/**
 * GET /api/v1/users/me/earnings
 *
 * Returns:
 *   • balance, total_earned, total_withdrawn
 *   • per-campaign breakdown
 *   • total credited views
 *   • full milestone progress with next target and views remaining
 */
app.get(
  `${API}/users/me/earnings`,
  authenticate,
  authorize('creator'),
  async (req, res) => {
    try {
      // 1. Financial totals
      const userResult = await db.query(
        `SELECT balance, total_earned, total_withdrawn
         FROM   users
         WHERE  id = $1 AND deleted_at IS NULL`,
        [req.user.id]
      );

      if (userResult.rowCount === 0) return sendError(res, 404, 'User not found.');
      const fin = userResult.rows[0];

      // 2. Per-campaign breakdown
      const campaignResult = await db.query(
        `SELECT
           vl.campaign_id,
           c.title             AS campaign_title,
           COUNT(*)::int       AS views_credited,
           SUM(vl.reward_amount) AS amount_earned
         FROM   view_logs vl
         JOIN   campaigns c ON c.id = vl.campaign_id
         WHERE  vl.user_id         = $1
           AND  vl.reward_credited  = TRUE
         GROUP  BY vl.campaign_id, c.title
         ORDER  BY amount_earned DESC`,
        [req.user.id]
      );

      // 3. Total credited views across all campaigns
      const totalViews = campaignResult.rows.reduce(
        (sum, r) => sum + r.views_credited, 0
      );

      // 4. Already-awarded milestones (from idempotency table)
      const milestoneResult = await db.query(
        `SELECT threshold, bonus_amount, awarded_at
         FROM   milestone_bonuses
         WHERE  user_id = $1
         ORDER  BY threshold ASC`,
        [req.user.id]
      );

      const awardedSet = new Set(milestoneResult.rows.map((r) => r.threshold));

      // 5. Build progress array
      const avgCPV = totalViews > 0
        ? parseFloat(fin.total_earned) / totalViews
        : 0;

      const milestoneProgress = MILESTONE_THRESHOLDS.map((threshold) => ({
        threshold,
        reached     : totalViews >= threshold,
        bonusAwarded: awardedSet.has(threshold),
        bonusAmount : parseFloat((avgCPV * MILESTONE_MULT).toFixed(6)),
      }));

      const nextMilestone = MILESTONE_THRESHOLDS.find((t) => totalViews < t) ?? null;

      return sendSuccess(res, {
        earnings: {
          balance         : parseFloat(fin.balance),
          total_earned    : parseFloat(fin.total_earned),
          total_withdrawn : parseFloat(fin.total_withdrawn),
          total_views     : totalViews,
          by_campaign     : campaignResult.rows,
          milestones      : {
            thresholds   : MILESTONE_THRESHOLDS,
            multiplier   : MILESTONE_MULT,
            progress     : milestoneProgress,
            awarded      : milestoneResult.rows,
            next_milestone: nextMilestone,
            views_to_next : nextMilestone ? nextMilestone - totalViews : 0,
          },
        },
      });
    } catch (err) {
      logger.error('Earnings error', { error: err.message });
      return sendError(res, 500, 'Could not fetch earnings.');
    }
  }
);


// ================================================================
// ANTI-FRAUD VIEW TRACKING
// ================================================================

/**
 * POST /api/v1/views/track
 *
 * Ten-gate fraud pipeline:
 *
 *  Gate  1  JWT authentication           (authenticate middleware)
 *  Gate  2  Role = creator only          (authorize middleware)
 *  Gate  3  Rate limiter per IP×campaign (viewLimiter middleware)
 *  Gate  4  Request body validation      (express-validator)
 *  Gate  5  Bot / automation detection   (detectBotSignals)
 *  Gate  6  Campaign existence & status
 *  Gate  7  Campaign date window
 *  Gate  8  Minimum watch time
 *  Gate  9  Per-user duplicate credit check
 *  Gate 10  Per-IP daily cap
 *           + Device fingerprint duplicate check (if supplied)
 *
 * DB backstops that survive race conditions
 * (from database.sql Section 4):
 *   uidx_view_logs_one_credit_per_user_per_campaign
 *   uidx_view_logs_one_attempt_per_ip_per_campaign_per_day
 *   uidx_view_logs_one_credit_per_device_per_campaign
 *
 * Body: { campaignId, watchSeconds, deviceFingerprint? }
 */
app.post(
  `${API}/views/track`,
  authenticate,
  authorize('creator'),
  viewLimiter,
  [
    body('campaignId')
      .isUUID().withMessage('campaignId must be a valid UUID.'),
    body('watchSeconds')
      .isInt({ min: 0, max: 86400 })
      .withMessage('watchSeconds must be an integer between 0 and 86 400.')
      .toInt(),
    body('deviceFingerprint')
      .optional()
      .isString()
      .isLength({ max: 512 })
      .trim(),
  ],
  async (req, res) => {
    if (hasValidationErrors(req, res)) return;

    const { campaignId, watchSeconds, deviceFingerprint } = req.body;
    const userId    = req.user.id;
    const ipAddress = getClientIP(req);
    const userAgent = req.headers['user-agent'] || '';

    // Gate 5 — bot detection (runs outside the transaction so we
    // do not hold the DB lock while inspecting headers)
    const { flagged: isBotFlagged, reason: botReason } = detectBotSignals(req);

    try {
      const result = await db.withTransaction(async (client) => {

        // Gate 6 — load campaign with row-level lock to prevent
        // concurrent budget races on the same campaign
        const campaignRes = await client.query(
          `SELECT id, title, status, cost_per_view, remaining_budget,
                  min_watch_seconds, max_views_per_user,
                  starts_at, ends_at, allowed_countries
           FROM   campaigns
           WHERE  id = $1 AND deleted_at IS NULL
           FOR    UPDATE`,
          [campaignId]
        );

        if (campaignRes.rowCount === 0) {
          return { httpStatus: 404, message: 'Campaign not found.' };
        }

        const campaign = campaignRes.rows[0];

        if (campaign.status !== 'active') {
          return {
            httpStatus: 400,
            message   : `Campaign is not accepting views (status: ${campaign.status}).`,
          };
        }

        // Gate 7 — date window
        const now = new Date();
        if (campaign.starts_at && new Date(campaign.starts_at) > now) {
          return { httpStatus: 400, message: 'Campaign has not started yet.' };
        }
        if (campaign.ends_at && new Date(campaign.ends_at) < now) {
          return { httpStatus: 400, message: 'Campaign has ended.' };
        }

        if (parseFloat(campaign.remaining_budget) <= 0) {
          return { httpStatus: 400, message: 'Campaign budget is exhausted.' };
        }

        // Gate 8 — minimum watch time
        const requiredSeconds = campaign.min_watch_seconds ?? MIN_WATCH_SECONDS;
        const completed       = watchSeconds >= requiredSeconds;

        // Gate 9 — per-user duplicate credit
        const existingCredit = await client.query(
          `SELECT id
           FROM   view_logs
           WHERE  user_id         = $1
             AND  campaign_id     = $2
             AND  reward_credited = TRUE
           LIMIT  1`,
          [userId, campaignId]
        );

        if (existingCredit.rowCount > 0) {
          return {
            httpStatus: 409,
            message   : 'You have already earned a reward for this campaign.',
          };
        }

        // Gate 10 — per-IP daily cap
        const ipCount = await client.query(
          `SELECT COUNT(*)::int AS cnt
           FROM   view_logs
           WHERE  ip_address  = $1
             AND  campaign_id = $2
             AND  DATE(viewed_at) = CURRENT_DATE`,
          [ipAddress, campaignId]
        );

        if (ipCount.rows[0].cnt >= MAX_VIEWS_PER_IP) {
          return {
            httpStatus: 429,
            message   : `Daily view limit reached for this IP on this campaign (max ${MAX_VIEWS_PER_IP}/day).`,
          };
        }

        // Device fingerprint duplicate check
        if (deviceFingerprint) {
          const deviceCheck = await client.query(
            `SELECT id
             FROM   view_logs
             WHERE  device_fingerprint = $1
               AND  campaign_id        = $2
               AND  reward_credited    = TRUE
             LIMIT  1`,
            [deviceFingerprint, campaignId]
          );

          if (deviceCheck.rowCount > 0) {
            return {
              httpStatus: 409,
              message   : 'This device has already earned a reward for this campaign.',
            };
          }
        }

        // ── All gates passed ──────────────────────────────────

        const costPerView  = parseFloat(campaign.cost_per_view);
        const rewardAmount = completed && !isBotFlagged ? costPerView : 0;
        const shouldCredit = completed && !isBotFlagged;

        // Insert the view_log row
        let viewRecord;
        try {
          const insertRes = await client.query(
            `INSERT INTO view_logs
               (campaign_id, user_id, ip_address, user_agent,
                device_fingerprint, watch_seconds, completed,
                reward_amount, reward_credited,
                is_flagged, flag_reason)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
             RETURNING *`,
            [
              campaignId,
              userId,
              ipAddress,
              userAgent,
              deviceFingerprint || null,
              watchSeconds,
              completed,
              rewardAmount,
              shouldCredit,
              isBotFlagged,
              botReason,
            ]
          );
          viewRecord = insertRes.rows[0];
        } catch (insertErr) {
          // 23505 = unique_violation — DB backstop index caught a race
          if (insertErr.code === '23505') {
            logger.warn('DB unique index blocked duplicate view', {
              userId, campaignId, ipAddress,
              constraint: insertErr.constraint,
            });
            return { httpStatus: 409, message: 'Duplicate view attempt blocked.' };
          }
          throw insertErr;
        }

        // Bot flagged — recorded but not credited
        if (isBotFlagged) {
          logger.warn('View flagged as bot — not credited', {
            viewId: viewRecord.id, userId, campaignId, reason: botReason,
          });
          return {
            credited: false,
            flagged : true,
            reason  : botReason,
            reward  : 0,
            viewId  : viewRecord.id,
          };
        }

        // Did not meet minimum watch time
        if (!completed) {
          return {
            credited        : false,
            flagged         : false,
            reward          : 0,
            watchSeconds,
            requiredSeconds,
            message         : `Watch ${requiredSeconds - watchSeconds} more second(s) to earn a reward.`,
            viewId          : viewRecord.id,
          };
        }

        // Flip reward_credited = TRUE
        // This fires fn_credit_view_reward trigger which atomically:
        //   • deducts reward_amount from campaigns.remaining_budget
        //   • increments campaigns.total_paid_out and total_views
        //   • credits users.balance and users.total_earned
        //   • auto-completes campaign if remaining_budget hits 0
        await client.query(
          `UPDATE view_logs
           SET    reward_credited = TRUE,
                  credited_at    = NOW()
           WHERE  id = $1`,
          [viewRecord.id]
        );

        // Count total credited views for this user (for milestone check)
        const viewCountRes = await client.query(
          `SELECT COUNT(*)::int AS total
           FROM   view_logs
           WHERE  user_id        = $1
             AND  reward_credited = TRUE`,
          [userId]
        );

        const totalCreditedViews = viewCountRes.rows[0].total;
        const previousCount      = totalCreditedViews - 1;

        // Milestone bonus calculation
        const milestonesCrossed = getMilestonesCrossed(
          previousCount,
          totalCreditedViews,
          costPerView,
          campaignId,
          userId
        );

        const milestonesAwarded = [];

        for (const milestone of milestonesCrossed) {
          // INSERT ... ON CONFLICT DO NOTHING is safe to call even
          // under concurrent requests; the unique index on
          // (user_id, campaign_id, threshold) prevents double awards.
          const milestoneInsert = await client.query(
            `INSERT INTO milestone_bonuses
               (user_id, campaign_id, threshold, bonus_amount)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id, campaign_id, threshold) DO NOTHING
             RETURNING id, threshold, bonus_amount`,
            [userId, campaignId, milestone.threshold, milestone.bonusAmount]
          );

          if (milestoneInsert.rowCount === 0) {
            // Already awarded (race condition safely handled by index)
            logger.warn('Milestone already awarded — skipping', {
              userId, campaignId, threshold: milestone.threshold,
            });
            continue;
          }

          // Verify campaign still has budget for the bonus
          const budgetCheck = await client.query(
            `SELECT remaining_budget FROM campaigns WHERE id = $1 FOR UPDATE`,
            [campaignId]
          );

          const remaining = parseFloat(budgetCheck.rows[0]?.remaining_budget || 0);

          if (remaining < milestone.bonusAmount) {
            logger.warn('Insufficient budget for milestone bonus', {
              userId, campaignId,
              threshold: milestone.threshold,
              bonusAmount: milestone.bonusAmount,
              remaining,
            });
            continue;
          }

          // Credit bonus to user and deduct from campaign
          await client.query(
            `UPDATE users
             SET    balance      = balance      + $1,
                    total_earned = total_earned + $1
             WHERE  id = $2`,
            [milestone.bonusAmount, userId]
          );

          await client.query(
            `UPDATE campaigns
             SET    remaining_budget = remaining_budget - $1,
                    total_paid_out   = total_paid_out   + $1
             WHERE  id = $2`,
            [milestone.bonusAmount, campaignId]
          );

          milestonesAwarded.push({
            threshold  : milestone.threshold,
            bonusAmount: milestone.bonusAmount,
          });

          logger.info('Milestone bonus awarded', {
            userId, campaignId,
            threshold  : milestone.threshold,
            bonusAmount: milestone.bonusAmount,
          });
        }

        // Fetch updated balance
        const balanceRes = await client.query(
          `SELECT balance FROM users WHERE id = $1`,
          [userId]
        );
        const newBalance = parseFloat(balanceRes.rows[0]?.balance || 0);
        const totalBonus = milestonesAwarded.reduce((s, m) => s + m.bonusAmount, 0);

        logger.info('View credited', {
          viewId: viewRecord.id, userId, campaignId,
          rewardAmount, totalBonus, totalCreditedViews, newBalance,
        });

        return {
          credited       : true,
          flagged        : false,
          reward         : rewardAmount,
          total_bonus    : parseFloat(totalBonus.toFixed(6)),
          new_balance    : newBalance,
          total_views    : totalCreditedViews,
          milestones_hit : milestonesAwarded,
          viewId         : viewRecord.id,
        };
      }); // end withTransaction

      // Translate gate-error objects into HTTP responses
      if (result.httpStatus) {
        return sendError(res, result.httpStatus, result.message);
      }

      return sendSuccess(res, result);

    } catch (err) {
      if (err.code === 'P0001') {
        return sendError(res, 400, 'Campaign budget exhausted while processing your view.');
      }
      logger.error('View tracking error', {
        error: err.message, stack: err.stack, userId, campaignId,
      });
      return sendError(res, 500, 'View tracking failed. Please try again.');
    }
  }
);


// ================================================================
// WITHDRAWAL ROUTES
// ================================================================

/**
 * POST /api/v1/withdrawals
 * Body: { amount, method, payout_details }
 */
app.post(
  `${API}/withdrawals`,
  authenticate,
  authorize('creator'),
  [
    body('amount')
      .isFloat({ min: 0.000001 }).withMessage('Amount must be a positive number.')
      .toFloat(),
    body('method')
      .isIn(['bank_transfer', 'paypal', 'crypto', 'gift_card'])
      .withMessage('Invalid payment method.'),
    body('payout_details')
      .isObject().withMessage('payout_details must be a non-empty object.')
      .custom((v) => {
        if (Object.keys(v).length === 0) throw new Error('payout_details must not be empty.');
        return true;
      }),
  ],
  async (req, res) => {
    if (hasValidationErrors(req, res)) return;

    const { amount, method, payout_details } = req.body;
    const requested = parseFloat(amount);

    if (requested < MIN_WITHDRAWAL) {
      return sendError(res, 400, `Minimum withdrawal is $${MIN_WITHDRAWAL.toFixed(2)}.`);
    }

    try {
      const withdrawal = await db.withTransaction(async (client) => {

        const userRes = await client.query(
          `SELECT balance FROM users WHERE id = $1 FOR UPDATE`,
          [req.user.id]
        );

        const balance = parseFloat(userRes.rows[0]?.balance || 0);
        if (balance < requested) {
          return {
            httpStatus: 400,
            message   : `Insufficient balance. Available: $${balance.toFixed(2)}.`,
          };
        }

        const pendingCheck = await client.query(
          `SELECT id FROM withdrawal_requests
           WHERE  user_id = $1 AND status = 'pending' LIMIT 1`,
          [req.user.id]
        );

        if (pendingCheck.rowCount > 0) {
          return {
            httpStatus: 409,
            message   : 'You already have a pending withdrawal. Wait for it to be reviewed.',
          };
        }

        const fee       = parseFloat((requested * (WITHDRAWAL_FEE_PCT / 100)).toFixed(6));
        const netAmount = parseFloat((requested - fee).toFixed(6));

        if (netAmount <= 0) {
          return {
            httpStatus: 400,
            message   : 'Amount too small after platform fee.',
          };
        }

        const insertRes = await client.query(
          `INSERT INTO withdrawal_requests
             (user_id, amount, fee, net_amount, method, payout_details)
           VALUES ($1,$2,$3,$4,$5,$6)
           RETURNING id, amount, fee, net_amount, method, status, requested_at`,
          [req.user.id, requested, fee, netAmount, method, JSON.stringify(payout_details)]
        );

        logger.info('Withdrawal submitted', {
          userId: req.user.id,
          amount: requested,
          method,
          id    : insertRes.rows[0].id,
        });

        return insertRes.rows[0];
      });

      if (withdrawal.httpStatus) {
        return sendError(res, withdrawal.httpStatus, withdrawal.message);
      }

      return sendSuccess(res, { withdrawal }, 201);

    } catch (err) {
      if (err.code === '23505') {
        return sendError(res, 409, 'You already have a pending withdrawal request.');
      }
      logger.error('Withdrawal error', { error: err.message });
      return sendError(res, 500, 'Could not submit withdrawal request.');
    }
  }
);


/**
 * GET /api/v1/withdrawals
 * Query params: page?, limit?
 */
app.get(
  `${API}/withdrawals`,
  authenticate,
  authorize('creator'),
  [
    qv('page').optional().isInt({ min: 1 }).toInt(),
    qv('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  ],
  async (req, res) => {
    if (hasValidationErrors(req, res)) return;

    const page   = req.query.page  || 1;
    const limit  = req.query.limit || 10;
    const offset = (page - 1) * limit;

    try {
      const [listRes, countRes] = await Promise.all([
        db.query(
          `SELECT id, amount, fee, net_amount, method, status,
                  requested_at, paid_at, review_note, transaction_ref
           FROM   withdrawal_requests
           WHERE  user_id = $1
           ORDER  BY requested_at DESC
           LIMIT  $2 OFFSET $3`,
          [req.user.id, limit, offset]
        ),
        db.query(
          `SELECT COUNT(*)::int AS total
           FROM   withdrawal_requests WHERE user_id = $1`,
          [req.user.id]
        ),
      ]);

      const total = countRes.rows[0].total;
      return sendSuccess(res, {
        withdrawals: listRes.rows,
        pagination : { page, limit, total, pages: Math.ceil(total / limit) },
      });
    } catch (err) {
      logger.error('Withdrawal list error', { error: err.message });
      return sendError(res, 500, 'Could not retrieve withdrawal history.');
    }
  }
);


// ================================================================
// CAMPAIGN ROUTES
// ================================================================

/**
 * GET /api/v1/campaigns
 * Query params: page?, limit?, category?
 */
app.get(
  `${API}/campaigns`,
  authenticate,
  [
    qv('page').optional().isInt({ min: 1 }).toInt(),
    qv('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
    qv('category').optional().isString().trim().escape(),
  ],
  async (req, res) => {
    if (hasValidationErrors(req, res)) return;

    const page     = req.query.page     || 1;
    const limit    = req.query.limit    || 10;
    const category = req.query.category || null;
    const offset   = (page - 1) * limit;

    try {
      const [listRes, countRes] = await Promise.all([
        db.query(
          `SELECT id, title, description, thumbnail_url, category, tags,
                  cost_per_view, min_watch_seconds, total_views,
                  starts_at, ends_at
           FROM   campaigns
           WHERE  status           = 'active'
             AND  deleted_at       IS NULL
             AND  remaining_budget > 0
             AND  (starts_at IS NULL OR starts_at <= NOW())
             AND  (ends_at   IS NULL OR ends_at   >= NOW())
             AND  ($1::text IS NULL OR category = $1)
           ORDER  BY cost_per_view DESC, created_at DESC
           LIMIT  $2 OFFSET $3`,
          [category, limit, offset]
        ),
        db.query(
          `SELECT COUNT(*)::int AS total
           FROM   campaigns
           WHERE  status           = 'active'
             AND  deleted_at       IS NULL
             AND  remaining_budget > 0
             AND  (starts_at IS NULL OR starts_at <= NOW())
             AND  (ends_at   IS NULL OR ends_at   >= NOW())
             AND  ($1::text IS NULL OR category = $1)`,
          [category]
        ),
      ]);

      const total = countRes.rows[0].total;
      return sendSuccess(res, {
        campaigns : listRes.rows,
        pagination: { page, limit, total, pages: Math.ceil(total / limit) },
      });
    } catch (err) {
      logger.error('Campaign list error', { error: err.message });
      return sendError(res, 500, 'Could not retrieve campaigns.');
    }
  }
);


/**
 * POST /api/v1/campaigns
 * Body: { title, target_url, total_budget, cost_per_view,
 *         description?, min_watch_seconds?, max_views_per_user?,
 *         category?, tags?, starts_at?, ends_at? }
 */
app.post(
  `${API}/campaigns`,
  authenticate,
  authorize('advertiser', 'admin'),
  [
    body('title').isLength({ min: 5, max: 200 }).trim(),
    body('description').optional().isLength({ max: 5000 }).trim(),
    body('target_url').isURL().isLength({ max: 2048 }),
    body('total_budget').isFloat({ min: 0.000001 }).toFloat(),
    body('cost_per_view').isFloat({ min: 0.000001 }).toFloat(),
    body('min_watch_seconds').optional().isInt({ min: 0, max: 3600 }).toInt(),
    body('max_views_per_user').optional().isInt({ min: 1, max: 1000 }).toInt(),
    body('category').optional().isLength({ max: 100 }).trim(),
    body('tags').optional().isArray({ max: 20 }),
    body('starts_at').optional().isISO8601(),
    body('ends_at').optional().isISO8601(),
  ],
  async (req, res) => {
    if (hasValidationErrors(req, res)) return;

    const {
      title, description, target_url, total_budget, cost_per_view,
      min_watch_seconds, max_views_per_user, category, tags,
      starts_at, ends_at,
    } = req.body;

    if (ends_at && starts_at && new Date(ends_at) <= new Date(starts_at)) {
      return sendError(res, 400, 'ends_at must be after starts_at.');
    }

    try {
      const result = await db.query(
        `INSERT INTO campaigns
           (advertiser_id, title, description, target_url,
            total_budget, remaining_budget, cost_per_view,
            min_watch_seconds, max_views_per_user,
            category, tags, starts_at, ends_at, status)
         VALUES
           ($1,$2,$3,$4,$5,$5,$6,$7,$8,$9,$10,$11,$12,'draft')
         RETURNING id, title, status, total_budget, cost_per_view, created_at`,
        [
          req.user.id,
          title,
          description        || null,
          target_url,
          parseFloat(total_budget),
          parseFloat(cost_per_view),
          min_watch_seconds  ?? MIN_WATCH_SECONDS,
          max_views_per_user ?? 1,
          category           || null,
          tags               || [],
          starts_at          || null,
          ends_at            || null,
        ]
      );

      logger.info('Campaign created', { id: result.rows[0].id, advertiserId: req.user.id });
      return sendSuccess(res, { campaign: result.rows[0] }, 201);
    } catch (err) {
      logger.error('Campaign creation error', { error: err.message });
      return sendError(res, 500, 'Could not create campaign.');
    }
  }
);


/**
 * PATCH /api/v1/campaigns/:id/status
 * Body: { status }
 */
app.patch(
  `${API}/campaigns/:id/status`,
  authenticate,
  authorize('advertiser', 'admin'),
  [
    param('id').isUUID(),
    body('status').isIn(['active', 'paused', 'cancelled', 'completed']),
  ],
  async (req, res) => {
    if (hasValidationErrors(req, res)) return;

    const { id }     = req.params;
    const { status } = req.body;

    // Advertisers may only modify their own campaigns
    const ownerClause = req.user.role === 'admin'
      ? ''
      : `AND advertiser_id = '${req.user.id}'`;

    try {
      const result = await db.query(
        `UPDATE campaigns
         SET    status = $1
         WHERE  id = $2 ${ownerClause} AND deleted_at IS NULL
         RETURNING id, title, status`,
        [status, id]
      );

      if (result.rowCount === 0) {
        return sendError(res, 404, 'Campaign not found or access denied.');
      }

      logger.info('Campaign status updated', { id, status, userId: req.user.id });
      return sendSuccess(res, { campaign: result.rows[0] });
    } catch (err) {
      logger.error('Campaign status error', { error: err.message });
      return sendError(res, 500, 'Could not update campaign status.');
    }
  }
);


// ================================================================
// ADMIN ROUTES
// ================================================================

/** GET /api/v1/admin/stats */
app.get(`${API}/admin/stats`, authenticate, authorize('admin'), async (req, res) => {
  try {
    const result = await db.query(`SELECT * FROM v_daily_platform_stats LIMIT 30`);
    return sendSuccess(res, { stats: result.rows });
  } catch (err) {
    logger.error('Admin stats error', { error: err.message });
    return sendError(res, 500, 'Could not retrieve stats.');
  }
});


/** GET /api/v1/admin/withdrawals */
app.get(`${API}/admin/withdrawals`, authenticate, authorize('admin'), async (req, res) => {
  try {
    const result = await db.query(`SELECT * FROM v_pending_withdrawals`);
    return sendSuccess(res, { withdrawals: result.rows });
  } catch (err) {
    logger.error('Admin withdrawal list error', { error: err.message });
    return sendError(res, 500, 'Could not retrieve pending withdrawals.');
  }
});


/**
 * PATCH /api/v1/admin/withdrawals/:id
 * Body: { status, review_note?, transaction_ref? }
 */
app.patch(
  `${API}/admin/withdrawals/:id`,
  authenticate,
  authorize('admin'),
  [
    param('id').isUUID(),
    body('status').isIn(['approved', 'rejected', 'paid']),
    body('review_note').optional().isLength({ max: 1000 }).trim(),
    body('transaction_ref').optional().isLength({ max: 255 }).trim(),
  ],
  async (req, res) => {
    if (hasValidationErrors(req, res)) return;

    const { id }                               = req.params;
    const { status, review_note, transaction_ref } = req.body;

    try {
      const result = await db.query(
        `UPDATE withdrawal_requests
         SET    status          = $1,
                review_note     = COALESCE($2, review_note),
                transaction_ref = COALESCE($3, transaction_ref),
                reviewed_by     = $4,
                reviewed_at     = NOW()
         WHERE  id = $5
         RETURNING id, status, review_note, transaction_ref, reviewed_at`,
        [status, review_note || null, transaction_ref || null, req.user.id, id]
      );

      if (result.rowCount === 0) return sendError(res, 404, 'Withdrawal not found.');

      logger.info('Withdrawal updated by admin', { id, status, adminId: req.user.id });
      return sendSuccess(res, { withdrawal: result.rows[0] });
    } catch (err) {
      if (err.code === 'P0002') {
        return sendError(res, 400, 'User has insufficient balance for this withdrawal.');
      }
      logger.error('Admin withdrawal update error', { error: err.message });
      return sendError(res, 500, 'Could not update withdrawal.');
    }
  }
);


/**
 * PATCH /api/v1/admin/views/:id/flag
 * Body: { is_flagged, flag_reason? }
 */
app.patch(
  `${API}/admin/views/:id/flag`,
  authenticate,
  authorize('admin'),
  [
    param('id').isUUID(),
    body('is_flagged').isBoolean().toBoolean(),
    body('flag_reason').optional().isLength({ max: 500 }).trim(),
  ],
  async (req, res) => {
    if (hasValidationErrors(req, res)) return;

    const { id }                      = req.params;
    const { is_flagged, flag_reason } = req.body;

    try {
      const result = await db.query(
        `UPDATE view_logs
         SET    is_flagged  = $1,
                flag_reason = COALESCE($2, flag_reason)
         WHERE  id = $3
         RETURNING id, is_flagged, flag_reason, campaign_id, user_id`,
        [is_flagged, flag_reason || null, id]
      );

      if (result.rowCount === 0) return sendError(res, 404, 'View log entry not found.');

      logger.info('View log flagged by admin', { id, is_flagged, adminId: req.user.id });
      return sendSuccess(res, { view: result.rows[0] });
    } catch (err) {
      logger.error('Flag view error', { error: err.message });
      return sendError(res, 500, 'Could not update view flag.');
    }
  }
);


/** GET /api/v1/admin/fraud-signals */
app.get(`${API}/admin/fraud-signals`, authenticate, authorize('admin'), async (req, res) => {
  try {
    const result = await db.query(`SELECT * FROM v_fraud_signals LIMIT 100`);
    return sendSuccess(res, { signals: result.rows });
  } catch (err) {
    logger.error('Fraud signals error', { error: err.message });
    return sendError(res, 500, 'Could not retrieve fraud signals.');
  }
});


/**
 * GET /api/v1/admin/users
 * Query params: page?, limit?, role?
 */
app.get(
  `${API}/admin/users`,
  authenticate,
  authorize('admin'),
  [
    qv('page').optional().isInt({ min: 1 }).toInt(),
    qv('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
    qv('role').optional().isIn(['creator', 'advertiser', 'admin']),
  ],
  async (req, res) => {
    if (hasValidationErrors(req, res)) return;

    const page   = req.query.page  || 1;
    const limit  = req.query.limit || 20;
    const role   = req.query.role  || null;
    const offset = (page - 1) * limit;

    try {
      const [listRes, countRes] = await Promise.all([
        db.query(
          `SELECT id, email, username, role, full_name, country_code,
                  balance, total_earned, total_withdrawn,
                  is_active, is_verified, last_login_at, created_at
           FROM   users
           WHERE  deleted_at IS NULL
             AND  ($1::text IS NULL OR role::text = $1)
           ORDER  BY created_at DESC
           LIMIT  $2 OFFSET $3`,
          [role, limit, offset]
        ),
        db.query(
          `SELECT COUNT(*)::int AS total
           FROM   users
           WHERE  deleted_at IS NULL
             AND  ($1::text IS NULL OR role::text = $1)`,
          [role]
        ),
      ]);

      const total = countRes.rows[0].total;
      return sendSuccess(res, {
        users     : listRes.rows,
        pagination: { page, limit, total, pages: Math.ceil(total / limit) },
      });
    } catch (err) {
      logger.error('Admin user list error', { error: err.message });
      return sendError(res, 500, 'Could not retrieve users.');
    }
  }
);


/**
 * PATCH /api/v1/admin/users/:id/status
 * Body: { is_active }
 */
app.patch(
  `${API}/admin/users/:id/status`,
  authenticate,
  authorize('admin'),
  [
    param('id').isUUID(),
    body('is_active').isBoolean().toBoolean(),
  ],
  async (req, res) => {
    if (hasValidationErrors(req, res)) return;

    const { id }        = req.params;
    const { is_active } = req.body;

    try {
      const result = await db.query(
        `UPDATE users
         SET    is_active = $1
         WHERE  id = $2 AND deleted_at IS NULL
         RETURNING id, username, email, role, is_active`,
        [is_active, id]
      );

      if (result.rowCount === 0) return sendError(res, 404, 'User not found.');

      logger.info('User status changed by admin', { targetId: id, is_active, adminId: req.user.id });
      return sendSuccess(res, { user: result.rows[0] });
    } catch (err) {
      logger.error('Admin user status error', { error: err.message });
      return sendError(res, 500, 'Could not update user status.');
    }
  }
);


// ================================================================
// 404 & GLOBAL ERROR HANDLER
// ================================================================

app.use((req, res) => {
  sendError(res, 404, `Route ${req.method} ${req.path} not found.`);
});

// Four-argument signature is required by Express
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  logger.error('Unhandled Express error', {
    error : err.message,
    stack : err.stack,
    method: req.method,
    path  : req.path,
  });
  sendError(res, 500, 'An unexpected error occurred.');
});


// ================================================================
// STARTUP & GRACEFUL SHUTDOWN
// ================================================================

let httpServer;

async function startServer() {
  try {
    await db.testConnection();

    httpServer = app.listen(PORT, () => {
      logger.info('Server started', {
        port   : PORT,
        env    : NODE_ENV,
        api    : API,
        pid    : process.pid,
      });
    });
  } catch (err) {
    logger.error('Server failed to start', { error: err.message, stack: err.stack });
    process.exit(1);
  }
}

async function gracefulShutdown(signal) {
  logger.info(`${signal} received — shutting down`);

  httpServer?.close(async () => {
    logger.info('HTTP server closed');
    try {
      await db.closePool();
    } catch (err) {
      logger.error('Error closing pool', { error: err.message });
    }
    logger.info('Shutdown complete');
    process.exit(0);
  });

  setTimeout(() => {
    logger.warn('Shutdown timed out — forcing exit');
    process.exit(1);
  }, 15_000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled rejection', { reason: String(reason) });
});

process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception', { error: err.message, stack: err.stack });
  process.exit(1);
});

if (require.main === module) {
  startServer();
}

module.exports = app;
