-- ============================================================
-- Content Rewards Platform — Full PostgreSQL DDL
-- Run this script against a fresh database to initialise
-- every table, index, constraint, and seed value needed.
-- ============================================================

-- ------------------------------------------------------------
-- 0. Extensions
-- ------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";


-- ------------------------------------------------------------
-- 1. ENUM types
-- ------------------------------------------------------------
DO $$
BEGIN
    -- User roles
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
        CREATE TYPE user_role AS ENUM ('creator', 'advertiser', 'admin');
    END IF;

    -- Campaign status lifecycle
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'campaign_status') THEN
        CREATE TYPE campaign_status AS ENUM ('draft', 'active', 'paused', 'completed', 'cancelled');
    END IF;

    -- Withdrawal request status
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'withdrawal_status') THEN
        CREATE TYPE withdrawal_status AS ENUM ('pending', 'approved', 'rejected', 'paid');
    END IF;

    -- Payment methods for withdrawals
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'payment_method') THEN
        CREATE TYPE payment_method AS ENUM ('bank_transfer', 'paypal', 'crypto', 'gift_card');
    END IF;
END
$$;


-- ------------------------------------------------------------
-- 2. USERS table
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id                  UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    email               VARCHAR(255)    NOT NULL,
    password_hash       TEXT            NOT NULL,
    username            VARCHAR(50)     NOT NULL,
    role                user_role       NOT NULL DEFAULT 'creator',

    -- Profile
    full_name           VARCHAR(150),
    avatar_url          TEXT,
    bio                 TEXT,
    country_code        CHAR(2),

    -- Financial
    balance             NUMERIC(12, 4)  NOT NULL DEFAULT 0.0000
                            CONSTRAINT balance_non_negative CHECK (balance >= 0),
    total_earned        NUMERIC(12, 4)  NOT NULL DEFAULT 0.0000,
    total_withdrawn     NUMERIC(12, 4)  NOT NULL DEFAULT 0.0000,

    -- Account state
    is_active           BOOLEAN         NOT NULL DEFAULT TRUE,
    is_verified         BOOLEAN         NOT NULL DEFAULT FALSE,
    email_verified_at   TIMESTAMPTZ,
    verification_token  TEXT,

    -- Security
    failed_login_count  SMALLINT        NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    last_login_at       TIMESTAMPTZ,
    last_login_ip       INET,
    password_reset_token        TEXT,
    password_reset_expires_at   TIMESTAMPTZ,

    -- Audit
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMPTZ                          -- soft-delete
);

-- Unique constraints on users
CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique
    ON users (LOWER(email))
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS users_username_unique
    ON users (LOWER(username))
    WHERE deleted_at IS NULL;

-- General-purpose indexes on users
CREATE INDEX IF NOT EXISTS idx_users_role            ON users (role);
CREATE INDEX IF NOT EXISTS idx_users_is_active       ON users (is_active);
CREATE INDEX IF NOT EXISTS idx_users_created_at      ON users (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_users_country_code    ON users (country_code);


-- ------------------------------------------------------------
-- 3. CAMPAIGNS table
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS campaigns (
    id                  UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    advertiser_id       UUID            NOT NULL
                            REFERENCES users (id) ON DELETE RESTRICT,
    title               VARCHAR(200)    NOT NULL,
    description         TEXT,
    target_url          TEXT            NOT NULL,

    -- Budget & pricing
    total_budget        NUMERIC(12, 4)  NOT NULL
                            CONSTRAINT budget_positive CHECK (total_budget > 0),
    remaining_budget    NUMERIC(12, 4)  NOT NULL
                            CONSTRAINT remaining_budget_non_negative CHECK (remaining_budget >= 0),
    cost_per_view       NUMERIC(8, 6)   NOT NULL
                            CONSTRAINT cpv_positive CHECK (cost_per_view > 0),

    -- Targeting
    allowed_countries   CHAR(2)[]                            -- NULL means worldwide
                            DEFAULT NULL,
    category            VARCHAR(100),
    tags                TEXT[]          DEFAULT '{}',

    -- Lifecycle
    status              campaign_status NOT NULL DEFAULT 'draft',
    starts_at           TIMESTAMPTZ,
    ends_at             TIMESTAMPTZ,
    CONSTRAINT campaign_dates_valid CHECK (ends_at IS NULL OR ends_at > starts_at),

    -- Stats (denormalised for fast reads; kept in sync by triggers)
    total_views         BIGINT          NOT NULL DEFAULT 0,
    unique_views        BIGINT          NOT NULL DEFAULT 0,
    total_paid_out      NUMERIC(12, 4)  NOT NULL DEFAULT 0.0000,

    -- Fraud controls
    max_views_per_user  SMALLINT        NOT NULL DEFAULT 1
                            CONSTRAINT max_views_positive CHECK (max_views_per_user >= 1),
    min_watch_seconds   SMALLINT        NOT NULL DEFAULT 30
                            CONSTRAINT min_watch_positive CHECK (min_watch_seconds >= 0),

    -- Audit
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_campaigns_advertiser    ON campaigns (advertiser_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_status        ON campaigns (status);
CREATE INDEX IF NOT EXISTS idx_campaigns_starts_at     ON campaigns (starts_at);
CREATE INDEX IF NOT EXISTS idx_campaigns_ends_at       ON campaigns (ends_at);
CREATE INDEX IF NOT EXISTS idx_campaigns_category      ON campaigns (category);
CREATE INDEX IF NOT EXISTS idx_campaigns_tags          ON campaigns USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_campaigns_countries     ON campaigns USING GIN (allowed_countries);


-- ------------------------------------------------------------
-- 4. VIEWS_LOG table  (core anti-fraud table)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS views_log (
    id                  UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    campaign_id         UUID            NOT NULL
                            REFERENCES campaigns (id) ON DELETE CASCADE,
    user_id             UUID            NOT NULL
                            REFERENCES users (id)    ON DELETE CASCADE,

    -- Request fingerprint (for fraud detection)
    ip_address          INET            NOT NULL,
    user_agent          TEXT,
    device_fingerprint  TEXT,

    -- Watch quality
    watch_seconds       INTEGER         NOT NULL DEFAULT 0
                            CONSTRAINT watch_seconds_non_negative CHECK (watch_seconds >= 0),
    completed           BOOLEAN         NOT NULL DEFAULT FALSE,

    -- Reward
    reward_amount       NUMERIC(8, 6)   NOT NULL DEFAULT 0.000000,
    reward_credited     BOOLEAN         NOT NULL DEFAULT FALSE,
    credited_at         TIMESTAMPTZ,

    -- Fraud flags
    is_flagged          BOOLEAN         NOT NULL DEFAULT FALSE,
    flag_reason         TEXT,

    -- Geo (resolved at record time)
    country_code        CHAR(2),
    region              VARCHAR(100),

    -- Timing
    viewed_at           TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- *** ANTI-FRAUD UNIQUE INDEXES ***

-- 1. One reward per (user, campaign) — the primary fraud gate.
--    A user can only earn once per campaign, regardless of device.
CREATE UNIQUE INDEX IF NOT EXISTS uidx_views_log_user_campaign
    ON views_log (user_id, campaign_id)
    WHERE reward_credited = TRUE;

-- 2. One view attempt per (ip_address, campaign) per calendar day.
--    Blocks a single IP from farming views across multiple accounts.
CREATE UNIQUE INDEX IF NOT EXISTS uidx_views_log_ip_campaign_day
    ON views_log (ip_address, campaign_id, DATE(viewed_at));

-- 3. One view attempt per (device_fingerprint, campaign).
--    Blocks device-level replay even when IP changes (VPN rotation).
CREATE UNIQUE INDEX IF NOT EXISTS uidx_views_log_device_campaign
    ON views_log (device_fingerprint, campaign_id)
    WHERE device_fingerprint IS NOT NULL
      AND reward_credited = TRUE;

-- General-purpose indexes on views_log
CREATE INDEX IF NOT EXISTS idx_views_log_campaign       ON views_log (campaign_id);
CREATE INDEX IF NOT EXISTS idx_views_log_user           ON views_log (user_id);
CREATE INDEX IF NOT EXISTS idx_views_log_ip             ON views_log (ip_address);
CREATE INDEX IF NOT EXISTS idx_views_log_viewed_at      ON views_log (viewed_at DESC);
CREATE INDEX IF NOT EXISTS idx_views_log_flagged        ON views_log (is_flagged) WHERE is_flagged = TRUE;
CREATE INDEX IF NOT EXISTS idx_views_log_uncredited     ON views_log (reward_credited) WHERE reward_credited = FALSE;


-- ------------------------------------------------------------
-- 5. WITHDRAWAL_REQUESTS table
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS withdrawal_requests (
    id                  UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id             UUID            NOT NULL
                            REFERENCES users (id) ON DELETE RESTRICT,

    amount              NUMERIC(12, 4)  NOT NULL
                            CONSTRAINT withdrawal_amount_positive CHECK (amount > 0),
    fee                 NUMERIC(12, 4)  NOT NULL DEFAULT 0.0000
                            CONSTRAINT fee_non_negative CHECK (fee >= 0),
    net_amount          NUMERIC(12, 4)  NOT NULL
                            CONSTRAINT net_amount_positive CHECK (net_amount > 0),

    method              payment_method  NOT NULL,
    status              withdrawal_status NOT NULL DEFAULT 'pending',

    -- Destination details (stored as JSONB for flexibility across methods)
    payout_details      JSONB           NOT NULL DEFAULT '{}',

    -- Admin processing
    reviewed_by         UUID            REFERENCES users (id) ON DELETE SET NULL,
    reviewed_at         TIMESTAMPTZ,
    review_note         TEXT,
    transaction_ref     TEXT,          -- external payment reference

    -- Audit
    requested_at        TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    paid_at             TIMESTAMPTZ,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Prevent a user from submitting duplicate pending requests
CREATE UNIQUE INDEX IF NOT EXISTS uidx_withdrawal_one_pending_per_user
    ON withdrawal_requests (user_id)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_withdrawal_user          ON withdrawal_requests (user_id);
CREATE INDEX IF NOT EXISTS idx_withdrawal_status        ON withdrawal_requests (status);
CREATE INDEX IF NOT EXISTS idx_withdrawal_method        ON withdrawal_requests (method);
CREATE INDEX IF NOT EXISTS idx_withdrawal_requested_at  ON withdrawal_requests (requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_withdrawal_reviewed_by   ON withdrawal_requests (reviewed_by);


-- ------------------------------------------------------------
-- 6. AUDIT_LOG table  (immutable event trail)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id                  BIGSERIAL       PRIMARY KEY,
    actor_id            UUID            REFERENCES users (id) ON DELETE SET NULL,
    action              VARCHAR(100)    NOT NULL,
    entity_type         VARCHAR(50),
    entity_id           TEXT,
    old_value           JSONB,
    new_value           JSONB,
    ip_address          INET,
    user_agent          TEXT,
    occurred_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_actor          ON audit_log (actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action         ON audit_log (action);
CREATE INDEX IF NOT EXISTS idx_audit_entity         ON audit_log (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_occurred_at    ON audit_log (occurred_at DESC);


-- ------------------------------------------------------------
-- 7. AUTOMATIC updated_at TRIGGER
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql AS
$$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

-- Attach the trigger to every table that has an updated_at column
DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['users', 'campaigns', 'withdrawal_requests']
    LOOP
        EXECUTE FORMAT(
            'DROP TRIGGER IF EXISTS trg_set_updated_at ON %I;
             CREATE TRIGGER trg_set_updated_at
             BEFORE UPDATE ON %I
             FOR EACH ROW EXECUTE FUNCTION set_updated_at();',
            tbl, tbl
        );
    END LOOP;
END;
$$;


-- ------------------------------------------------------------
-- 8. CAMPAIGN BUDGET GUARD TRIGGER
--    Prevents remaining_budget from going below zero
--    when a view reward is credited.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION guard_campaign_budget()
RETURNS TRIGGER
LANGUAGE plpgsql AS
$$
BEGIN
    IF NEW.reward_credited = TRUE AND OLD.reward_credited = FALSE THEN
        UPDATE campaigns
        SET
            remaining_budget = remaining_budget - NEW.reward_amount,
            total_paid_out   = total_paid_out   + NEW.reward_amount,
            total_views      = total_views      + 1
        WHERE id = NEW.campaign_id
          AND remaining_budget >= NEW.reward_amount;

        IF NOT FOUND THEN
            RAISE EXCEPTION
                'Insufficient campaign budget for campaign %', NEW.campaign_id
                USING ERRCODE = 'P0001';
        END IF;

        -- Credit the creator's balance
        UPDATE users
        SET
            balance      = balance      + NEW.reward_amount,
            total_earned = total_earned + NEW.reward_amount
        WHERE id = NEW.user_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_guard_campaign_budget
AFTER UPDATE ON views_log
FOR EACH ROW EXECUTE FUNCTION guard_campaign_budget();


-- ------------------------------------------------------------
-- 9. WITHDRAWAL BALANCE GUARD TRIGGER
--    Deducts balance when a withdrawal is approved → paid.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION guard_withdrawal_balance()
RETURNS TRIGGER
LANGUAGE plpgsql AS
$$
BEGIN
    IF NEW.status = 'paid' AND OLD.status != 'paid' THEN
        UPDATE users
        SET
            balance          = balance          - NEW.amount,
            total_withdrawn  = total_withdrawn  + NEW.net_amount
        WHERE id = NEW.user_id
          AND balance >= NEW.amount;

        IF NOT FOUND THEN
            RAISE EXCEPTION
                'Insufficient balance for withdrawal % (user %)',
                NEW.id, NEW.user_id
                USING ERRCODE = 'P0002';
        END IF;

        NEW.paid_at = NOW();
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_guard_withdrawal_balance
BEFORE UPDATE ON withdrawal_requests
FOR EACH ROW EXECUTE FUNCTION guard_withdrawal_balance();


-- ------------------------------------------------------------
-- 10. SEED DATA — default admin account
--     Password: Admin@123456  (bcrypt hash, cost=12)
--     CHANGE THIS before going to production.
-- ------------------------------------------------------------
INSERT INTO users (
    email,
    password_hash,
    username,
    role,
    full_name,
    is_active,
    is_verified,
    email_verified_at
)
VALUES (
    'admin@rewardsplatform.com',
    '$2b$12$KIXtCR1wE0YqV5Lz3mP8OOQ1Vz5X7gK2nM4pA6bS9dT0uW3eY1fC',
    'admin',
    'admin',
    'Platform Administrator',
    TRUE,
    TRUE,
    NOW()
)
ON CONFLICT DO NOTHING;


-- ------------------------------------------------------------
-- 11. HELPFUL VIEWS
-- ------------------------------------------------------------

-- Per-campaign summary with remaining budget percentage
CREATE OR REPLACE VIEW v_campaign_summary AS
SELECT
    c.id,
    c.title,
    c.status,
    c.total_budget,
    c.remaining_budget,
    ROUND(
        (c.remaining_budget / NULLIF(c.total_budget, 0)) * 100,
        2
    )                               AS budget_remaining_pct,
    c.cost_per_view,
    c.total_views,
    c.unique_views,
    c.total_paid_out,
    c.starts_at,
    c.ends_at,
    u.username                      AS advertiser_username,
    u.email                         AS advertiser_email,
    c.created_at
FROM campaigns c
JOIN users u ON u.id = c.advertiser_id
WHERE c.deleted_at IS NULL;

-- Top earners leaderboard
CREATE OR REPLACE VIEW v_top_earners AS
SELECT
    u.id,
    u.username,
    u.country_code,
    u.total_earned,
    u.balance,
    u.total_withdrawn,
    COUNT(vl.id)                    AS total_views_credited
FROM users u
LEFT JOIN views_log vl
       ON vl.user_id = u.id
      AND vl.reward_credited = TRUE
WHERE u.role = 'creator'
  AND u.is_active = TRUE
  AND u.deleted_at IS NULL
GROUP BY u.id
ORDER BY u.total_earned DESC;

-- Pending withdrawal queue for admins
CREATE OR REPLACE VIEW v_pending_withdrawals AS
SELECT
    wr.id,
    wr.requested_at,
    wr.amount,
    wr.fee,
    wr.net_amount,
    wr.method,
    wr.payout_details,
    u.username,
    u.email,
    u.country_code,
    u.total_earned,
    u.balance
FROM withdrawal_requests wr
JOIN users u ON u.id = wr.user_id
WHERE wr.status = 'pending'
ORDER BY wr.requested_at ASC;

-- Daily platform revenue / activity snapshot
CREATE OR REPLACE VIEW v_daily_stats AS
SELECT
    DATE(vl.viewed_at)              AS stat_date,
    COUNT(*)                        AS total_view_attempts,
    COUNT(*) FILTER (
        WHERE vl.reward_credited = TRUE
    )                               AS credited_views,
    COUNT(*) FILTER (
        WHERE vl.is_flagged = TRUE
    )                               AS flagged_views,
    COALESCE(SUM(vl.reward_amount) FILTER (
        WHERE vl.reward_credited = TRUE
    ), 0)                           AS total_rewards_paid,
    COUNT(DISTINCT vl.user_id)      AS unique_users,
    COUNT(DISTINCT vl.campaign_id)  AS active_campaigns
FROM views_log vl
GROUP BY DATE(vl.viewed_at)
ORDER BY stat_date DESC;


-- ============================================================
-- END OF SCRIPT
-- ============================================================
