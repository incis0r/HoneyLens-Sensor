-- 0014_honeypot_api_keys -- Per-honeypot read-only API keys paired with HTTP Basic Auth.
--
-- Each honeypot API key is bound to:
--   1. A honeypot scope (`honeypot`, e.g. 'ssh', 'fortigate', 'paloalto', 'k8s', or '*' for all)
--   2. A unique HTTP Basic Auth credential pair (`apiaccess1:<randompass>`, `apiaccess2:<randompass>`, ...)
--   3. A unique API key token (stored only as a SHA-256 hash + short prefix for UI display)
--
-- Expiration & rotation policy:
--   * Default max age is <= 90 days (`max_age_days <= 90`).
--   * Extended 365-day keys (`max_age_days = 365`) are permitted ONLY when the operator
--     explicitly acknowledges the security risk (`risk_acknowledged = TRUE`).
--   * Keys can be revoked immediately by an admin (`revoked = TRUE`).

CREATE TABLE IF NOT EXISTS honeypot_api_keys (
    id                  SERIAL PRIMARY KEY,
    key_name            VARCHAR(128) NOT NULL DEFAULT '',
    honeypot            VARCHAR(64) NOT NULL,
    basic_username      VARCHAR(64) UNIQUE NOT NULL,
    basic_password_hash VARCHAR(256) NOT NULL,
    basic_salt          VARCHAR(64) NOT NULL,
    api_key_prefix      VARCHAR(24) NOT NULL,
    api_key_hash        VARCHAR(128) UNIQUE NOT NULL,
    max_age_days        INTEGER NOT NULL DEFAULT 90,
    risk_acknowledged   BOOLEAN NOT NULL DEFAULT FALSE,
    created_by          INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,
    last_used_at        TIMESTAMPTZ,
    last_used_ip        INET,
    revoked             BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at          TIMESTAMPTZ,
    revoked_by          INTEGER REFERENCES users(id) ON DELETE SET NULL,
    revoked_reason      TEXT
);

CREATE INDEX IF NOT EXISTS idx_hp_api_keys_honeypot
    ON honeypot_api_keys (honeypot);

CREATE INDEX IF NOT EXISTS idx_hp_api_keys_basic_username
    ON honeypot_api_keys (basic_username);

CREATE INDEX IF NOT EXISTS idx_hp_api_keys_api_key_hash
    ON honeypot_api_keys (api_key_hash);

CREATE INDEX IF NOT EXISTS idx_hp_api_keys_expires_at
    ON honeypot_api_keys (expires_at)
    WHERE revoked = FALSE;
