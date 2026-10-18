-- API/manual hunting needs these tables even when the daemon has never run.
CREATE TABLE IF NOT EXISTS attacker_osint_log (
    id BIGSERIAL PRIMARY KEY,
    ip INET NOT NULL,
    provider VARCHAR(32) NOT NULL,
    response_code SMALLINT,
    response_data JSONB,
    queried_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_aol_ip ON attacker_osint_log (ip);
CREATE INDEX IF NOT EXISTS idx_aol_provider ON attacker_osint_log (provider);
CREATE INDEX IF NOT EXISTS idx_aol_queried ON attacker_osint_log (queried_at DESC);

CREATE TABLE IF NOT EXISTS attacker_tags (
    id SERIAL PRIMARY KEY,
    tag_name VARCHAR(64) NOT NULL UNIQUE,
    description TEXT,
    mitre_techniques TEXT[],
    apt_groups JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Durable requests survive API/worker restarts. A session advisory lock ensures
-- one worker; rows remain queued until the profile is committed successfully.
CREATE TABLE IF NOT EXISTS attacker_hunt_queue (
    ip INET PRIMARY KEY,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    attempts INTEGER NOT NULL DEFAULT 0,
    retry_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_hunt_queue_retry ON attacker_hunt_queue (retry_at, requested_at);
