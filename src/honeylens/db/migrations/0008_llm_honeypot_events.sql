-- 0008_llm_honeypot_events — the LLM honeypot table moves from honeypot code into a migration.
--
-- In 0.9 honeypot_llm.py created it itself at startup (init_db), so the schema depended
-- on which process came up first, and the honeypot had to hold database credentials.
-- In 1.0 the honeypot is a container with no database access; ingest/honeypot.py inserts
-- the rows from the ``llm`` block of the event line. Content identical to the 0.9
-- honeypot's _DB_SCHEMA.
CREATE TABLE IF NOT EXISTS llm_honeypot_events (
    id              BIGSERIAL       PRIMARY KEY,
    event_id        VARCHAR(64)     UNIQUE NOT NULL,
    timestamp       TIMESTAMPTZ     DEFAULT NOW(),
    session_id      VARCHAR(64)     NOT NULL,
    src_ip          INET            NOT NULL,
    turn_number     INTEGER         DEFAULT 1,
    user_message    TEXT            NOT NULL,
    message_tokens  INTEGER,
    message_entropy FLOAT,
    attack_category VARCHAR(32),
    attack_rules    TEXT[],
    confidence      INTEGER,
    severity        VARCHAR(16),
    response_text   TEXT,
    response_strategy VARCHAR(32),
    response_ms     INTEGER,
    actor_type      VARCHAR(16),
    agent_score     INTEGER,
    timing_ms       FLOAT,
    endpoint        VARCHAR(64),
    model_requested VARCHAR(64),
    api_key_used    VARCHAR(64),
    user_agent      TEXT,
    headers         JSONB,
    mitre_technique VARCHAR(32),
    mitre_tactic    VARCHAR(64),
    created_at      TIMESTAMPTZ     DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_llm_hp_session ON llm_honeypot_events (session_id);
CREATE INDEX IF NOT EXISTS idx_llm_hp_ip      ON llm_honeypot_events (src_ip);
CREATE INDEX IF NOT EXISTS idx_llm_hp_attack  ON llm_honeypot_events (attack_category);
CREATE INDEX IF NOT EXISTS idx_llm_hp_agent   ON llm_honeypot_events (actor_type)
    WHERE actor_type = 'LLM_AGENT';
CREATE INDEX IF NOT EXISTS idx_llm_hp_time    ON llm_honeypot_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_llm_hp_sev     ON llm_honeypot_events (severity)
    WHERE severity IN ('CRITICAL', 'HIGH');
