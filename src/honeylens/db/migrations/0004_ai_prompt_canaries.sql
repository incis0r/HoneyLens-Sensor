-- 0004_ai_prompt_canaries — Idea 52 Phase A: durable AI prompt-injection canary store.
-- Additive + idempotent. Phase A correlates nonces in-process and emits callbacks as
-- AI_AGENT_CALLBACK honeypot events; this table is the durable option for Phase B
-- (issue rows, callback latency, dashboard metrics). Harmless no-op until then.

CREATE TABLE IF NOT EXISTS ai_prompt_canaries (
    id                   BIGSERIAL PRIMARY KEY,
    nonce                TEXT UNIQUE NOT NULL,
    canary_type          TEXT NOT NULL,
    carrier              TEXT NOT NULL,
    origin_event_id      TEXT,
    origin_protocol      TEXT,
    origin_path          TEXT,
    issued_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at           TIMESTAMPTZ,
    callback_at          TIMESTAMPTZ,
    callback_src_ip      INET,
    callback_user_agent  TEXT,
    callback_headers     JSONB,
    callback_body_sample TEXT
);
CREATE INDEX IF NOT EXISTS idx_ai_canary_callback_at ON ai_prompt_canaries(callback_at);
