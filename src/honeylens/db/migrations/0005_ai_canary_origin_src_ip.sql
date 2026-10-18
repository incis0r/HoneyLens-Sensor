-- 0005_ai_canary_origin_src_ip — Idea 52: record who was reading the artefact.
--
-- The canary registry was written before the canary carried the origin IP. Knowing
-- *which* client was handed a canary is what turns a callback into attribution: the
-- agent that calls back is often not the address that read the honeypot output, and
-- that gap between reader and caller is the finding.
--
-- Additive + idempotent.

ALTER TABLE ai_prompt_canaries ADD COLUMN IF NOT EXISTS origin_src_ip INET;

-- Callbacks are looked up by nonce on every canary hit.
CREATE INDEX IF NOT EXISTS idx_ai_canary_nonce ON ai_prompt_canaries(nonce);
