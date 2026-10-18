-- 0012_attack_patterns_unique -- the unique index that three ON CONFLICT clauses already assume.
--
-- 0001 created attack_patterns with two plain indexes and no unique constraint beyond the id
-- primary key. The Suricata ingest inserts its row with
-- `ON CONFLICT (event_id, attack_type, rule_name) DO NOTHING`, which Postgres rejects outright
-- when no unique index matches those columns:
--     there is no unique or exclusion constraint matching the ON CONFLICT specification
-- That error is a psycopg2.Error, so it was swallowed by the handler around the insert and the
-- ingest reported nothing. Measured on sensor-a 2026-11-01: **zero** rows with
-- `rule_name LIKE 'suricata_sid_%'`, against 2.19M Suricata events. Every Suricata detection has
-- been living only in sensor_events.attack_types, with no attack_patterns row behind it -- and a
-- reprocess rebuilds attack_types from attack_patterns, so the nightly backfill erased 1,991,772
-- of those labels on sensor-a alone and 49,772 on sensor-b.
--
-- The central classifier escaped this because write_patterns_batch uses a bare
-- `ON CONFLICT DO NOTHING`, which needs no index -- and therefore also never deduplicates, so
-- re-running a pattern backfill inserted copies. This index fixes both: the Suricata clause
-- becomes legal, and every DO NOTHING in the codebase starts being genuinely idempotent.
--
-- Duplicates must go first or the index cannot be built. Measured fleet-wide before writing this:
-- sensor-a 120 excess rows, sensor-b 5, sensor-c 2, sensor-e/sensor-f/sensor-d 0 -- out of 8.7M, 115k, 267k. The
-- dedupe keeps the lowest id of each group, which is the first row written.
--
-- The index build takes a write lock on attack_patterns for its duration (seconds on 8.7M rows).
-- The ingest is timer-driven and reads from log files, so a short backpressure loses nothing.

DELETE FROM attack_patterns ap
USING (
    SELECT event_id, attack_type, rule_name, min(id) AS keep_id
    FROM attack_patterns
    GROUP BY event_id, attack_type, rule_name
    HAVING count(*) > 1
) dup
WHERE ap.event_id = dup.event_id
  AND ap.attack_type = dup.attack_type
  AND ap.rule_name = dup.rule_name
  AND ap.id <> dup.keep_id;

CREATE UNIQUE INDEX IF NOT EXISTS idx_ap_event_type_rule
    ON attack_patterns (event_id, attack_type, rule_name);
