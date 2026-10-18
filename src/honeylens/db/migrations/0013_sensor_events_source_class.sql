-- 0013_sensor_events_source_class -- whose traffic was this, written by the ingest.
--
-- source_class is one of own_infra, validation, internal (the list lives in
-- honeylens.intelligence.source_class), decided from the source address at ingest.
-- **NULL means EXTERNAL -- a real actor** -- and that is the value every reader filters on,
-- so it is also what an unparseable or unrecognised address produces: guessing "ours" would
-- hide an actor on the strength of a parse failure.
--
-- Why the column exists. Measured over 30 days to 2026-11-04: 2,139,975 rows -- 12.8% of
-- everything the fleet recorded -- came from us. They are the single root cause behind the
-- window's three most distorted verdicts: ANOMALY reads 99.7% own traffic, SURICATA_ALERT
-- 97.9%, SCANNER 83.1%. Report-time CIDR guessing could not fix that, because provenance is a
-- fact about the moment of capture and the CIDR list changes under it.
--
-- The rows are kept and marked, not dropped at ingest: a validation run is evidence the decoy
-- works, and a row that vanishes cannot be audited.
--
-- Additive and idempotent: a nullable VARCHAR(16) with no default, so no table rewrite and no
-- existing row is touched. **Existing rows stay NULL until Task C5 backfills them**, which
-- means that until that pass runs the column says "every stored row is external" -- true of
-- 87.2% of them and wrong about the rest, so read it only after the backfill.
--
-- The index is partial on the predicate every reader will use. `source_class IS NULL` selects
-- 87.2% of the table, which is normally the wrong shape for an index -- but these queries
-- always carry a timestamp range and a grouping as well, so this exists to let the planner
-- combine it with idx_se_timestamp rather than to be selective on its own. A partial index also
-- costs nothing on the 12.8%: those rows are simply not in it.
--
-- Guarded with to_regclass as 0010 and 0011 are: sensor_events exists on every profile today,
-- and a migration that assumes a table is how a runner starts failing on the one host that
-- differs.

DO $$
BEGIN
    IF to_regclass('public.sensor_events') IS NULL THEN
        RETURN;
    END IF;

    ALTER TABLE sensor_events ADD COLUMN IF NOT EXISTS source_class VARCHAR(16);
END $$;

CREATE INDEX IF NOT EXISTS idx_se_source_class_external
    ON sensor_events (timestamp DESC)
    WHERE source_class IS NULL;
