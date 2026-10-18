-- 0011_ics_events_semantics -- what an ICS frame means, written by the ingest.
--
-- semantics is one of read, enumerate, discovery, write, command, control, anomaly (the
-- list lives in honeylens.ics.SEMANTICS), decoded from the captured bytes. NULL means the
-- frame decodes but its code is not in the specification, or there were no bytes to
-- decode. The five is_* booleans stay for compatibility; semantics is the single truth.
--
-- Additive and idempotent: a nullable semantics column with no default, so no table rewrite and no
-- existing row is touched. Existing rows keep NULL until a backfill decides otherwise.
-- Skipped where ics_events is absent (profiles differ), as in 0010.

DO $$
BEGIN
    IF to_regclass('public.ics_events') IS NULL THEN
        RETURN;
    END IF;

    ALTER TABLE ics_events ADD COLUMN IF NOT EXISTS semantics VARCHAR(16);
    -- The ingest INSERT also writes is_anomaly. 0001 already creates it; restated here so
    -- this migration does not depend on that, and it stays a no-op where the column exists.
    ALTER TABLE ics_events ADD COLUMN IF NOT EXISTS is_anomaly BOOLEAN DEFAULT FALSE;
END $$;
