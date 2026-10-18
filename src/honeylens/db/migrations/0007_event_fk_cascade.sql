-- 0007_event_fk_cascade — make retention able to archive at all.
--
-- attack_patterns, ja4_fingerprints and threat_scores each reference
-- sensor_events(event_id). Created with the default ON DELETE NO ACTION, they make
-- `db_archive` fail the moment it tries to remove an archived month from the live
-- table:
--
--     [ERROR] Error archiving 2026-06: update or delete on table "sensor_events"
--             violates foreign key constraint ...
--     Total archived: 0 events
--
-- The partition-drop step then runs anyway and succeeds, so the unit exits 0 and
-- the nightly log reads like a healthy retention run. It is not: nothing is being
-- archived, and the live table grows without bound while old archives are deleted.
--
-- Found by comparing the fleet. Two hosts had been converted to CASCADE by hand
-- during an earlier disk-full incident; three never were. On one of those that
-- left **7,873,995 rows older than 60 days** stuck in
-- sensor_events (April 2.68M, May 2.55M, June 2.61M) while its archive partitions
-- for those very months were being dropped.
--
-- CASCADE is the right rule here on the merits, not just for convenience: these
-- three tables are per-event derivations. An attack pattern, a JA4 fingerprint or
-- a threat score describes one event and means nothing once that event is gone —
-- exactly the reasoning behind delete_orphaned_analyses in tools/db_archive.py.
--
-- Idempotent: each constraint is dropped only if present and re-added with the
-- same name, so re-running is a no-op on a host already converted.

DO $$
DECLARE
    t   text;
    con text;
BEGIN
    FOREACH t IN ARRAY ARRAY['attack_patterns', 'ja4_fingerprints', 'threat_scores']
    LOOP
        -- Skip hosts where the table does not exist (profiles differ).
        IF to_regclass('public.' || t) IS NULL THEN
            CONTINUE;
        END IF;

        SELECT con.conname INTO con
          FROM pg_constraint con
          JOIN pg_class cl ON cl.oid = con.conrelid
          JOIN pg_class rf ON rf.oid = con.confrelid
         WHERE con.contype = 'f'
           AND cl.relname  = t
           AND rf.relname  = 'sensor_events'
           AND con.confdeltype <> 'c';        -- 'c' = CASCADE; already done

        IF con IS NOT NULL THEN
            EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', t, con);
            EXECUTE format(
                'ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (event_id) '
                'REFERENCES sensor_events(event_id) ON DELETE CASCADE', t, con);
            RAISE NOTICE 'converted %.% to ON DELETE CASCADE', t, con;
        END IF;
    END LOOP;
END $$;
