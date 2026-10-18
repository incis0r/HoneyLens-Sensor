-- 0010_ics_events_fk — stop retention from leaving ics_events rows behind.
--
-- ics_events.event_id has a UNIQUE constraint but no foreign key to
-- sensor_events(event_id). Retention removes old events from sensor_events, and the
-- CORRECTION (2026-10-25, measured after deploy): "108 orphans on sensor-b" below conflates two
-- definitions. For THIS KEY they are genuine violations -- an FK references sensor_events and
-- knows nothing of archive partitions -- so NOT VALID was required, as designed. For the ORPHAN
-- SWEEP they are not orphans: _event_exists_clause counts an event in any surviving
-- archive_events_YYYY_MM as existing, and all 108 sit in sensor-b's archive_events_2026_09 (3721
-- rows). The sweep ran after deploy and correctly deleted nothing. So no ics_events row on the
-- fleet points at an event that cannot be found; the class was real (no FK, outside the sweep)
-- and this key is pre-emptive. The genuinely unfindable rows are mitm_events on prod (4272 of
-- 4272) and llm_honeypot_events on sensor-d (61), neither covered by this phase.
--
-- orphan sweep in tools/db_archive.py originally covered only ANALYSIS_TABLES
-- (ai_analysis and claude_analysis_log), so every ICS row outlived the event it
-- describes. The sweep now also covers ics_events (ORPHAN_TABLES) and clears the
-- orphans that already exist; this foreign key is what stops new ones, from the
-- moment it is added.
--
-- Measured 2026-10-25: 108 ics_events rows on sensor-b whose event has left the live table
-- (FK violations for this key; not sweep orphans -- see the correction above), oldest dated
-- 2026-09-20 -- five days older than the oldest surviving sensor_events row.
--
-- This is the same bug already paid for once. The docstring of
-- delete_orphaned_analyses records it: 63% of ai_analysis and 62% of
-- claude_analysis_log rows on PROD (4.4 GB) were orphaned "because retention covered
-- sensor_events alone". That fix added two tables to a list and did not make the next
-- table safe. ics_events is the next table, and this key is the rule in the schema
-- rather than another list entry.
--
-- It does not make the class safe, and saying it did would be the same false claim one
-- generation on. Two per-event derivations are still exactly where ics_events stood
-- before today -- event_id VARCHAR(64) UNIQUE NOT NULL, no foreign key, no entry in
-- ORPHAN_TABLES -- and their orphans are not hypothetical. Measured across all seven
-- sensors on 2026-10-25:
--
--     mitm_events (0001_base_schema.sql:310-312)
--         prod    4263 rows, ALL 4263 orphaned (3120 kB)
--         zero rows on the other six
--     llm_honeypot_events (0008_llm_honeypot_events.sql:10)
--         sensor-d       62 rows, ALL   62 orphaned (216 kB)
--         sensor-b     33 rows,       0 orphaned
--         sensor-c     1 row,        0 orphaned
--         zero rows on the other four
--     pcap_index: 0 rows on all seven; every other host/table pair: 0 rows.
--
-- Those are the known remaining instances, and they are deliberately left alone here.
-- Adding them to ORPHAN_TABLES would make the nightly retention timer delete 4325 rows
-- on prod and sensor-d with nobody running anything, and whether that data goes is the
-- operator's decision, not a side effect of this header being made honest. Follow-up:
-- decide per table whether it gets a cascade key of its own (the rule) or a sweep entry
-- (the list), and apply that -- after the decision, not before.
--
-- CASCADE is right on the merits, as in 0007: an ICS event is a per-event record
-- keyed to one sensor_events row, exactly like attack_patterns, ja4_fingerprints and
-- threat_scores, and means nothing once that event is gone.
--
-- Operator decision (settled): ICS rows now expire with the live event at 30 days,
-- rather than following it into the archive for 30-61 days. Retention copies events
-- into archive_events_YYYY_MM and then removes them from sensor_events, and
-- _event_exists_clause in db_archive.py counts an archived event as still existing,
-- so a sweep-based fix would have kept ICS rows for the longer window. The foreign key
-- does not. attack_patterns, ja4_fingerprints and threat_scores already behave this
-- way. The first archive partitions appear around 7 November, so the change becomes
-- observable then.
--
-- NOT VALID is what makes this legal. migrate.apply() never deletes or rewrites
-- data, and a validating ADD CONSTRAINT would simply fail on sensor-b with its 108
-- orphans -- the only way through would be a DELETE FROM ics_events inside a migration.
-- NOT VALID skips checking the rows already present but still installs the triggers,
-- so ON DELETE CASCADE applies to every removal from now on. The existing orphans are
-- cleared separately, by the orphan sweep. NOT VALID also keeps the work to a
-- catalogue change instead of a scan of sensor_events, which matters on sensor-a
-- (8.4 M rows) and prod (4.9 M).
--
-- Lock caveat, for the rollout runbook: ADD FOREIGN KEY, even NOT VALID, takes
-- SHARE ROW EXCLUSIVE on both tables, which conflicts with the ROW EXCLUSIVE that
-- every ingest INSERT holds on sensor_events. migrate.apply() sets
-- lock_timeout = 3000ms and then records the version as applied regardless, with a
-- warning. A busy sensor can therefore end up with 0010 recorded and no constraint.
-- Verify on each host with the delete rule in the projection, because an existing key
-- with the wrong rule is the failure this migration also has to fix:
--
--     SELECT conname, confdeltype, convalidated FROM pg_constraint
--      WHERE conrelid = to_regclass('public.ics_events') AND contype = 'f';
--
-- Expected: one row, ics_events_event_id_fkey, confdeltype = 'c', convalidated = false.
-- No rows with to_regclass returning NULL is the legitimate skip below, not a failure.
-- Re-run with force=True where the key is missing; force re-applies all ten migrations,
-- which is safe (0001-0009 are guarded or IF NOT EXISTS, and 0007 skips a host already
-- cascaded) but is worth knowing before running it.
--
-- Like 0007, this CONVERTS a foreign key created with the wrong delete rule rather than
-- skipping it. The first version of this file returned early on *any* foreign key from
-- ics_events to sensor_events, which made it a silent no-op on a host that had acquired
-- a hand-made NO ACTION key -- and db_archive would then fail exactly as 0007's header
-- records ('update or delete on table "sensor_events" violates foreign key constraint'),
-- with the partition drop still succeeding and the unit still exiting 0. 0007 exists
-- because these seven hosts diverge by hand; the base schema declares no key here at all.
--
-- Idempotent: skipped when ics_events or sensor_events is absent (profiles differ) and
-- when a correctly cascading key is already present, so re-running is a no-op.

DO $$
DECLARE
    con_name text;
BEGIN
    IF to_regclass('public.ics_events') IS NULL
       OR to_regclass('public.sensor_events') IS NULL THEN
        RETURN;
    END IF;

    -- Every foreign key to sensor_events whose delete rule is not CASCADE goes, so the
    -- correct one can be added below. The name is read from the catalogue, never
    -- assumed: a key added by hand during an incident is called whatever that hand
    -- chose, and 'ics_events_event_id_fkey' is only this migration's own choice.
    FOR con_name IN
        SELECT con.conname
          FROM pg_constraint con
          JOIN pg_class cl ON cl.oid = con.conrelid
          JOIN pg_class rf ON rf.oid = con.confrelid
         WHERE con.contype = 'f'
           AND cl.relname  = 'ics_events'
           AND rf.relname  = 'sensor_events'
           AND con.confdeltype <> 'c'        -- 'c' = CASCADE; already correct
    LOOP
        EXECUTE format('ALTER TABLE ics_events DROP CONSTRAINT %I', con_name);
        RAISE NOTICE 'ics_events: dropped non-cascading key % for re-creation', con_name;
    END LOOP;

    -- A correctly cascading key is left exactly as it is, so a re-run changes nothing.
    IF EXISTS (
        SELECT 1
          FROM pg_constraint con
          JOIN pg_class cl ON cl.oid = con.conrelid
          JOIN pg_class rf ON rf.oid = con.confrelid
         WHERE con.contype = 'f'
           AND cl.relname  = 'ics_events'
           AND rf.relname  = 'sensor_events'
           AND con.confdeltype = 'c'
    ) THEN
        RETURN;
    END IF;

    ALTER TABLE ics_events
        ADD CONSTRAINT ics_events_event_id_fkey
        FOREIGN KEY (event_id) REFERENCES sensor_events(event_id)
        ON DELETE CASCADE
        NOT VALID;
END $$;
