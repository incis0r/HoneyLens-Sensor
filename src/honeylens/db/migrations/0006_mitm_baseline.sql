-- 0006_mitm_baseline — move the MiTM baseline schema out of a service's startup path.
--
-- `mitm_events.baseline` and the `mitm_baseline` table were only ever created by
-- `intelligence/mitm_detector.py::_ensure_tables`, which runs when — and only when —
-- sensor-mitm starts. The API queries both unconditionally.
--
-- On any sensor that does not run the MiTM detector the objects therefore never
-- existed, and every /mitm request failed with:
--
--     psycopg2.errors.UndefinedColumn: column "baseline" does not exist
--
-- Found 2026-08-27: DEV had the schema, and the edge host, sensor-a, PROD, sensor-e and sensor-f did
-- not — five of six. sensor-a does not run sensor-mitm at all. Worse than the failing
-- endpoint was its side effect: each failure leaked a database connection, and once
-- eleven had accumulated the API could not serve anything, so /ics/stats, /ai/stats
-- and / all timed out. (The leak itself is fixed separately, in routes/_helpers.db
-- plus DbConnScopeMiddleware — a schema gap should never have been able to take an
-- API down, and now cannot.)
--
-- The lesson this file encodes: schema belongs in a numbered migration, not in the
-- startup path of one optional service. A service that may not be installed cannot
-- be the thing that creates what another component requires.
--
-- Additive + idempotent; matches the detector's definition exactly so the two can
-- coexist during rollout.

-- Baselined events are known-good: hidden from the main dashboard and excluded
-- from alert counts, listed under the "baseline events" view.
ALTER TABLE mitm_events ADD COLUMN IF NOT EXISTS baseline BOOLEAN DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_mitm_baseline_flag ON mitm_events(baseline);

-- Operator-declared baseline entries: "this LLMNR responder is our own DC".
CREATE TABLE IF NOT EXISTS mitm_baseline (
    id          BIGSERIAL PRIMARY KEY,
    attack_type VARCHAR(50),
    src_ip      INET,
    src_mac     MACADDR,
    note        TEXT,
    created_by  VARCHAR(128),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The detector matches an incoming event against the baseline on every detection.
CREATE INDEX IF NOT EXISTS idx_mitm_baseline_match ON mitm_baseline(attack_type, src_ip);
