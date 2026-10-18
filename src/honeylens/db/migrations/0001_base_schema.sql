-- 0001_base_schema — CREATE TABLE/INDEX (idempotent). Extracted from
-- setup_db.py SQL_CREATE_TABLE (Phase 2 / T9). Do not hand-edit for parity;
-- add NEW schema changes as higher-numbered migration files.

CREATE TABLE IF NOT EXISTS sensor_events (
    id              BIGSERIAL       PRIMARY KEY,
    event_id        VARCHAR(64)     UNIQUE NOT NULL,
    timestamp       TIMESTAMPTZ,
    source          VARCHAR(32),
    protocol        VARCHAR(32),
    src_ip          INET,
    src_port        INTEGER,
    dst_ip          INET,
    dst_port        INTEGER,
    payload         TEXT,
    payload_hash    VARCHAR(64),
    scan_score      DOUBLE PRECISION,
    port_entropy    DOUBLE PRECISION,
    ja3             VARCHAR(64),
    metadata        JSONB,
    attack_types    TEXT,
    created_at      TIMESTAMPTZ     DEFAULT NOW()
);

-- Migration: add attack_types column if upgrading from older schema
-- MUST run BEFORE creating indexes that reference this column
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'sensor_events' AND column_name = 'attack_types')
    THEN
        ALTER TABLE sensor_events ADD COLUMN attack_types TEXT;
        RAISE NOTICE 'Added attack_types column to sensor_events';
    END IF;
END $$;

-- Migration: full_payload columns for Idea 30 Phase 0 (eBPF full dissection)
-- Populated by ingest/ebpf.py when the destination port is in monitored_ports
-- and the captured payload exceeds the 256-byte default sample.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'sensor_events' AND column_name = 'full_payload')
    THEN
        ALTER TABLE sensor_events ADD COLUMN full_payload BYTEA;
        RAISE NOTICE 'Added full_payload column to sensor_events';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'sensor_events' AND column_name = 'full_payload_hash')
    THEN
        ALTER TABLE sensor_events ADD COLUMN full_payload_hash VARCHAR(64);
        RAISE NOTICE 'Added full_payload_hash column to sensor_events';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'sensor_events' AND column_name = 'tcp_seq')
    THEN
        ALTER TABLE sensor_events ADD COLUMN tcp_seq BIGINT;
        RAISE NOTICE 'Added tcp_seq column to sensor_events';
    END IF;
END $$;

-- Runtime port-management table for eBPF full dissection (Idea 30 Phase 0).
-- sensor-capture polls this every EBPF_DISSECTION_RECONCILE_SEC seconds and
-- reconciles the monitored_ports BPF map. Adding a port via SQL or the admin
-- endpoint is effective without restart.
CREATE TABLE IF NOT EXISTS ebpf_dissection_ports (
    port            INTEGER         PRIMARY KEY,
    capture_depth   INTEGER         NOT NULL DEFAULT 4096,
    retain_hours    INTEGER         NOT NULL DEFAULT 168,
    enabled         BOOLEAN         NOT NULL DEFAULT TRUE,
    reason          TEXT,
    added_by        TEXT,
    added_at        TIMESTAMPTZ     DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     DEFAULT NOW(),
    CHECK (port BETWEEN 1 AND 65535),
    CHECK (capture_depth IN (256, 1024, 4096)),
    CHECK (retain_hours BETWEEN 1 AND 8760)
);

-- Attack pattern detail table: one row per detected pattern per event
CREATE TABLE IF NOT EXISTS attack_patterns (
    id              BIGSERIAL       PRIMARY KEY,
    event_id        VARCHAR(64)     NOT NULL REFERENCES sensor_events(event_id),
    attack_type     VARCHAR(32)     NOT NULL,
    rule_name       VARCHAR(64)     NOT NULL,
    matched_text    TEXT,
    severity        VARCHAR(16)     DEFAULT 'medium',  -- critical, high, medium, low, info
    confidence      VARCHAR(16)     DEFAULT 'high',    -- high, medium, low
    created_at      TIMESTAMPTZ     DEFAULT NOW()
);

-- Migration: Add severity column to existing attack_patterns table
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'attack_patterns' AND column_name = 'severity')
    THEN
        ALTER TABLE attack_patterns ADD COLUMN severity VARCHAR(16) DEFAULT 'medium';
        RAISE NOTICE 'Added severity column to attack_patterns';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'attack_patterns' AND column_name = 'confidence')
    THEN
        ALTER TABLE attack_patterns ADD COLUMN confidence VARCHAR(16) DEFAULT 'high';
        RAISE NOTICE 'Added confidence column to attack_patterns';
    END IF;
END $$;

-- Rule statistics table: tracks effectiveness of detection rules
CREATE TABLE IF NOT EXISTS rule_statistics (
    id              SERIAL          PRIMARY KEY,
    rule_name       VARCHAR(128)    UNIQUE NOT NULL,
    attack_type     VARCHAR(64)     NOT NULL,
    total_hits      BIGINT          DEFAULT 0,
    confirmed_true  BIGINT          DEFAULT 0,
    confirmed_false BIGINT          DEFAULT 0,
    last_hit        TIMESTAMPTZ,
    avg_score       FLOAT,
    severity        VARCHAR(16),
    enabled         BOOLEAN         DEFAULT TRUE,
    notes           TEXT,
    created_at      TIMESTAMPTZ     DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     DEFAULT NOW()
);

-- Threat score history: stores calculated threat scores for analytics
CREATE TABLE IF NOT EXISTS threat_scores (
    id              BIGSERIAL       PRIMARY KEY,
    event_id        VARCHAR(64)     NOT NULL REFERENCES sensor_events(event_id),
    score           INTEGER         NOT NULL,  -- 0-100
    severity        VARCHAR(16)     NOT NULL,  -- critical, high, medium, low, info
    attack_types    TEXT[],                    -- Array of detected attack types
    chain_detected  VARCHAR(64),               -- Name of attack chain if detected
    hit_count       INTEGER         NOT NULL,
    metadata        JSONB,                     -- Additional scoring details
    created_at      TIMESTAMPTZ     DEFAULT NOW()
);

-- JA4+ fingerprint table: stores all JA4+ fingerprints for each event
-- Supports: JA4, JA4S, JA4H, JA4X, JA4SSH, JA4T, JA4TS
CREATE TABLE IF NOT EXISTS ja4_fingerprints (
    id              BIGSERIAL       PRIMARY KEY,
    event_id        VARCHAR(64)     NOT NULL REFERENCES sensor_events(event_id),
    fingerprint_type VARCHAR(16)    NOT NULL,  -- 'ja4', 'ja4s', 'ja4h', 'ja4x', 'ja4ssh', 'ja4t'
    fingerprint     VARCHAR(128)    NOT NULL,  -- Full fingerprint (a_b_c format)
    fingerprint_a   VARCHAR(32),               -- Part a (human-readable prefix)
    fingerprint_b   VARCHAR(16),               -- Part b (first hash)
    fingerprint_c   VARCHAR(16),               -- Part c (second hash)
    fingerprint_raw TEXT,                      -- Raw/unsorted fingerprint for deep analysis
    tls_version     VARCHAR(16),               -- TLS version string
    sni             VARCHAR(255),              -- Server Name Indication
    alpn            VARCHAR(64),               -- ALPN value
    cipher_count    INTEGER,                   -- Number of cipher suites
    extension_count INTEGER,                   -- Number of extensions
    identified      VARCHAR(128),              -- Known fingerprint identification
    metadata        JSONB,                     -- Additional fingerprint details
    created_at      TIMESTAMPTZ     DEFAULT NOW()
);

-- Migration: add ja4_fingerprints table if upgrading from older schema
-- (table creation is IF NOT EXISTS, so this is just for documentation)

-- Performance indexes — sensor_events
-- NOTE: Reviewed 2026-04-07 after production analysis (25M+ events on DEV).
--   Removed: idx_se_src_ip (superseded by ip_time), idx_se_dst_port (0 scans),
--   idx_se_protocol (0 scans), idx_se_source (superseded by source_time),
--   idx_se_scan_score (0 scans), idx_se_event_id (duplicates pkey),
--   idx_se_proto_port (0 scans). These wasted 4.4GB on DEV.
CREATE INDEX IF NOT EXISTS idx_se_timestamp   ON sensor_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_se_attack      ON sensor_events (attack_types);

-- Composite indexes — sensor_events (optimised for dashboard queries)
CREATE INDEX IF NOT EXISTS idx_se_ip_time     ON sensor_events (src_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_se_source_time ON sensor_events (source, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_se_attack_time ON sensor_events (attack_types, timestamp DESC)
    WHERE attack_types IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_se_attack_notnull ON sensor_events (timestamp DESC)
    WHERE attack_types IS NOT NULL AND attack_types != '';
-- Covering partial index for the Suricata dashboard (routes/intelligence.py
-- suricata_stats): COUNT(*) + time-window FILTERs + COUNT(DISTINCT suricata_sid/src_ip)
-- over source='suricata'. Without it the dashboard seq-scans sensor_events and times out
-- on large tables. On big live tables build it CONCURRENTLY with statement_timeout=0.
CREATE INDEX IF NOT EXISTS idx_se_suricata_stats ON sensor_events (timestamp, suricata_sid, src_ip)
    WHERE source = 'suricata';

-- Performance indexes — attack_patterns
CREATE INDEX IF NOT EXISTS idx_ap_event_id    ON attack_patterns (event_id);
CREATE INDEX IF NOT EXISTS idx_ap_type_created ON attack_patterns (attack_type, created_at DESC);

-- Performance indexes — rule_statistics
CREATE INDEX IF NOT EXISTS idx_rs_rule_name   ON rule_statistics (rule_name);
CREATE INDEX IF NOT EXISTS idx_rs_attack_type ON rule_statistics (attack_type);
CREATE INDEX IF NOT EXISTS idx_rs_severity    ON rule_statistics (severity);
CREATE INDEX IF NOT EXISTS idx_rs_hits        ON rule_statistics (total_hits DESC);
CREATE INDEX IF NOT EXISTS idx_rs_last_hit    ON rule_statistics (last_hit DESC);
CREATE INDEX IF NOT EXISTS idx_rs_enabled     ON rule_statistics (enabled);

-- Performance indexes — threat_scores
CREATE INDEX IF NOT EXISTS idx_ts_event_id    ON threat_scores (event_id);
CREATE INDEX IF NOT EXISTS idx_ts_score       ON threat_scores (score DESC);
CREATE INDEX IF NOT EXISTS idx_ts_severity    ON threat_scores (severity);
CREATE INDEX IF NOT EXISTS idx_ts_chain       ON threat_scores (chain_detected) WHERE chain_detected IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ts_time        ON threat_scores (created_at DESC);

-- Performance indexes — ja4_fingerprints
CREATE INDEX IF NOT EXISTS idx_ja4_event_id   ON ja4_fingerprints (event_id);
CREATE INDEX IF NOT EXISTS idx_ja4_type       ON ja4_fingerprints (fingerprint_type);
CREATE INDEX IF NOT EXISTS idx_ja4_fp         ON ja4_fingerprints (fingerprint);
CREATE INDEX IF NOT EXISTS idx_ja4_fp_a       ON ja4_fingerprints (fingerprint_a);
CREATE INDEX IF NOT EXISTS idx_ja4_sni        ON ja4_fingerprints (sni);
CREATE INDEX IF NOT EXISTS idx_ja4_identified ON ja4_fingerprints (identified);
CREATE INDEX IF NOT EXISTS idx_ja4_fp_time    ON ja4_fingerprints (fingerprint, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ja4_sni_time   ON ja4_fingerprints (sni, created_at DESC)
    WHERE sni IS NOT NULL;

-- =============================================================================
-- Materialised View — Dashboard Event Stats (Idea 7)
-- =============================================================================
-- Avoids COUNT(*) on 25M+ rows on every dashboard page load.
-- Refresh via cron every 5 minutes:
--   */5 * * * * sensor PGPASSWORD=xxx psql -U sensor_user -d sensor -c "REFRESH MATERIALIZED VIEW CONCURRENTLY mv_event_stats;"

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_event_stats AS
SELECT
    COUNT(*) as total_events,
    MAX(timestamp) as latest_event,
    COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '5 minutes') as recent_5m,
    COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '1 hour') as recent_1h,
    COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours') as recent_24h,
    COUNT(DISTINCT src_ip) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours') as unique_ips_24h,
    NOW() as refreshed_at
FROM sensor_events;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_event_stats ON mv_event_stats(refreshed_at);

-- =============================================================================
-- User Management Tables
-- =============================================================================

-- User accounts table
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL          PRIMARY KEY,
    username        VARCHAR(64)     UNIQUE NOT NULL,
    name            VARCHAR(128),
    lastname        VARCHAR(128),
    email           VARCHAR(256)    UNIQUE NOT NULL,
    password_hash   VARCHAR(256)    NOT NULL,
    salt            VARCHAR(64)     NOT NULL,
    role            VARCHAR(32)     NOT NULL DEFAULT 'user',
    created_at      TIMESTAMPTZ     DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     DEFAULT NOW(),
    last_login      TIMESTAMPTZ,
    is_active       BOOLEAN         DEFAULT TRUE,
    failed_attempts INTEGER         DEFAULT 0,
    locked_until    TIMESTAMPTZ
);

-- Admin audit log for tracking administrative actions
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id              SERIAL          PRIMARY KEY,
    admin_user_id   INTEGER         REFERENCES users(id),
    action          VARCHAR(64)     NOT NULL,
    target_user_id  INTEGER         REFERENCES users(id),
    details         JSONB,
    ip_address      INET,
    timestamp       TIMESTAMPTZ     DEFAULT NOW()
);

-- Performance indexes — users
CREATE INDEX IF NOT EXISTS idx_users_username   ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_email      ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_role       ON users (role);
CREATE INDEX IF NOT EXISTS idx_users_active     ON users (is_active);

-- Performance indexes — admin_audit_log
CREATE INDEX IF NOT EXISTS idx_audit_admin      ON admin_audit_log (admin_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_target     ON admin_audit_log (target_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action     ON admin_audit_log (action);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp  ON admin_audit_log (timestamp DESC);

-- =============================================================================
-- User Sessions (server-side session management)
-- =============================================================================
-- Stores hashed session tokens (SHA-256). Raw tokens live only in cookies.
-- If DB is compromised, hashed tokens cannot be replayed.

CREATE TABLE IF NOT EXISTS user_sessions (
    id              BIGSERIAL       PRIMARY KEY,
    session_hash    VARCHAR(128)    NOT NULL UNIQUE,
    user_id         INTEGER         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ     NOT NULL,
    last_active_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    ip_address      INET,
    user_agent      TEXT,
    is_persistent   BOOLEAN         DEFAULT FALSE,
    revoked         BOOLEAN         DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ,
    revoked_reason  VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS idx_sessions_hash    ON user_sessions (session_hash) WHERE NOT revoked;
CREATE INDEX IF NOT EXISTS idx_sessions_user    ON user_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions (expires_at);

-- =============================================================================
-- MiTM Detection Tables
-- =============================================================================
-- Stores detected MiTM attacks (ARP spoofing, DNS poisoning, etc.)
-- Written directly by mitm_detector.py in real-time

CREATE TABLE IF NOT EXISTS mitm_events (
    id              BIGSERIAL       PRIMARY KEY,
    event_id        VARCHAR(64)     UNIQUE NOT NULL,
    timestamp       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    -- Attack classification
    attack_type     VARCHAR(50)     NOT NULL,  -- ARP_SPOOF, DNS_POISON, etc.
    severity        VARCHAR(10)     NOT NULL,  -- LOW, MEDIUM, HIGH, CRITICAL
    confidence      SMALLINT        NOT NULL,  -- 0-100 confidence score

    -- Network identifiers
    src_mac         MACADDR,
    dst_mac         MACADDR,
    src_ip          INET,
    dst_ip          INET,
    src_port        INTEGER,
    dst_port        INTEGER,

    -- ARP attack specific
    original_mac    MACADDR,                   -- Legitimate MAC being spoofed
    spoofed_mac     MACADDR,                   -- Attacker's MAC

    -- DNS attack specific
    dns_query       VARCHAR(255),              -- Queried domain
    dns_answer      INET,                      -- Returned IP
    expected_answer INET,                      -- Expected IP

    -- Context
    interface       VARCHAR(50),
    vlan_id         INTEGER,
    metadata        JSONB,

    -- Workflow
    acknowledged    BOOLEAN         DEFAULT FALSE,
    false_positive  BOOLEAN         DEFAULT FALSE,
    notes           TEXT,

    created_at      TIMESTAMPTZ     DEFAULT NOW()
);

-- Tracks legitimate ARP bindings for anomaly detection
CREATE TABLE IF NOT EXISTS mitm_arp_cache (
    id              BIGSERIAL       PRIMARY KEY,
    ip_address      INET            NOT NULL,
    mac_address     MACADDR         NOT NULL,
    interface       VARCHAR(50),
    vlan_id         INTEGER,

    first_seen      TIMESTAMPTZ     DEFAULT NOW(),
    last_seen       TIMESTAMPTZ     DEFAULT NOW(),
    seen_count      BIGINT          DEFAULT 1,

    -- Trust classification
    is_gateway      BOOLEAN         DEFAULT FALSE,
    is_static       BOOLEAN         DEFAULT FALSE,  -- Manually trusted
    trust_score     SMALLINT        DEFAULT 50,     -- 0-100

    UNIQUE(ip_address, interface)
);

-- Performance indexes — mitm_events
CREATE INDEX IF NOT EXISTS idx_mitm_timestamp   ON mitm_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_mitm_attack_type ON mitm_events (attack_type);
CREATE INDEX IF NOT EXISTS idx_mitm_severity    ON mitm_events (severity);
CREATE INDEX IF NOT EXISTS idx_mitm_src_ip      ON mitm_events (src_ip);
CREATE INDEX IF NOT EXISTS idx_mitm_src_mac     ON mitm_events (src_mac);
CREATE INDEX IF NOT EXISTS idx_mitm_unacked     ON mitm_events (acknowledged) WHERE acknowledged = FALSE;
-- Optimized composite index — mitm_events
CREATE INDEX IF NOT EXISTS idx_mitm_unacked_sev ON mitm_events (severity, timestamp DESC)
    WHERE acknowledged = FALSE;

-- Performance indexes — mitm_arp_cache
CREATE INDEX IF NOT EXISTS idx_arp_cache_ip     ON mitm_arp_cache (ip_address);
CREATE INDEX IF NOT EXISTS idx_arp_cache_mac    ON mitm_arp_cache (mac_address);
CREATE INDEX IF NOT EXISTS idx_arp_cache_last   ON mitm_arp_cache (last_seen DESC);

-- =============================================================================
-- ICS/OT Event Detection Tables (MITRE Caldera / ATT&CK for ICS)
-- =============================================================================
-- Stores ICS protocol events with MITRE ATT&CK for ICS mapping
-- Supports: Modbus, DNP3, S7comm, EtherNet/IP, BACnet, OPC UA, IEC 104

CREATE TABLE IF NOT EXISTS ics_events (
    id              BIGSERIAL       PRIMARY KEY,
    event_id        VARCHAR(64)     UNIQUE NOT NULL,
    timestamp       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    -- Protocol identification
    protocol        VARCHAR(32)     NOT NULL,  -- modbus, dnp3, s7comm, enip, bacnet, opcua, iec104
    function_code   INTEGER,                   -- Protocol-specific function code
    function_name   VARCHAR(64),               -- Human-readable function name

    -- Network identifiers
    src_ip          INET,
    src_port        INTEGER,
    dst_ip          INET,
    dst_port        INTEGER,

    -- ICS-specific fields
    unit_id         INTEGER,                   -- Modbus unit/slave ID
    device_address  VARCHAR(64),               -- DNP3/BACnet device address
    register_start  INTEGER,                   -- Starting register/address
    register_count  INTEGER,                   -- Number of registers/points
    data_value      TEXT,                      -- Written/read values (JSON array)

    -- Classification
    is_read         BOOLEAN         DEFAULT FALSE,
    is_write        BOOLEAN         DEFAULT FALSE,
    is_control      BOOLEAN         DEFAULT FALSE,
    is_discovery    BOOLEAN         DEFAULT FALSE,
    is_anomaly      BOOLEAN         DEFAULT FALSE,

    -- MITRE ATT&CK for ICS mapping
    mitre_tactic    VARCHAR(64),               -- e.g., collection, impact, discovery
    mitre_technique VARCHAR(16),               -- e.g., T0801, T0814, T0821
    mitre_subtechnique VARCHAR(16),
    attack_type     VARCHAR(64),               -- From attack_classifier: ICS_ATTACK
    rule_name       VARCHAR(128),              -- Matched rule name

    -- Caldera-specific
    caldera_ability VARCHAR(64),               -- Matched Caldera ability ID
    caldera_tactic  VARCHAR(64),

    -- Source tracking
    source          VARCHAR(32),               -- honeypot, sensor, etc.
    severity        VARCHAR(10)     DEFAULT 'LOW',  -- LOW, MEDIUM, HIGH, CRITICAL
    confidence      SMALLINT        DEFAULT 50,

    -- Workflow
    acknowledged    BOOLEAN         DEFAULT FALSE,
    false_positive  BOOLEAN         DEFAULT FALSE,
    notes           TEXT,

    metadata        JSONB,
    created_at      TIMESTAMPTZ     DEFAULT NOW()
);

-- ICS communication baselines for anomaly detection
CREATE TABLE IF NOT EXISTS ics_baselines (
    id              BIGSERIAL       PRIMARY KEY,
    protocol        VARCHAR(32)     NOT NULL,
    src_ip          INET            NOT NULL,
    dst_ip          INET            NOT NULL,
    dst_port        INTEGER,

    -- Allowed operations
    allowed_functions   INTEGER[],             -- Array of allowed function codes
    typical_rate        FLOAT,                 -- Typical requests per minute

    -- Classification
    is_hmi          BOOLEAN         DEFAULT FALSE,
    is_engineering  BOOLEAN         DEFAULT FALSE,
    is_trusted      BOOLEAN         DEFAULT FALSE,

    -- Statistics
    first_seen      TIMESTAMPTZ     DEFAULT NOW(),
    last_seen       TIMESTAMPTZ     DEFAULT NOW(),
    request_count   BIGINT          DEFAULT 1,
    anomaly_count   INTEGER         DEFAULT 0,

    UNIQUE(protocol, src_ip, dst_ip, dst_port)
);

-- Performance indexes — ics_events
CREATE INDEX IF NOT EXISTS idx_ics_timestamp    ON ics_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ics_protocol     ON ics_events (protocol);
CREATE INDEX IF NOT EXISTS idx_ics_src_ip       ON ics_events (src_ip);
CREATE INDEX IF NOT EXISTS idx_ics_dst_ip       ON ics_events (dst_ip);
CREATE INDEX IF NOT EXISTS idx_ics_mitre        ON ics_events (mitre_technique);
CREATE INDEX IF NOT EXISTS idx_ics_attack_type  ON ics_events (attack_type);
CREATE INDEX IF NOT EXISTS idx_ics_is_write     ON ics_events (is_write) WHERE is_write = TRUE;
CREATE INDEX IF NOT EXISTS idx_ics_is_control   ON ics_events (is_control) WHERE is_control = TRUE;
CREATE INDEX IF NOT EXISTS idx_ics_severity     ON ics_events (severity);
CREATE INDEX IF NOT EXISTS idx_ics_unacked      ON ics_events (acknowledged) WHERE acknowledged = FALSE;
-- Optimized composite indexes — ics_events
CREATE INDEX IF NOT EXISTS idx_ics_proto_mitre  ON ics_events (protocol, mitre_technique, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ics_critical     ON ics_events (timestamp DESC)
    WHERE is_write = TRUE OR is_control = TRUE;

-- Performance indexes — ics_baselines
CREATE INDEX IF NOT EXISTS idx_ics_bl_protocol  ON ics_baselines (protocol);
CREATE INDEX IF NOT EXISTS idx_ics_bl_src_dst   ON ics_baselines (src_ip, dst_ip);
CREATE INDEX IF NOT EXISTS idx_ics_bl_trusted   ON ics_baselines (is_trusted);

-- =============================================================================
-- PCAP Lifecycle Management Tables (Idea 23)
-- =============================================================================
-- Compressed PCAP archive index with AI-driven retention

CREATE TABLE IF NOT EXISTS pcap_index (
    id              BIGSERIAL       PRIMARY KEY,
    event_id        VARCHAR(64)     NOT NULL UNIQUE,
    filepath        TEXT            NOT NULL,
    original_size   INTEGER         NOT NULL,
    compressed_size INTEGER,
    compression     VARCHAR(8)      DEFAULT 'zstd',
    verdict         VARCHAR(16)     NOT NULL,
    retention_rule  VARCHAR(64),
    retention_days  INTEGER         DEFAULT 30,
    protocol        VARCHAR(32),
    src_ip          INET,
    dst_port        INTEGER,
    attack_types    TEXT,
    ai_class        VARCHAR(16),
    threat_score    INTEGER,
    captured_at     TIMESTAMPTZ,
    archived_at     TIMESTAMPTZ     DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ     DEFAULT NOW()
);

-- PCAP lifecycle run metrics
CREATE TABLE IF NOT EXISTS pcap_stats (
    id              SERIAL          PRIMARY KEY,
    run_at          TIMESTAMPTZ     DEFAULT NOW(),
    total_scanned   INTEGER,
    kept            INTEGER,
    conditional     INTEGER,
    purged          INTEGER,
    compressed      INTEGER,
    skipped         INTEGER,
    already_indexed INTEGER         DEFAULT 0,
    raw_bytes       BIGINT,
    compressed_bytes BIGINT,
    freed_bytes     BIGINT,
    scan_ms         INTEGER,
    query_ms        INTEGER,
    compress_ms     INTEGER,
    purge_ms        INTEGER,
    total_ms        INTEGER,
    archive_files   INTEGER,
    archive_bytes   BIGINT
);

-- Performance indexes — pcap_index
CREATE INDEX IF NOT EXISTS idx_pcap_event    ON pcap_index (event_id);
CREATE INDEX IF NOT EXISTS idx_pcap_verdict  ON pcap_index (verdict);
CREATE INDEX IF NOT EXISTS idx_pcap_ai       ON pcap_index (ai_class);
CREATE INDEX IF NOT EXISTS idx_pcap_protocol ON pcap_index (protocol);
CREATE INDEX IF NOT EXISTS idx_pcap_src      ON pcap_index (src_ip);
CREATE INDEX IF NOT EXISTS idx_pcap_expires  ON pcap_index (expires_at)
    WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pcap_captured ON pcap_index (captured_at DESC);

-- =============================================================================
-- AI Custom Rules (approved AI-suggested rules)
-- =============================================================================
-- Rules suggested by the AI analyzer and approved by an analyst.
-- Loaded at runtime by attack_classifier.py alongside built-in rules.

CREATE TABLE IF NOT EXISTS ai_custom_rules (
    id              SERIAL          PRIMARY KEY,
    rule_name       VARCHAR(128)    NOT NULL UNIQUE,
    attack_type     VARCHAR(64)     NOT NULL,
    regex_pattern   TEXT            NOT NULL,
    severity        VARCHAR(16)     DEFAULT 'HIGH',
    mitre_technique VARCHAR(128),
    description     TEXT,
    enabled         BOOLEAN         DEFAULT TRUE,

    -- Origin tracking
    source_event_id VARCHAR(64),
    ai_reasoning    TEXT,
    ai_novelty      INTEGER,
    ai_triage_class VARCHAR(16),

    -- Audit
    approved_by     VARCHAR(64)     DEFAULT 'analyst',
    approved_at     TIMESTAMPTZ     DEFAULT NOW(),
    disabled_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ     DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_custom_rules_type    ON ai_custom_rules (attack_type);
CREATE INDEX IF NOT EXISTS idx_custom_rules_enabled ON ai_custom_rules (enabled) WHERE enabled = TRUE;

-- =============================================================================
-- AI Analysis Table (ai_analyzer.py triage + deep analysis)
-- =============================================================================
-- Stores Ollama local triage and optional deep analysis results per event.

CREATE TABLE IF NOT EXISTS ai_analysis (
    event_id            VARCHAR(64)     PRIMARY KEY,
    timestamp           TIMESTAMPTZ     DEFAULT NOW(),

    -- Triage (Ollama)
    triage_class        VARCHAR(16),                -- NOISE, KNOWN, SUSPICIOUS, CRITICAL
    triage_confidence   INTEGER,                    -- 0-100
    triage_reasoning    TEXT,
    novelty_score       INTEGER,                    -- 0-10
    known_cve           VARCHAR(64),
    zero_day_score      INTEGER,                    -- 0-100
    iocs                JSONB,

    -- Triage performance
    triage_model        VARCHAR(64),
    triage_duration_ms  INTEGER,
    triage_raw          TEXT,                    -- Raw triage response from AI model
    triage_iocs         TEXT,                    -- IOCs extracted during triage

    -- Deep analysis (Ollama)
    deep_model          VARCHAR(64),
    deep_analysis       JSONB,

    -- AI-suggested rule
    suggested_rule_name     VARCHAR(128),
    suggested_rule_regex    TEXT,
    suggested_mitre         VARCHAR(128),

    -- Review status
    analyst_reviewed    BOOLEAN         DEFAULT FALSE,
    reviewed_by         VARCHAR(64),
    reviewed_at         TIMESTAMPTZ,

    -- Claude Sonnet deep analysis (structured fields)
    claude_verdict          VARCHAR(16),        -- CRITICAL/HIGH/MEDIUM/LOW/INFO
    claude_confidence       INTEGER,            -- 0-100
    claude_attack_type      VARCHAR(128),       -- e.g. "SQL Injection"
    claude_technique        VARCHAR(32),        -- MITRE T-code
    claude_tactic           VARCHAR(64),        -- MITRE tactic name
    claude_cve              VARCHAR(32),        -- CVE identified
    claude_zero_day_prob    INTEGER,            -- 0-100
    claude_threat_actor     VARCHAR(128),       -- APT attribution
    claude_kill_chain       VARCHAR(64),        -- kill chain phase
    claude_summary          TEXT,               -- executive summary
    claude_iocs             JSONB,              -- indicators of compromise
    claude_recommendations  JSONB,              -- defensive actions
    claude_related_cves     JSONB,              -- related CVEs
    claude_input_tokens     INTEGER,
    claude_output_tokens    INTEGER,
    claude_cost_usd         FLOAT,
    claude_elapsed_ms       INTEGER,
    claude_analyzed_at      TIMESTAMPTZ
);

-- Migration: add Claude columns to existing ai_analysis table
-- Uses IF NOT EXISTS (PostgreSQL 9.6+) — safe to run repeatedly
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_verdict VARCHAR(16);
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_confidence INTEGER;
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_attack_type VARCHAR(128);
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_technique VARCHAR(32);
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_tactic VARCHAR(64);
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_cve VARCHAR(32);
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_zero_day_prob INTEGER;
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_threat_actor VARCHAR(128);
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_kill_chain VARCHAR(64);
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_summary TEXT;
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_iocs JSONB;
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_recommendations JSONB;
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_related_cves JSONB;
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_input_tokens INTEGER;
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_output_tokens INTEGER;
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_cost_usd FLOAT;
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_elapsed_ms INTEGER;
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS claude_analyzed_at TIMESTAMPTZ;

-- Migration: widen VARCHAR columns that are too short
ALTER TABLE ai_analysis ALTER COLUMN suggested_mitre TYPE VARCHAR(128);
ALTER TABLE ai_custom_rules ALTER COLUMN mitre_technique TYPE VARCHAR(128);
ALTER TABLE ai_analysis ALTER COLUMN claude_technique TYPE VARCHAR(128);
ALTER TABLE ai_analysis ALTER COLUMN claude_attack_type TYPE VARCHAR(256);
ALTER TABLE ai_analysis ALTER COLUMN claude_threat_actor TYPE VARCHAR(256);
ALTER TABLE ai_analysis ALTER COLUMN claude_kill_chain TYPE VARCHAR(128);
ALTER TABLE ai_analysis ALTER COLUMN claude_tactic TYPE VARCHAR(128);
ALTER TABLE attacker_profiles ALTER COLUMN claude_technique TYPE VARCHAR(128);
ALTER TABLE attacker_profiles ALTER COLUMN claude_threat_actor TYPE VARCHAR(256);

CREATE INDEX IF NOT EXISTS idx_ai_class     ON ai_analysis (triage_class);
CREATE INDEX IF NOT EXISTS idx_ai_novelty   ON ai_analysis (novelty_score DESC);
CREATE INDEX IF NOT EXISTS idx_ai_zday      ON ai_analysis (zero_day_score DESC) WHERE zero_day_score IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ai_time      ON ai_analysis (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ai_cve       ON ai_analysis (known_cve) WHERE known_cve IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ai_pending   ON ai_analysis (analyst_reviewed, triage_class)
    WHERE analyst_reviewed = FALSE AND triage_class IN ('SUSPICIOUS', 'CRITICAL');
CREATE INDEX IF NOT EXISTS idx_ai_claude_verdict ON ai_analysis (claude_verdict) WHERE claude_verdict IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ai_claude_cve     ON ai_analysis (claude_cve) WHERE claude_cve IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ai_claude_actor   ON ai_analysis (claude_threat_actor) WHERE claude_threat_actor IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ai_claude_time    ON ai_analysis (claude_analyzed_at DESC) WHERE claude_analyzed_at IS NOT NULL;

-- =============================================================================
-- Attacker Profiles (attacker_profiler.py — Idea 22)
-- =============================================================================
-- OSINT-enriched attacker profiles with AI threat assessment.

CREATE TABLE IF NOT EXISTS attacker_profiles (
    ip                  INET            PRIMARY KEY,
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    total_events        INTEGER         DEFAULT 0,
    total_attacks       INTEGER         DEFAULT 0,
    attack_types        TEXT[],

    -- OSINT data
    abuse_score         INTEGER,                    -- AbuseIPDB 0-100
    is_noise            BOOLEAN         DEFAULT FALSE,
    is_vpn              BOOLEAN         DEFAULT FALSE,
    asn                 INTEGER,
    as_org              VARCHAR(256),
    country             VARCHAR(64),
    city                VARCHAR(128),
    hostname            VARCHAR(256),
    open_ports          INTEGER[],
    os_guess            VARCHAR(64),

    -- AI assessment
    ai_summary          TEXT,
    ai_intent           VARCHAR(32),                -- RECON, EXPLOIT, BRUTE_FORCE, UNKNOWN
    ai_threat_level     VARCHAR(16),                -- CRITICAL, HIGH, MEDIUM, LOW
    ai_updated_at       TIMESTAMPTZ,

    -- MITRE mapping + APT attribution
    mitre_techniques    TEXT[],
    internal_tags       TEXT[],
    apt_candidates      JSONB,

    -- Profile version tracking
    profile_version     INTEGER         DEFAULT 1,
    updated_at          TIMESTAMPTZ     DEFAULT NOW(),

    -- Claude Sonnet analysis (latest for this IP)
    claude_verdict          VARCHAR(16),
    claude_summary          TEXT,
    claude_technique        VARCHAR(32),
    claude_cve              VARCHAR(32),
    claude_threat_actor     VARCHAR(128),
    claude_analyzed_at      TIMESTAMPTZ,

    -- Hunt lifecycle
    hunt_status             VARCHAR(16)     DEFAULT 'ACTIVE',   -- ACTIVE or FINISHED
    finished_at             TIMESTAMPTZ,
    finish_notes            TEXT
);

-- Migration: add Claude columns to existing attacker_profiles table
ALTER TABLE attacker_profiles ADD COLUMN IF NOT EXISTS claude_verdict VARCHAR(16);
ALTER TABLE attacker_profiles ADD COLUMN IF NOT EXISTS claude_summary TEXT;
ALTER TABLE attacker_profiles ADD COLUMN IF NOT EXISTS claude_technique VARCHAR(32);
ALTER TABLE attacker_profiles ADD COLUMN IF NOT EXISTS claude_cve VARCHAR(32);
ALTER TABLE attacker_profiles ADD COLUMN IF NOT EXISTS claude_threat_actor VARCHAR(128);
ALTER TABLE attacker_profiles ADD COLUMN IF NOT EXISTS claude_analyzed_at TIMESTAMPTZ;

-- Migration: add hunt lifecycle columns
ALTER TABLE attacker_profiles ADD COLUMN IF NOT EXISTS hunt_status VARCHAR(16) DEFAULT 'ACTIVE';
ALTER TABLE attacker_profiles ADD COLUMN IF NOT EXISTS finished_at TIMESTAMPTZ;
ALTER TABLE attacker_profiles ADD COLUMN IF NOT EXISTS finish_notes TEXT;

CREATE INDEX IF NOT EXISTS idx_ap_threat    ON attacker_profiles (ai_threat_level);
CREATE INDEX IF NOT EXISTS idx_ap_abuse     ON attacker_profiles (abuse_score DESC) WHERE abuse_score IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ap_country   ON attacker_profiles (country);
CREATE INDEX IF NOT EXISTS idx_ap_updated   ON attacker_profiles (updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_ap_last_seen ON attacker_profiles (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_ap_tags      ON attacker_profiles USING GIN (internal_tags);

-- =============================================================================
-- Claude Analysis Log (claude_analyzer.py — External AI)
-- =============================================================================
-- Persistent log of every Claude Sonnet analysis with full context.
-- Links event + IP + verdict + cost for auditing and intelligence.

CREATE TABLE IF NOT EXISTS claude_analysis_log (
    id                  SERIAL          PRIMARY KEY,
    event_id            VARCHAR(64)     NOT NULL,
    src_ip              INET,
    dst_port            INTEGER,
    protocol            VARCHAR(32),
    attack_types        TEXT,

    -- Claude result
    verdict             VARCHAR(16),                -- CRITICAL/HIGH/MEDIUM/LOW/INFO
    confidence          INTEGER,                    -- 0-100
    attack_type         VARCHAR(128),
    technique           VARCHAR(32),                -- MITRE T-code
    tactic              VARCHAR(64),                -- MITRE tactic
    cve                 VARCHAR(32),
    zero_day_prob       INTEGER,                    -- 0-100
    threat_actor        VARCHAR(128),
    kill_chain          VARCHAR(64),
    summary             TEXT,
    full_result         JSONB,

    -- Cost tracking
    model               VARCHAR(64),
    input_tokens        INTEGER,
    output_tokens       INTEGER,
    elapsed_ms          INTEGER,
    estimated_cost_usd  FLOAT,

    -- Hunting integration
    auto_hunted         BOOLEAN         DEFAULT FALSE,
    hunt_threat_level   VARCHAR(16),

    created_at          TIMESTAMPTZ     DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cal_event    ON claude_analysis_log (event_id);
CREATE INDEX IF NOT EXISTS idx_cal_ip       ON claude_analysis_log (src_ip);
CREATE INDEX IF NOT EXISTS idx_cal_verdict  ON claude_analysis_log (verdict);
CREATE INDEX IF NOT EXISTS idx_cal_cve      ON claude_analysis_log (cve) WHERE cve IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cal_time     ON claude_analysis_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cal_actor    ON claude_analysis_log (threat_actor) WHERE threat_actor IS NOT NULL;

-- =============================================================================
-- Attacker Fingerprints (fingerprint_extractor.py — Idea 28)
-- =============================================================================
-- Per-IP client-side fingerprints extracted from payloads.

CREATE TABLE IF NOT EXISTS attacker_fingerprints (
    id                  SERIAL      PRIMARY KEY,
    ip                  INET        NOT NULL,
    fingerprint_type    VARCHAR(32) NOT NULL,
    fingerprint_value   TEXT        NOT NULL,
    fingerprint_hash    VARCHAR(64),
    detail              JSONB,
    event_count         INTEGER     DEFAULT 1,
    first_seen          TIMESTAMPTZ DEFAULT NOW(),
    last_seen           TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE (ip, fingerprint_type, fingerprint_hash)
);

CREATE INDEX IF NOT EXISTS idx_af_ip   ON attacker_fingerprints (ip);
CREATE INDEX IF NOT EXISTS idx_af_type ON attacker_fingerprints (fingerprint_type);
CREATE INDEX IF NOT EXISTS idx_af_hash ON attacker_fingerprints (fingerprint_hash);
CREATE INDEX IF NOT EXISTS idx_af_val  ON attacker_fingerprints (fingerprint_value)
    WHERE fingerprint_type IN ('http_lib', 'ssh_client', 'ssh_lib');

-- =============================================================================
-- Fingerprint Clusters (correlation_engine.py — Idea 28)
-- =============================================================================
-- Detected IP groups sharing rare fingerprints.

CREATE TABLE IF NOT EXISTS fingerprint_clusters (
    id                  SERIAL      PRIMARY KEY,
    cluster_tag         VARCHAR(64) NOT NULL UNIQUE,
    fingerprint_type    VARCHAR(64) NOT NULL,
    fingerprint_hash    VARCHAR(64) NOT NULL,
    fingerprint_value   TEXT,
    ip_count            INTEGER     DEFAULT 0,
    confidence          FLOAT       DEFAULT 0,
    first_seen          TIMESTAMPTZ DEFAULT NOW(),
    last_seen           TIMESTAMPTZ DEFAULT NOW(),
    ips                 INET[],
    notes               TEXT,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fc_tag  ON fingerprint_clusters (cluster_tag);
CREATE INDEX IF NOT EXISTS idx_fc_hash ON fingerprint_clusters (fingerprint_hash);
CREATE INDEX IF NOT EXISTS idx_fc_conf ON fingerprint_clusters (confidence DESC);

-- =========================================================================
-- Attack Knowledge Base (Idea 27)
-- =========================================================================

CREATE TABLE IF NOT EXISTS attack_definitions (
    attack_type         VARCHAR(64) PRIMARY KEY,
    display_name        VARCHAR(256) NOT NULL,
    short_description   TEXT NOT NULL,
    category            VARCHAR(64),
    full_description    TEXT,
    how_it_works        TEXT,
    impact              TEXT,
    prerequisites       TEXT,
    detection_methods   TEXT,
    prevention          TEXT,
    remediation         TEXT,
    default_severity    VARCHAR(32),
    owasp_category      VARCHAR(128),
    owasp_id            VARCHAR(64),
    cwe_id              VARCHAR(64),
    cwe_ids             JSONB,
    capec_ids           JSONB,
    mitre_techniques    JSONB,
    mitre_tactics       JSONB,
    mitre_data_sources  JSONB,
    ms_bulletin_ids     JSONB,
    notable_cves        JSONB,
    cisa_kev_count      INTEGER DEFAULT 0,
    threat_actors       JSONB,
    malware_families    JSONB,
    campaigns           JSONB,
    target_industries   JSONB,
    example_payloads    JSONB,
    observed_count      INTEGER DEFAULT 0,
    observed_unique_ips INTEGER DEFAULT 0,
    first_observed      TIMESTAMPTZ,
    last_observed       TIMESTAMPTZ,
    trend_7d            FLOAT,
    trend_30d           FLOAT,
    references_         JSONB,
    tools_used          JSONB,
    generated_by        VARCHAR(32),
    generated_model     VARCHAR(64),
    analyst_reviewed    BOOLEAN DEFAULT FALSE,
    analyst_notes       TEXT,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

-- Migration: widen short code columns. attack_kb_builder LLM output can overflow the
-- original VARCHAR(16) (e.g. owasp_id "A03:2021-Injection", multi-value cwe_id) causing
-- StringDataRightTruncation. Widening to the same/larger type is a safe repeatable no-op.
ALTER TABLE attack_definitions ALTER COLUMN default_severity TYPE VARCHAR(32);
ALTER TABLE attack_definitions ALTER COLUMN owasp_id         TYPE VARCHAR(64);
ALTER TABLE attack_definitions ALTER COLUMN cwe_id           TYPE VARCHAR(64);

CREATE TABLE IF NOT EXISTS attack_rule_definitions (
    rule_name           VARCHAR(128) PRIMARY KEY,
    attack_type         VARCHAR(64) REFERENCES attack_definitions(attack_type),
    display_name        VARCHAR(256),
    description         TEXT,
    severity            VARCHAR(16),
    regex_explanation   TEXT,
    true_positive_note  TEXT,
    false_positive_note TEXT,
    tuning_guidance     TEXT,
    target_cves         JSONB,
    target_products     JSONB,
    hit_count           INTEGER DEFAULT 0,
    unique_source_ips   INTEGER DEFAULT 0,
    last_hit            TIMESTAMPTZ,
    example_payloads    JSONB,
    top_source_countries JSONB,
    is_custom           BOOLEAN DEFAULT FALSE,
    generated_by        VARCHAR(32),
    analyst_reviewed    BOOLEAN DEFAULT FALSE,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ard_type     ON attack_rule_definitions(attack_type);
CREATE INDEX IF NOT EXISTS idx_ard_severity ON attack_rule_definitions(severity);

CREATE TABLE IF NOT EXISTS attack_cve_links (
    id                  SERIAL PRIMARY KEY,
    attack_type         VARCHAR(64) REFERENCES attack_definitions(attack_type),
    cve_id              VARCHAR(20) NOT NULL,
    cve_name            VARCHAR(256),
    vendor              VARCHAR(128),
    product             VARCHAR(256),
    cvss_score          FLOAT,
    cvss_vector         VARCHAR(128),
    cwe_id              VARCHAR(20),
    published_date      DATE,
    description         TEXT,
    ms_bulletin_id      VARCHAR(16),
    ms_kb_id            VARCHAR(16),
    in_cisa_kev         BOOLEAN DEFAULT FALSE,
    kev_date_added      DATE,
    kev_ransomware      BOOLEAN DEFAULT FALSE,
    exploit_available   BOOLEAN DEFAULT FALSE,
    exploit_maturity    VARCHAR(32),
    link_type           VARCHAR(32),
    notes               TEXT,
    UNIQUE (attack_type, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_acl_cve  ON attack_cve_links(cve_id);
CREATE INDEX IF NOT EXISTS idx_acl_type ON attack_cve_links(attack_type);
CREATE INDEX IF NOT EXISTS idx_acl_ms   ON attack_cve_links(ms_bulletin_id);
CREATE INDEX IF NOT EXISTS idx_acl_kev  ON attack_cve_links(in_cisa_kev);

-- =============================================================================
-- CVE Intelligence (Idea 32 — CIRCL Vulnerability-Lookup)
-- =============================================================================
-- Tracks CVEs observed on the sensor with CIRCL enrichment data

CREATE TABLE IF NOT EXISTS cve_intelligence (
    id                    SERIAL PRIMARY KEY,
    cve_id                VARCHAR(32) UNIQUE NOT NULL,
    title                 TEXT,
    cvss_score            NUMERIC(3,1),
    cvss_severity         VARCHAR(16),
    cvss_vector           TEXT,
    cwe                   TEXT[],
    vendor                TEXT,
    product               TEXT,
    is_kev                BOOLEAN DEFAULT FALSE,
    kev_date_added        DATE,
    affected_json         JSONB,
    references_json       JSONB,
    first_seen_on_sensor  TIMESTAMPTZ,
    times_seen            INTEGER DEFAULT 1,
    last_seen_on_sensor   TIMESTAMPTZ,
    fetched_at            TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cve_intel_id   ON cve_intelligence (cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_intel_kev  ON cve_intelligence (is_kev) WHERE is_kev = TRUE;
CREATE INDEX IF NOT EXISTS idx_cve_intel_cvss ON cve_intelligence (cvss_score DESC);

-- Migration: add cve_details column to ai_analysis
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS cve_details JSONB;
