-- Durable hand-off between sensor ingestion and the HoneyLens PCAP exporter.
CREATE TABLE IF NOT EXISTS pcap_export_outbox (
    event_id          TEXT PRIMARY KEY,
    spool_path        TEXT NOT NULL,
    severity          VARCHAR(16) NOT NULL,
    captured_at       TIMESTAMPTZ NOT NULL,
    source            TEXT NOT NULL,
    protocol          TEXT,
    src_ip            INET,
    src_port          INTEGER,
    dst_ip            INET,
    dst_port          INTEGER,
    metadata          JSONB NOT NULL DEFAULT '{}'::jsonb,
    eligible_at       TIMESTAMPTZ NOT NULL,
    state             VARCHAR(16) NOT NULL DEFAULT 'pending',
    attempts          INTEGER NOT NULL DEFAULT 0,
    next_attempt_at   TIMESTAMPTZ,
    last_error        TEXT,
    intake_case_id    TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at           TIMESTAMPTZ,
    CONSTRAINT pcap_export_state_check CHECK (
        state IN ('pending', 'uploading', 'retry', 'sent', 'excluded', 'dead_letter')
    )
);

CREATE INDEX IF NOT EXISTS idx_pcap_export_ready
    ON pcap_export_outbox (state, eligible_at, next_attempt_at);
