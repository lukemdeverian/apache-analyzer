CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    log_type TEXT NOT NULL CHECK (log_type IN ('access', 'error')),
    log_format TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    raw_log TEXT NOT NULL,
    source_file TEXT,
    line_number INTEGER CHECK (line_number > 0),
    source_host TEXT,
    source_ip TEXT,
    source_port INTEGER CHECK (source_port BETWEEN 0 AND 65535),
    assumed_timezone TEXT,
    remote_logname TEXT,
    username TEXT,
    request TEXT,
    method TEXT,
    request_target TEXT,
    path TEXT,
    query_string TEXT,
    protocol TEXT,
    status_code INTEGER CHECK (status_code BETWEEN 100 AND 599),
    response_bytes INTEGER CHECK (response_bytes >= 0),
    referrer TEXT,
    user_agent TEXT,
    module TEXT,
    level TEXT,
    process_id INTEGER CHECK (process_id >= 0),
    thread_id TEXT,
    error_code TEXT,
    message TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    grouping_key TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL CHECK (last_seen >= first_seen),
    source_ip TEXT,
    status TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'investigating', 'resolved', 'false_positive')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE RESTRICT,
    PRIMARY KEY (alert_id, event_id)
);

CREATE TABLE IF NOT EXISTS alert_merges (
    former_id INTEGER PRIMARY KEY CHECK (former_id > 0),
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE RESTRICT,
    merged_at TEXT NOT NULL,
    CHECK (former_id > alert_id)
);

CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp, id);
CREATE INDEX IF NOT EXISTS idx_events_source_time ON events(source_ip, timestamp, id);
CREATE INDEX IF NOT EXISTS idx_events_type_time ON events(log_type, timestamp, id);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(first_seen, id);
CREATE INDEX IF NOT EXISTS idx_alerts_source_time ON alerts(source_ip, first_seen, id);
CREATE INDEX IF NOT EXISTS idx_alerts_status_time ON alerts(status, last_seen, id);
CREATE INDEX IF NOT EXISTS idx_alerts_correlation ON alerts(rule_id, grouping_key, status, last_seen);
CREATE INDEX IF NOT EXISTS idx_alert_events_event ON alert_events(event_id);
CREATE INDEX IF NOT EXISTS idx_alert_merges_target ON alert_merges(alert_id);

CREATE TABLE IF NOT EXISTS imports (
    id INTEGER PRIMARY KEY,
    source_file TEXT NOT NULL,
    log_type TEXT NOT NULL CHECK (log_type IN ('access', 'error')),
    assumed_timezone TEXT,
    max_line_bytes INTEGER CHECK (max_line_bytes > 0),
    legacy INTEGER NOT NULL DEFAULT 0 CHECK (legacy IN (0, 1)),
    recorded_at TEXT NOT NULL,
    content_sha256 TEXT,
    records_sha256 TEXT,
    lines_read INTEGER CHECK (lines_read >= 0),
    imported_events INTEGER NOT NULL DEFAULT 0 CHECK (imported_events >= 0),
    blank_lines INTEGER CHECK (blank_lines >= 0),
    malformed_lines INTEGER CHECK (malformed_lines >= 0),
    encoding_error_lines INTEGER CHECK (encoding_error_lines >= 0),
    oversized_lines INTEGER CHECK (oversized_lines >= 0),
    invalid_value_lines INTEGER CHECK (invalid_value_lines >= 0),
    duplicate_lines INTEGER NOT NULL DEFAULT 0 CHECK (duplicate_lines >= 0),
    UNIQUE (log_type, content_sha256)
);

CREATE TABLE IF NOT EXISTS import_lines (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE RESTRICT,
    import_id INTEGER NOT NULL REFERENCES imports(id) ON DELETE CASCADE,
    record_sha256 TEXT NOT NULL,
    duplicate_of_event_id INTEGER REFERENCES events(id) ON DELETE RESTRICT,
    CHECK (duplicate_of_event_id IS NULL OR duplicate_of_event_id < event_id)
);

CREATE INDEX IF NOT EXISTS idx_imports_records ON imports(log_type, records_sha256, id);
CREATE INDEX IF NOT EXISTS idx_import_lines_hash ON import_lines(import_id, record_sha256, event_id);
