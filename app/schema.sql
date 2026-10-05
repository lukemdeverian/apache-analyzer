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

CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp, id);
CREATE INDEX IF NOT EXISTS idx_events_source_time ON events(source_ip, timestamp, id);
CREATE INDEX IF NOT EXISTS idx_events_type_time ON events(log_type, timestamp, id);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(first_seen, id);
CREATE INDEX IF NOT EXISTS idx_alerts_source_time ON alerts(source_ip, first_seen, id);
CREATE INDEX IF NOT EXISTS idx_alerts_status_time ON alerts(status, last_seen, id);
CREATE INDEX IF NOT EXISTS idx_alerts_correlation ON alerts(rule_id, grouping_key, status, last_seen);
CREATE INDEX IF NOT EXISTS idx_alert_events_event ON alert_events(event_id);
