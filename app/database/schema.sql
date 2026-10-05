-- Network Events Table
CREATE TABLE IF NOT EXISTS network_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL,
    source_ip TEXT NOT NULL,
    source_port INTEGER NOT NULL,
    destination_ip TEXT NOT NULL,
    destination_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    action TEXT NOT NULL,
    raw_log TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_source_ip ON network_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_destination_ip ON network_events(destination_ip);
CREATE INDEX IF NOT EXISTS idx_destination_port ON network_events(destination_port);
CREATE INDEX IF NOT EXISTS idx_action ON network_events(action);
CREATE INDEX IF NOT EXISTS idx_timestamp ON network_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_protocol ON network_events(protocol);

-- Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT,
    destination_port INTEGER,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    event_count INTEGER DEFAULT 1,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    explanation TEXT,
    recommendation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alert_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alert_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alert_type ON alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alert_risk_score ON alerts(risk_score);

-- Incidents Table
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_type TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    status TEXT DEFAULT 'New',
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    event_count INTEGER DEFAULT 0,
    alert_count INTEGER DEFAULT 0,
    summary TEXT,
    recommendation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_incident_source_ip ON incidents(source_ip);
CREATE INDEX IF NOT EXISTS idx_incident_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incident_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incident_risk_score ON incidents(risk_score);
