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

-- ML Predictions Table
-- Stores the latest per-source classification so ML findings survive a
-- Streamlit browser refresh and can be included in exported reports.
CREATE TABLE IF NOT EXISTS ml_predictions (
    source_ip TEXT PRIMARY KEY,
    ml_prediction INTEGER NOT NULL CHECK (ml_prediction IN (0, 1)),
    ml_threat_probability REAL NOT NULL,
    ml_confidence REAL NOT NULL,
    ml_label TEXT NOT NULL,
    total_connections INTEGER NOT NULL,
    denied_connections INTEGER NOT NULL,
    unique_dst_ports INTEGER NOT NULL,
    connections_per_minute REAL NOT NULL,
    deny_ratio REAL NOT NULL,
    port_scan_score REAL NOT NULL,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ml_prediction_label ON ml_predictions(ml_label);
CREATE INDEX IF NOT EXISTS idx_ml_prediction_probability ON ml_predictions(ml_threat_probability DESC);
