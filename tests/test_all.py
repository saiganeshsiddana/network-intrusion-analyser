"""
Unit Tests for Network Intrusion Log Analyser
"""

import pytest
import os
from datetime import datetime
from app.parser.log_parser import LogParser, ParsedLog
from app.database.db import DatabaseManager
from app.analysis.analytics import NetworkAnalytics
from app.detection.rules import ThreatDetectionEngine
from app.detection.incidents import IncidentCorrelator
from app.ml.features import FeatureEngineer
from app.ml.train import ThreatClassifierTrainer
from app.ml.predict import ThreatPredictor
import pandas as pd


# Parser Tests
def test_log_parser_valid():
    parser = LogParser()
    line = "2024-10-01 09:00:01 203.0.113.5:45123 -> 10.0.1.15:443 TCP ALLOW"
    parsed = parser.parse_line(line)

    assert parsed.is_valid is True
    assert parsed.source_ip == "203.0.113.5"
    assert parsed.source_port == 45123
    assert parsed.destination_ip == "10.0.1.15"
    assert parsed.destination_port == 443
    assert parsed.protocol == "TCP"
    assert parsed.action == "ALLOW"


def test_log_parser_malformed():
    parser = LogParser()
    line = "invalid log line format"
    parsed = parser.parse_line(line)

    assert parsed.is_valid is False
    assert parsed.error_message == "Malformed log entry"


def test_log_parser_invalid_ip():
    parser = LogParser()
    line = "2024-10-01 09:00:01 999.999.999.999:45123 -> 10.0.1.15:443 TCP ALLOW"
    parsed = parser.parse_line(line)

    assert parsed.is_valid is False


# Database Tests
def test_database_manager(tmp_path):
    db_file = tmp_path / "test.db"
    db = DatabaseManager(str(db_file))

    # Test initialization
    assert db.get_event_count() == 0

    # Test log insertion
    parsed = ParsedLog(
        timestamp=datetime.now(),
        source_ip="192.168.1.1",
        source_port=12345,
        destination_ip="10.0.0.1",
        destination_port=80,
        protocol="TCP",
        action="ALLOW",
        raw_log="test log",
        is_valid=True
    )

    inserted = db.insert_logs_batch([parsed])
    assert inserted == 1
    assert db.get_event_count() == 1


# Detection Engine Tests
def test_threat_detection():
    data = []
    # Create artificial port scan
    for port in range(20, 50):
        data.append({
            'timestamp': pd.to_datetime('2024-10-01 09:00:00'),
            'source_ip': '198.51.100.1',
            'source_port': 50000,
            'destination_ip': '10.0.0.1',
            'destination_port': port,
            'protocol': 'TCP',
            'action': 'DENY'
        })

    df = pd.DataFrame(data)
    detector = ThreatDetectionEngine(df)
    alerts = detector.detect_port_scanning(min_unique_ports=10)

    assert len(alerts) > 0
    assert alerts[0].alert_type == "Port Scanning"
    assert alerts[0].source_ip == "198.51.100.1"


# ML Pipeline Tests
def test_ml_pipeline():
    trainer = ThreatClassifierTrainer()
    X, y = trainer.generate_synthetic_training_data(n_samples=200)

    metrics = trainer.train(X, y)
    assert metrics['test_accuracy'] > 0.7  # Should get good accuracy on synthetic data
