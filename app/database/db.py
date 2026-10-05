"""
Database Management Module

Handles SQLite database creation, indexing, bulk insertion, and querying.
"""

import sqlite3
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import pandas as pd
from app.parser.log_parser import ParsedLog


class DatabaseManager:
    """Manages SQLite database operations for the intrusion analyser."""

    def __init__(self, db_path: str = "database/intrusion_analyser.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Get database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Initialize database schema from SQL file."""
        schema_path = Path(__file__).parent / "schema.sql"
        with open(schema_path, 'r') as f:
            schema_sql = f.read()

        with self.get_connection() as conn:
            conn.executescript(schema_sql)
            conn.commit()

    def insert_logs_batch(self, logs: List[ParsedLog]) -> int:
        """
        Insert batch of valid parsed logs efficiently.

        Returns number of inserted records.
        """
        valid_logs = [log for log in logs if log.is_valid]

        if not valid_logs:
            return 0

        insert_sql = """
        INSERT INTO network_events
        (timestamp, source_ip, source_port, destination_ip, destination_port, protocol, action, raw_log)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """

        data = [
            (
                log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                log.source_ip,
                log.source_port,
                log.destination_ip,
                log.destination_port,
                log.protocol,
                log.action,
                log.raw_log
            )
            for log in valid_logs
        ]

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany(insert_sql, data)
            conn.commit()
            return cursor.rowcount

    def clear_all_events(self):
        """Clear network events table."""
        with self.get_connection() as conn:
            conn.execute("DELETE FROM network_events")
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM incidents")
            conn.commit()

    def get_event_count(self) -> int:
        """Get total number of stored events."""
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM network_events")
            return cursor.fetchone()[0]

    def get_logs_as_dataframe(self, limit: Optional[int] = None) -> pd.DataFrame:
        """Fetch network events as a Pandas DataFrame for analysis."""
        query = "SELECT * FROM network_events ORDER BY timestamp DESC"
        if limit:
            query += f" LIMIT {limit}"

        with self.get_connection() as conn:
            df = pd.read_sql_query(query, conn)
            if not df.empty and 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            return df

    def query_logs(self,
                   source_ip: Optional[str] = None,
                   destination_ip: Optional[str] = None,
                   protocol: Optional[str] = None,
                   action: Optional[str] = None,
                   limit: int = 1000) -> pd.DataFrame:
        """Query logs with filters."""
        conditions = []
        params = []

        if source_ip:
            conditions.append("source_ip = ?")
            params.append(source_ip)
        if destination_ip:
            conditions.append("destination_ip = ?")
            params.append(destination_ip)
        if protocol:
            conditions.append("protocol = ?")
            params.append(protocol)
        if action:
            conditions.append("action = ?")
            params.append(action)

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""
        query = f"SELECT * FROM network_events{where_clause} ORDER BY timestamp DESC LIMIT {limit}"

        with self.get_connection() as conn:
            df = pd.read_sql_query(query, conn, params=params)
            if not df.empty and 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            return df

    def insert_alert(self, alert: Dict) -> int:
        """Insert detection alert into database."""
        insert_sql = """
        INSERT INTO alerts
        (alert_type, source_ip, destination_ip, destination_port, severity, risk_score,
         event_count, first_seen, last_seen, explanation, recommendation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(insert_sql, (
                alert['alert_type'],
                alert['source_ip'],
                alert.get('destination_ip'),
                alert.get('destination_port'),
                alert['severity'],
                alert['risk_score'],
                alert.get('event_count', 1),
                alert['first_seen'],
                alert['last_seen'],
                alert['explanation'],
                alert['recommendation']
            ))
            conn.commit()
            return cursor.lastrowid

    def get_alerts(self, limit: Optional[int] = None) -> pd.DataFrame:
        """Fetch alerts as DataFrame."""
        query = "SELECT * FROM alerts ORDER BY risk_score DESC, created_at DESC"
        if limit:
            query += f" LIMIT {limit}"

        with self.get_connection() as conn:
            return pd.read_sql_query(query, conn)

    def clear_alerts(self):
        """Clear all alerts."""
        with self.get_connection() as conn:
            conn.execute("DELETE FROM alerts")
            conn.commit()

    def insert_incident(self, incident: Dict) -> int:
        """Insert incident into database."""
        insert_sql = """
        INSERT INTO incidents
        (incident_type, source_ip, destination_ip, severity, risk_score, status,
         first_seen, last_seen, event_count, alert_count, summary, recommendation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(insert_sql, (
                incident['incident_type'],
                incident['source_ip'],
                incident.get('destination_ip'),
                incident['severity'],
                incident['risk_score'],
                incident.get('status', 'New'),
                incident['first_seen'],
                incident['last_seen'],
                incident.get('event_count', 0),
                incident.get('alert_count', 0),
                incident['summary'],
                incident['recommendation']
            ))
            conn.commit()
            return cursor.lastrowid

    def get_incidents(self, status: Optional[str] = None) -> pd.DataFrame:
        """Fetch incidents as DataFrame."""
        if status:
            query = f"SELECT * FROM incidents WHERE status = ? ORDER BY risk_score DESC, first_seen DESC"
            with self.get_connection() as conn:
                return pd.read_sql_query(query, conn, params=[status])
        else:
            query = "SELECT * FROM incidents ORDER BY risk_score DESC, first_seen DESC"
            with self.get_connection() as conn:
                return pd.read_sql_query(query, conn)

    def update_incident_status(self, incident_id: int, status: str):
        """Update incident status."""
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE incidents SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status, incident_id)
            )
            conn.commit()

    def clear_incidents(self):
        """Clear all incidents."""
        with self.get_connection() as conn:
            conn.execute("DELETE FROM incidents")
            conn.commit()
