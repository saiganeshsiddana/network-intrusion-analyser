"""
Rule-Based Threat Detection Engine

Implements explainable detection rules for suspicious network behavior.
Each rule provides clear evidence and reasoning for detections.
"""

import pandas as pd
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass


@dataclass
class DetectionResult:
    """Result from a detection rule."""
    alert_type: str
    source_ip: str
    destination_ip: Optional[str]
    destination_port: Optional[int]
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score: int  # 0-100
    event_count: int
    first_seen: datetime
    last_seen: datetime
    explanation: str
    recommendation: str
    evidence: Dict


class ThreatDetectionEngine:
    """Rule-based threat detection engine."""

    def __init__(self, df: pd.DataFrame):
        """
        Initialize detection engine with network events DataFrame.

        Expected columns: timestamp, source_ip, destination_ip,
                         source_port, destination_port, protocol, action
        """
        self.df = df
        if not df.empty and 'timestamp' in df.columns:
            self.df['timestamp'] = pd.to_datetime(df['timestamp'])

        self.detections: List[DetectionResult] = []

    def detect_port_scanning(self,
                            min_unique_ports: int = 20,
                            time_window_minutes: int = 10) -> List[DetectionResult]:
        """
        Detect possible port scanning behavior.

        A source contacting many different destination ports in a short time
        may indicate port scanning activity.

        Args:
            min_unique_ports: Minimum unique ports to trigger detection
            time_window_minutes: Time window to analyze
        """
        results = []

        if self.df.empty:
            return results

        # Group by source IP and analyze port diversity
        for source_ip in self.df['source_ip'].unique():
            ip_df = self.df[self.df['source_ip'] == source_ip].copy()

            # Check within time windows
            ip_df_sorted = ip_df.sort_values('timestamp')

            if len(ip_df_sorted) < min_unique_ports:
                continue

            # Analyze in sliding windows
            for i in range(len(ip_df_sorted)):
                window_start = ip_df_sorted.iloc[i]['timestamp']
                window_end = window_start + timedelta(minutes=time_window_minutes)

                window_df = ip_df_sorted[
                    (ip_df_sorted['timestamp'] >= window_start) &
                    (ip_df_sorted['timestamp'] <= window_end)
                ]

                unique_ports = window_df['destination_port'].nunique()

                if unique_ports >= min_unique_ports:
                    # Possible port scan detected
                    denied_count = len(window_df[window_df['action'] == 'DENY'])
                    target_ips = window_df['destination_ip'].unique()

                    # Calculate risk score
                    risk_score = min(100, 40 + (unique_ports - min_unique_ports) * 2)
                    if denied_count / len(window_df) > 0.8:
                        risk_score = min(100, risk_score + 20)

                    severity = 'HIGH' if risk_score >= 70 else 'MEDIUM'

                    results.append(DetectionResult(
                        alert_type='Port Scanning',
                        source_ip=source_ip,
                        destination_ip=', '.join(target_ips[:3]) if len(target_ips) <= 3 else f"{target_ips[0]} and {len(target_ips)-1} others",
                        destination_port=None,
                        severity=severity,
                        risk_score=risk_score,
                        event_count=len(window_df),
                        first_seen=window_df['timestamp'].min(),
                        last_seen=window_df['timestamp'].max(),
                        explanation=f"Source {source_ip} contacted {unique_ports} unique destination ports within {time_window_minutes} minutes. This pattern is consistent with port scanning behavior where an attacker probes multiple ports to identify open services.",
                        recommendation=f"Investigate source IP {source_ip}. Review firewall rules and consider blocking if unauthorized. Check if any targeted services were compromised.",
                        evidence={
                            'unique_ports_contacted': int(unique_ports),
                            'time_window_minutes': time_window_minutes,
                            'total_attempts': len(window_df),
                            'denied_attempts': int(denied_count),
                            'target_count': len(target_ips)
                        }
                    ))
                    break  # Only report first window per source

        return results

    def detect_brute_force(self,
                          min_attempts: int = 50,
                          time_window_minutes: int = 5) -> List[DetectionResult]:
        """
        Detect repeated connection attempts (possible brute force).

        Multiple connection attempts from the same source to the same
        destination/port, especially if denied, may indicate brute force.

        Args:
            min_attempts: Minimum attempts to trigger detection
            time_window_minutes: Time window to analyze
        """
        results = []

        if self.df.empty:
            return results

        # Group by source, destination, and port
        grouped = self.df.groupby(['source_ip', 'destination_ip', 'destination_port'])

        for (source_ip, dest_ip, dest_port), group_df in grouped:
            if len(group_df) < min_attempts:
                continue

            group_sorted = group_df.sort_values('timestamp')

            # Check within time windows
            for i in range(len(group_sorted)):
                window_start = group_sorted.iloc[i]['timestamp']
                window_end = window_start + timedelta(minutes=time_window_minutes)

                window_df = group_sorted[
                    (group_sorted['timestamp'] >= window_start) &
                    (group_sorted['timestamp'] <= window_end)
                ]

                if len(window_df) >= min_attempts:
                    denied_count = len(window_df[window_df['action'] == 'DENY'])
                    deny_ratio = denied_count / len(window_df)

                    # Calculate risk score
                    risk_score = min(100, 50 + int((len(window_df) - min_attempts) * 0.5))
                    if deny_ratio > 0.9:
                        risk_score = min(100, risk_score + 20)

                    severity = 'CRITICAL' if risk_score >= 80 else 'HIGH'

                    # Identify service
                    service_name = self._identify_service(dest_port)

                    results.append(DetectionResult(
                        alert_type='Repeated Connection Attempts',
                        source_ip=source_ip,
                        destination_ip=dest_ip,
                        destination_port=int(dest_port),
                        severity=severity,
                        risk_score=risk_score,
                        event_count=len(window_df),
                        first_seen=window_df['timestamp'].min(),
                        last_seen=window_df['timestamp'].max(),
                        explanation=f"Source {source_ip} made {len(window_df)} connection attempts to {dest_ip}:{dest_port} ({service_name}) within {time_window_minutes} minutes, with {denied_count} attempts denied. This pattern resembles brute-force behavior where repeated login or connection attempts are made.",
                        recommendation=f"Investigate {source_ip} immediately. Review authentication logs for {dest_ip}. Consider temporary IP blocking and enable rate limiting on {service_name}.",
                        evidence={
                            'total_attempts': len(window_df),
                            'denied_attempts': int(denied_count),
                            'time_window_minutes': time_window_minutes,
                            'target_service': service_name,
                            'deny_ratio': round(deny_ratio, 2)
                        }
                    ))
                    break

        return results

    def detect_excessive_denies(self, min_denies: int = 100) -> List[DetectionResult]:
        """
        Detect sources with excessive denied connections.

        High number of denied connections may indicate unauthorized access attempts.

        Args:
            min_denies: Minimum denied connections to trigger detection
        """
        results = []

        if self.df.empty:
            return results

        denied_df = self.df[self.df['action'] == 'DENY']

        # Do not depend on a database-specific ``id`` column: the public
        # constructor accepts ordinary parsed-log DataFrames as well.
        deny_counts = denied_df.groupby('source_ip').agg(
            deny_count=('action', 'size'),
            unique_destinations=('destination_ip', 'nunique'),
            unique_ports=('destination_port', 'nunique'),
            first_seen=('timestamp', 'min'),
            last_seen=('timestamp', 'max')
        )

        suspicious = deny_counts[deny_counts['deny_count'] >= min_denies]

        for source_ip, row in suspicious.iterrows():
            risk_score = min(100, 30 + int((row['deny_count'] - min_denies) * 0.3))
            severity = 'HIGH' if risk_score >= 70 else 'MEDIUM'

            results.append(DetectionResult(
                alert_type='Excessive Denied Connections',
                source_ip=source_ip,
                destination_ip=None,
                destination_port=None,
                severity=severity,
                risk_score=risk_score,
                event_count=int(row['deny_count']),
                first_seen=row['first_seen'],
                last_seen=row['last_seen'],
                explanation=f"Source {source_ip} generated {int(row['deny_count'])} denied connection attempts across {int(row['unique_destinations'])} destinations and {int(row['unique_ports'])} ports. This high volume of denied traffic suggests unauthorized access attempts or misconfigured systems.",
                recommendation=f"Investigate source {source_ip}. Verify if this is a legitimate internal system or external attacker. Review firewall policies and consider blocking if malicious.",
                evidence={
                    'denied_connections': int(row['deny_count']),
                    'unique_destinations': int(row['unique_destinations']),
                    'unique_ports': int(row['unique_ports']),
                    'duration_minutes': int((row['last_seen'] - row['first_seen']).total_seconds() / 60)
                }
            ))

        return results

    def detect_high_frequency(self,
                             min_connections: int = 150,
                             time_window_minutes: int = 5) -> List[DetectionResult]:
        """
        Detect unusually high connection frequency.

        Very rapid connections from a single source may indicate:
        - DDoS attempts
        - Automated scanning
        - Data exfiltration
        - Compromised system

        Args:
            min_connections: Minimum connections in window
            time_window_minutes: Time window to analyze
        """
        results = []

        if self.df.empty:
            return results

        for source_ip in self.df['source_ip'].unique():
            ip_df = self.df[self.df['source_ip'] == source_ip].copy().sort_values('timestamp')

            if len(ip_df) < min_connections:
                continue

            for i in range(len(ip_df)):
                window_start = ip_df.iloc[i]['timestamp']
                window_end = window_start + timedelta(minutes=time_window_minutes)

                window_df = ip_df[
                    (ip_df['timestamp'] >= window_start) &
                    (ip_df['timestamp'] <= window_end)
                ]

                if len(window_df) >= min_connections:
                    denied_count = len(window_df[window_df['action'] == 'DENY'])
                    unique_destinations = window_df['destination_ip'].nunique()

                    risk_score = min(100, 40 + int((len(window_df) - min_connections) * 0.2))
                    severity = 'HIGH' if risk_score >= 70 else 'MEDIUM'

                    results.append(DetectionResult(
                        alert_type='High Connection Frequency',
                        source_ip=source_ip,
                        destination_ip=None,
                        destination_port=None,
                        severity=severity,
                        risk_score=risk_score,
                        event_count=len(window_df),
                        first_seen=window_df['timestamp'].min(),
                        last_seen=window_df['timestamp'].max(),
                        explanation=f"Source {source_ip} generated {len(window_df)} connections within {time_window_minutes} minutes (average {len(window_df)/time_window_minutes:.1f} connections/minute). This unusually high frequency may indicate automated activity, scanning, or potential attack.",
                        recommendation=f"Investigate {source_ip} for unusual behavior. Check if this is a legitimate service or compromised system. Consider rate limiting.",
                        evidence={
                            'total_connections': len(window_df),
                            'time_window_minutes': time_window_minutes,
                            'connections_per_minute': round(len(window_df) / time_window_minutes, 1),
                            'denied_connections': int(denied_count),
                            'unique_destinations': int(unique_destinations)
                        }
                    ))
                    break

        return results

    def run_all_detections(self) -> List[DetectionResult]:
        """Run all detection rules and return combined results."""
        all_detections = []

        all_detections.extend(self.detect_port_scanning())
        all_detections.extend(self.detect_brute_force())
        all_detections.extend(self.detect_excessive_denies())
        all_detections.extend(self.detect_high_frequency())

        # Sort by risk score (highest first)
        all_detections.sort(key=lambda x: x.risk_score, reverse=True)

        self.detections = all_detections
        return all_detections

    def _identify_service(self, port: int) -> str:
        """Identify common service by port number."""
        services = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return services.get(port, f'Port {port}')
