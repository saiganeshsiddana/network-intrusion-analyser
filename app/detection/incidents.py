"""
Incident Management & Timeline Module

Groups related alerts and events into cohesive security incidents.
Provides timeline generation for analyst investigation.
"""

import pandas as pd
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from app.detection.rules import DetectionResult


@dataclass
class Incident:
    """Grouped security incident representing related suspicious activity."""
    incident_id: str
    incident_type: str
    source_ip: str
    destination_ip: Optional[str]
    severity: str
    risk_score: int
    status: str  # New, Investigating, Resolved, False Positive
    first_seen: datetime
    last_seen: datetime
    event_count: int
    alert_count: int
    summary: str
    recommendation: str
    alerts: List[DetectionResult] = field(default_factory=list)
    timeline_events: List[Dict] = field(default_factory=list)


class IncidentCorrelator:
    """Correlates alerts and events into incidents."""

    def __init__(self, alerts: List[DetectionResult], events_df: pd.DataFrame):
        self.alerts = alerts
        self.events_df = events_df
        if not events_df.empty and 'timestamp' in events_df.columns:
            self.events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])

    def correlate_incidents(self) -> List[Incident]:
        """
        Group alerts by source IP into coherent incidents.

        Alerts from the same source IP within a reasonable time window
        are combined into a single incident.
        """
        incidents = []

        if not self.alerts:
            return incidents

        # Group alerts by source IP
        alerts_by_source: Dict[str, List[DetectionResult]] = {}
        for alert in self.alerts:
            if alert.source_ip not in alerts_by_source:
                alerts_by_source[alert.source_ip] = []
            alerts_by_source[alert.source_ip].append(alert)

        # Create incident per source IP
        for incident_num, (source_ip, source_alerts) in enumerate(alerts_by_source.items(), 1):
            # Calculate overall metrics
            max_risk = max(a.risk_score for a in source_alerts)
            alert_types = list(set(a.alert_type for a in source_alerts))

            first_seen = min(a.first_seen for a in source_alerts)
            last_seen = max(a.last_seen for a in source_alerts)
            total_events = sum(a.event_count for a in source_alerts)

            # Determine primary incident type
            if len(alert_types) == 1:
                primary_type = alert_types[0]
            else:
                primary_type = f"Multiple Threat Patterns ({', '.join(alert_types[:2])})"

            # Overall severity
            if max_risk >= 80:
                severity = 'CRITICAL'
            elif max_risk >= 70:
                severity = 'HIGH'
            elif max_risk >= 50:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'

            # Primary destination
            dest_ips = [a.destination_ip for a in source_alerts if a.destination_ip]
            primary_dest = dest_ips[0] if dest_ips else "Multiple Internal Hosts"

            # Create summary
            summary = (
                f"Source {source_ip} exhibited {len(source_alerts)} threat indicator(s) "
                f"including {', '.join(alert_types)} between {first_seen.strftime('%H:%M:%S')} "
                f"and {last_seen.strftime('%H:%M:%S')}. Total associated events: {total_events}."
            )

            # Recommendations
            recommendations = [a.recommendation for a in source_alerts]
            primary_rec = recommendations[0] if recommendations else "Investigate source IP activity."

            # Generate timeline
            timeline = self._generate_timeline(source_ip, first_seen, last_seen)

            incident = Incident(
                incident_id=f"INC-{incident_num:04d}",
                incident_type=primary_type,
                source_ip=source_ip,
                destination_ip=primary_dest,
                severity=severity,
                risk_score=max_risk,
                status="New",
                first_seen=first_seen,
                last_seen=last_seen,
                event_count=total_events,
                alert_count=len(source_alerts),
                summary=summary,
                recommendation=primary_rec,
                alerts=source_alerts,
                timeline_events=timeline
            )

            incidents.append(incident)

        # Sort by risk score
        incidents.sort(key=lambda x: x.risk_score, reverse=True)
        return incidents

    def _generate_timeline(self, source_ip: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        """
        Generate detailed event timeline for analyst investigation.

        Shows chronological sequence of events for a source IP.
        """
        if self.events_df.empty:
            return []

        # Filter events for this source IP
        ip_events = self.events_df[
            (self.events_df['source_ip'] == source_ip) &
            (self.events_df['timestamp'] >= start_time - timedelta(minutes=2)) &
            (self.events_df['timestamp'] <= end_time + timedelta(minutes=2))
        ].copy()

        if ip_events.empty:
            return []

        ip_events = ip_events.sort_values('timestamp')

        # Limit to top 50 events for readability
        if len(ip_events) > 50:
            # Sample start, middle, end
            head = ip_events.head(15)
            tail = ip_events.tail(15)
            middle = ip_events.iloc[15:-15].sample(n=min(20, len(ip_events)-30))
            ip_events = pd.concat([head, middle, tail]).sort_values('timestamp')

        timeline = []
        for _, row in ip_events.iterrows():
            timeline.append({
                'timestamp': row['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                'source_ip': row['source_ip'],
                'destination_ip': row['destination_ip'],
                'destination_port': int(row['destination_port']),
                'protocol': row['protocol'],
                'action': row['action'],
                'description': f"{row['action']} -> {row['destination_ip']}:{row['destination_port']} ({row['protocol']})"
            })

        return timeline
