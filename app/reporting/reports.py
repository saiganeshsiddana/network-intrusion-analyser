"""
Report Generation Module

Generates security analysis reports in CSV format.
"""

import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import csv


class ReportGenerator:
    """Generates security analysis reports."""

    def __init__(self):
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)

    def generate_summary_report(self,
                               stats: Dict,
                               alerts: pd.DataFrame,
                               incidents: pd.DataFrame,
                               ml_results: Optional[pd.DataFrame] = None) -> str:
        """
        Generate comprehensive security summary report.

        Returns path to generated report file.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.reports_dir / f"security_report_{timestamp}.csv"

        with open(report_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow(['NETWORK INTRUSION LOG ANALYSIS REPORT'])
            writer.writerow(['Generated:', datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            writer.writerow([])

            # Summary Statistics
            writer.writerow(['=== SUMMARY STATISTICS ==='])
            writer.writerow(['Metric', 'Value'])
            writer.writerow(['Total Events', stats.get('total_events', 0)])
            writer.writerow(['Allowed Events', stats.get('allowed_events', 0)])
            writer.writerow(['Denied Events', stats.get('denied_events', 0)])
            writer.writerow(['Unique Source IPs', stats.get('unique_source_ips', 0)])
            writer.writerow(['Unique Destination IPs', stats.get('unique_destination_ips', 0)])
            writer.writerow(['Unique Destination Ports', stats.get('unique_destination_ports', 0)])
            writer.writerow([])

            # Time Range
            if stats.get('time_range'):
                writer.writerow(['Analysis Period'])
                writer.writerow(['Start', stats['time_range']['start']])
                writer.writerow(['End', stats['time_range']['end']])
                writer.writerow([])

            # Protocol Distribution
            if stats.get('protocols'):
                writer.writerow(['=== PROTOCOL DISTRIBUTION ==='])
                writer.writerow(['Protocol', 'Count'])
                for protocol, count in stats['protocols'].items():
                    writer.writerow([protocol, count])
                writer.writerow([])

            # Alerts Summary
            writer.writerow(['=== THREAT DETECTION SUMMARY ==='])
            writer.writerow(['Total Alerts Detected', len(alerts)])

            if not alerts.empty:
                severity_counts = alerts['severity'].value_counts()
                writer.writerow([])
                writer.writerow(['Severity Distribution'])
                writer.writerow(['Severity', 'Count'])
                for severity, count in severity_counts.items():
                    writer.writerow([severity, count])
                writer.writerow([])

                alert_types = alerts['alert_type'].value_counts()
                writer.writerow(['Alert Types'])
                writer.writerow(['Type', 'Count'])
                for alert_type, count in alert_types.items():
                    writer.writerow([alert_type, count])
                writer.writerow([])

            # Incidents Summary
            writer.writerow(['=== INCIDENTS ==='])
            writer.writerow(['Total Incidents', len(incidents)])

            if not incidents.empty:
                writer.writerow([])
                incident_severity = incidents['severity'].value_counts()
                writer.writerow(['Incident Severity'])
                writer.writerow(['Severity', 'Count'])
                for severity, count in incident_severity.items():
                    writer.writerow([severity, count])
                writer.writerow([])

            # ML Results Summary
            if ml_results is not None and not ml_results.empty:
                writer.writerow(['=== MACHINE LEARNING ANALYSIS ==='])
                suspicious_count = len(ml_results[ml_results['ml_prediction'] == 1])
                writer.writerow(['Suspicious IPs (ML)', suspicious_count])
                writer.writerow(['Normal IPs (ML)', len(ml_results) - suspicious_count])
                writer.writerow([])

            # Recommendations
            writer.writerow(['=== RECOMMENDATIONS ==='])
            writer.writerow(['Recommendation'])
            if not incidents.empty:
                writer.writerow(['1. Investigate all CRITICAL and HIGH severity incidents immediately'])
                writer.writerow(['2. Review firewall rules for top suspicious source IPs'])
                writer.writerow(['3. Enable rate limiting on frequently targeted services'])
                writer.writerow(['4. Monitor authentication logs for signs of compromise'])
                writer.writerow(['5. Consider blocking repeat offenders at network perimeter'])
            else:
                writer.writerow(['No immediate threats detected. Continue monitoring.'])
            writer.writerow([])

            # Limitations
            writer.writerow(['=== LIMITATIONS ==='])
            writer.writerow(['Limitation'])
            writer.writerow(['- Analysis based on firewall logs only (no payload inspection)'])
            writer.writerow(['- ML model trained on synthetic data for demonstration'])
            writer.writerow(['- Detection rules use configurable thresholds that may need tuning'])
            writer.writerow(['- Requires correlation with authentication and application logs'])
            writer.writerow(['- False positives possible - human verification required'])

        return str(report_path)

    def export_alerts_csv(self, alerts: pd.DataFrame) -> str:
        """Export alerts to CSV."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.reports_dir / f"alerts_{timestamp}.csv"

        if not alerts.empty:
            alerts.to_csv(report_path, index=False)
        else:
            # Create empty file with headers
            pd.DataFrame(columns=['alert_type', 'source_ip', 'severity', 'risk_score']).to_csv(
                report_path, index=False
            )

        return str(report_path)

    def export_incidents_csv(self, incidents: pd.DataFrame) -> str:
        """Export incidents to CSV."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.reports_dir / f"incidents_{timestamp}.csv"

        if not incidents.empty:
            incidents.to_csv(report_path, index=False)
        else:
            pd.DataFrame(columns=['incident_id', 'source_ip', 'severity', 'status']).to_csv(
                report_path, index=False
            )

        return str(report_path)

    def export_logs_csv(self, logs: pd.DataFrame, filename: str = "logs_export") -> str:
        """Export filtered logs to CSV."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.reports_dir / f"{filename}_{timestamp}.csv"

        if not logs.empty:
            logs.to_csv(report_path, index=False)
        else:
            pd.DataFrame(columns=['timestamp', 'source_ip', 'destination_ip', 'action']).to_csv(
                report_path, index=False
            )

        return str(report_path)
