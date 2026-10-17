"""Threat Detection UI Module."""

import streamlit as st


def _display_time(value, include_date: bool = True) -> str:
    """Format timestamps whether they came from memory or SQLite."""
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M:%S" if include_date else "%H:%M:%S")
    return str(value or "Unknown")


def _get_alert_records(db, alerts):
    """Prefer rich in-memory alerts, then fall back to persisted alerts."""
    if alerts:
        return [
            {
                "alert_type": alert.alert_type,
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip,
                "destination_port": alert.destination_port,
                "severity": alert.severity,
                "risk_score": alert.risk_score,
                "event_count": alert.event_count,
                "first_seen": alert.first_seen,
                "last_seen": alert.last_seen,
                "explanation": alert.explanation,
                "recommendation": alert.recommendation,
                "evidence": alert.evidence,
            }
            for alert in alerts
        ]

    # Streamlit session state resets after a browser refresh, whereas the
    # analysis results are stored in SQLite.
    return db.get_alerts().to_dict("records")


def show(db, alerts):
    st.markdown('<p class="main-header">🚨 Threat Detection</p>', unsafe_allow_html=True)

    alert_records = _get_alert_records(db, alerts)
    if not alert_records:
        st.info("No threats detected yet. Upload and analyze logs first.")
        return

    st.markdown(f"**Total Alerts Detected:** {len(alert_records)}")
    severity_filter = st.multiselect(
        "Filter by Severity",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    )
    alert_types = sorted({alert["alert_type"] for alert in alert_records})
    type_filter = st.multiselect("Filter by Type", alert_types, default=alert_types)

    filtered_alerts = [
        alert for alert in alert_records
        if alert["severity"] in severity_filter and alert["alert_type"] in type_filter
    ]
    st.markdown(f"**Showing {len(filtered_alerts)} alerts**")

    for index, alert in enumerate(filtered_alerts, 1):
        severity_class = f"alert-{str(alert['severity']).lower()}"
        destination = ""
        if alert.get("destination_ip"):
            port = f":{alert['destination_port']}" if alert.get("destination_port") else ""
            destination = f"<p><strong>Destination:</strong> {alert['destination_ip']}{port}</p>"

        # Keep the HTML contiguous.  A blank line inside a raw HTML block is
        # interpreted by Streamlit's Markdown renderer as a separate code
        # block, exposing the paragraph tags for alerts without a destination.
        alert_card = (
            f'<div class="{severity_class}">'
            f'<h3>{alert["severity"]} - {alert["alert_type"]}</h3>'
            f'<p><strong>Source IP:</strong> {alert["source_ip"]}</p>'
            f'{destination}'
            f'<p><strong>Risk Score:</strong> {alert["risk_score"]}/100</p>'
            f'<p><strong>Event Count:</strong> {alert["event_count"]}</p>'
            f'<p><strong>Time Range:</strong> {_display_time(alert["first_seen"])} to '
            f'{_display_time(alert["last_seen"], include_date=False)}</p>'
            '</div>'
        )
        st.markdown(
            alert_card,
            unsafe_allow_html=True,
        )

        with st.expander(f"Alert #{index} - Details"):
            if alert.get("explanation"):
                st.markdown(f"**Explanation:**\n\n{alert['explanation']}")
            if alert.get("recommendation"):
                st.markdown(f"**Recommendation:**\n\n{alert['recommendation']}")
            if alert.get("evidence"):
                st.markdown("**Evidence:**")
                for key, value in alert["evidence"].items():
                    st.write(f"- {key}: {value}")
