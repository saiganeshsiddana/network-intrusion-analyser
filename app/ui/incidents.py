"""Incidents UI Module."""

import streamlit as st
import pandas as pd


def _display_time(value) -> str:
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value or "Unknown")


def _get_incident_records(db, incidents):
    """Return current-session incidents or durable incident records."""
    if incidents:
        return [
            {
                "incident_id": incident.incident_id,
                "incident_type": incident.incident_type,
                "source_ip": incident.source_ip,
                "severity": incident.severity,
                "risk_score": incident.risk_score,
                "status": incident.status,
                "event_count": incident.event_count,
                "alert_count": incident.alert_count,
                "first_seen": incident.first_seen,
                "last_seen": incident.last_seen,
                "summary": incident.summary,
                "recommendation": incident.recommendation,
                "alerts": incident.alerts,
                "timeline_events": incident.timeline_events,
            }
            for incident in incidents
        ]

    # Database records survive browser refreshes; Streamlit session values do not.
    return db.get_incidents().to_dict("records")


def show(db, incidents):
    st.markdown('<p class="main-header">📋 Security Incidents</p>', unsafe_allow_html=True)

    incident_records = _get_incident_records(db, incidents)
    if not incident_records:
        st.info("No incidents detected. Upload and analyze logs first.")
        return

    st.markdown(f"**Total Incidents:** {len(incident_records)}")
    columns = st.columns(4)
    for column, severity in zip(columns, ("CRITICAL", "HIGH", "MEDIUM", "LOW")):
        with column:
            st.metric(severity.title(), sum(record["severity"] == severity for record in incident_records))

    st.markdown("---")
    for incident in incident_records:
        severity_class = f"alert-{str(incident['severity']).lower()}"
        incident_identifier = incident.get("incident_id") or f"INC-{incident.get('id', 'Unknown')}"
        st.markdown(
            f"""
            <div class="{severity_class}">
                <h3>{incident_identifier}: {incident['incident_type']}</h3>
                <p><strong>Severity:</strong> {incident['severity']} | <strong>Risk Score:</strong> {incident['risk_score']}/100</p>
                <p><strong>Source IP:</strong> {incident['source_ip']}</p>
                <p><strong>Status:</strong> {incident['status']}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        with st.expander(f"{incident_identifier} - Full Details"):
            if incident.get("summary"):
                st.markdown(f"**Summary:**\n\n{incident['summary']}")
            if incident.get("recommendation"):
                st.markdown(f"**Recommendation:**\n\n{incident['recommendation']}")
            st.markdown("**Metrics:**")
            st.write(f"- Total Events: {incident['event_count']}")
            st.write(f"- Related Alerts: {incident['alert_count']}")
            st.write(f"- First Seen: {_display_time(incident['first_seen'])}")
            st.write(f"- Last Seen: {_display_time(incident['last_seen'])}")

            if incident.get("alerts"):
                st.markdown("**Related Alerts:**")
                for alert in incident["alerts"]:
                    st.write(f"- {alert.alert_type} (Risk: {alert.risk_score})")
            if incident.get("timeline_events"):
                st.markdown(f"**Event Timeline ({len(incident['timeline_events'])} events):**")
                timeline_df = pd.DataFrame(incident["timeline_events"])
                st.dataframe(
                    timeline_df[["timestamp", "destination_ip", "destination_port", "action"]],
                    use_container_width=True,
                    height=200,
                )
