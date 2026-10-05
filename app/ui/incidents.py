"""Incidents UI Module."""

import streamlit as st
import pandas as pd


def show(db, incidents):
    st.markdown('<p class="main-header">📋 Security Incidents</p>', unsafe_allow_html=True)

    if not incidents:
        st.info("No incidents detected. Upload and analyze logs first.")
        return

    st.markdown(f"**Total Incidents:** {len(incidents)}")

    # Display incident summary
    col1, col2, col3, col4 = st.columns(4)
    critical = sum(1 for i in incidents if i.severity == 'CRITICAL')
    high = sum(1 for i in incidents if i.severity == 'HIGH')
    medium = sum(1 for i in incidents if i.severity == 'MEDIUM')
    low = sum(1 for i in incidents if i.severity == 'LOW')

    with col1:
        st.metric("Critical", critical)
    with col2:
        st.metric("High", high)
    with col3:
        st.metric("Medium", medium)
    with col4:
        st.metric("Low", low)

    st.markdown("---")

    # Display each incident
    for incident in incidents:
        severity_class = f"alert-{incident.severity.lower()}"

        st.markdown(f"""
        <div class="{severity_class}">
            <h3>{incident.incident_id}: {incident.incident_type}</h3>
            <p><strong>Severity:</strong> {incident.severity} | <strong>Risk Score:</strong> {incident.risk_score}/100</p>
            <p><strong>Source IP:</strong> {incident.source_ip}</p>
            <p><strong>Status:</strong> {incident.status}</p>
        </div>
        """, unsafe_allow_html=True)

        with st.expander(f"{incident.incident_id} - Full Details"):
            st.markdown(f"**Summary:**\n\n{incident.summary}")
            st.markdown(f"**Recommendation:**\n\n{incident.recommendation}")

            st.markdown(f"**Metrics:**")
            st.write(f"- Total Events: {incident.event_count}")
            st.write(f"- Related Alerts: {incident.alert_count}")
            st.write(f"- First Seen: {incident.first_seen.strftime('%Y-%m-%d %H:%M:%S')}")
            st.write(f"- Last Seen: {incident.last_seen.strftime('%Y-%m-%d %H:%M:%S')}")

            # Show related alerts
            if incident.alerts:
                st.markdown("**Related Alerts:**")
                for alert in incident.alerts:
                    st.write(f"- {alert.alert_type} (Risk: {alert.risk_score})")

            # Show timeline
            if incident.timeline_events:
                st.markdown(f"**Event Timeline ({len(incident.timeline_events)} events):**")
                timeline_df = pd.DataFrame(incident.timeline_events)
                st.dataframe(timeline_df[['timestamp', 'destination_ip', 'destination_port', 'action']],
                            use_container_width=True, height=200)
