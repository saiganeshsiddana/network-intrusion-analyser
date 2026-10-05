"""Threat Detection UI Module."""

import streamlit as st


def show(db, alerts):
    st.markdown('<p class="main-header">🚨 Threat Detection</p>', unsafe_allow_html=True)

    if not alerts:
        st.info("No threats detected yet. Upload and analyze logs first.")
        return

    st.markdown(f"**Total Alerts Detected:** {len(alerts)}")

    # Severity filter
    severity_filter = st.multiselect(
        "Filter by Severity",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )

    # Alert type filter
    alert_types = list(set(a.alert_type for a in alerts))
    type_filter = st.multiselect(
        "Filter by Type",
        alert_types,
        default=alert_types
    )

    # Filter alerts
    filtered_alerts = [a for a in alerts
                      if a.severity in severity_filter and a.alert_type in type_filter]

    st.markdown(f"**Showing {len(filtered_alerts)} alerts**")

    # Display alerts
    for idx, alert in enumerate(filtered_alerts, 1):
        severity_class = f"alert-{alert.severity.lower()}"

        st.markdown(f"""
        <div class="{severity_class}">
            <h3>{alert.severity} - {alert.alert_type}</h3>
            <p><strong>Source IP:</strong> {alert.source_ip}</p>
            {f'<p><strong>Destination:</strong> {alert.destination_ip}:{alert.destination_port}</p>' if alert.destination_ip else ''}
            <p><strong>Risk Score:</strong> {alert.risk_score}/100</p>
            <p><strong>Event Count:</strong> {alert.event_count}</p>
            <p><strong>Time Range:</strong> {alert.first_seen.strftime('%Y-%m-%d %H:%M:%S')} to {alert.last_seen.strftime('%H:%M:%S')}</p>
        </div>
        """, unsafe_allow_html=True)

        with st.expander(f"Alert #{idx} - Details"):
            st.markdown(f"**Explanation:**\n\n{alert.explanation}")
            st.markdown(f"**Recommendation:**\n\n{alert.recommendation}")

            if alert.evidence:
                st.markdown("**Evidence:**")
                for key, value in alert.evidence.items():
                    st.write(f"- {key}: {value}")
