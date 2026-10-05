"""Dashboard UI Module."""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from app.analysis.analytics import NetworkAnalytics


def show(db, df, alerts, incidents):
    st.markdown('<p class="main-header">🛡️ Security Dashboard</p>', unsafe_allow_html=True)

    if df.empty:
        df = db.get_logs_as_dataframe(limit=10000)

    if df.empty:
        st.info("No log data loaded. Go to **Upload Logs** to load sample or custom log data.")
        return

    analytics = NetworkAnalytics(df)
    stats = analytics.get_summary_stats()

    # KPI Metrics Row
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric("Total Events", f"{stats['total_events']:,}")
    with col2:
        st.metric("Allowed Events", f"{stats['allowed_events']:,}", delta=f"{stats['allowed_events']/stats['total_events']*100:.1f}%")
    with col3:
        st.metric("Denied Events", f"{stats['denied_events']:,}", delta=f"-{stats['denied_events']/stats['total_events']*100:.1f}%", delta_color="inverse")
    with col4:
        st.metric("Unique Sources", f"{stats['unique_source_ips']:,}")
    with col5:
        st.metric("Unique Destinations", f"{stats['unique_destination_ips']:,}")

    st.markdown("---")

    # Threat Summary if alerts exist
    if alerts:
        st.subheader("🚨 Threat Summary")
        critical_count = sum(1 for a in alerts if a.severity == 'CRITICAL')
        high_count = sum(1 for a in alerts if a.severity == 'HIGH')
        medium_count = sum(1 for a in alerts if a.severity == 'MEDIUM')
        low_count = sum(1 for a in alerts if a.severity == 'LOW')

        acol1, acol2, acol3, acol4, acol5 = st.columns(5)
        with acol1:
            st.metric("Total Alerts", len(alerts))
        with acol2:
            st.metric("Critical", critical_count, delta="Immediate action", delta_color="inverse")
        with acol3:
            st.metric("High", high_count, delta="Requires review", delta_color="inverse")
        with acol4:
            st.metric("Medium", medium_count)
        with acol5:
            st.metric("Low", low_count)

        st.markdown("---")

    # Visualizations Row 1
    vcol1, vcol2 = st.columns(2)

    with vcol1:
        st.subheader("📈 Traffic Over Time")
        traffic_time = analytics.get_traffic_over_time(interval='5min')
        if not traffic_time.empty:
            fig = px.area(traffic_time, x='timestamp', y=['ALLOW', 'DENY'],
                          labels={'value': 'Event Count', 'timestamp': 'Time'},
                          color_discrete_map={'ALLOW': '#2ca02c', 'DENY': '#d62728'})
            fig.update_layout(height=350, margin=dict(l=20, r=20, t=30, b=20))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No time series data available")

    with vcol2:
        st.subheader("🎯 Action Distribution")
        action_dist = analytics.get_action_distribution()
        if action_dist:
            fig = px.pie(values=list(action_dist.values()), names=list(action_dist.keys()),
                         color=list(action_dist.keys()),
                         color_discrete_map={'ALLOW': '#2ca02c', 'DENY': '#d62728'})
            fig.update_layout(height=350, margin=dict(l=20, r=20, t=30, b=20))
            st.plotly_chart(fig, use_container_width=True)

    # Visualizations Row 2
    vcol3, vcol4 = st.columns(2)

    with vcol3:
        st.subheader("🌐 Top Source IPs")
        top_sources = analytics.get_top_source_ips(top_n=10)
        if not top_sources.empty:
            fig = px.bar(top_sources, x='total_events', y='source_ip', orientation='h',
                         color='denied_events',
                         color_continuous_scale='Reds',
                         labels={'total_events': 'Total Events', 'source_ip': 'Source IP'})
            fig.update_layout(height=400, yaxis={'categoryorder': 'total ascending'},
                              margin=dict(l=20, r=20, t=30, b=20))
            st.plotly_chart(fig, use_container_width=True)

    with vcol4:
        st.subheader("🔌 Top Targeted Destination Ports")
        top_ports = analytics.get_top_destination_ports(top_n=10)
        if not top_ports.empty:
            top_ports['destination_port'] = top_ports['destination_port'].astype(str)
            fig = px.bar(top_ports, x='destination_port', y='total_attempts',
                         color='denied',
                         color_continuous_scale='Oranges',
                         labels={'total_attempts': 'Total Attempts', 'destination_port': 'Port'})
            fig.update_layout(height=400, margin=dict(l=20, r=20, t=30, b=20))
            st.plotly_chart(fig, use_container_width=True)

    # Visualizations Row 3
    vcol5, vcol6 = st.columns(2)

    with vcol5:
        st.subheader("📡 Protocol Distribution")
        protocol_dist = analytics.get_protocol_distribution()
        if protocol_dist:
            fig = px.bar(x=list(protocol_dist.keys()), y=list(protocol_dist.values()),
                         labels={'x': 'Protocol', 'y': 'Count'},
                         color=list(protocol_dist.keys()))
            fig.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20))
            st.plotly_chart(fig, use_container_width=True)

    with vcol6:
        st.subheader("⚠️ Denied Traffic Over Time")
        denied_time = analytics.get_denied_traffic_over_time(interval='5min')
        if not denied_time.empty:
            fig = px.line(denied_time, x='timestamp', y='denied_count',
                          labels={'denied_count': 'Denied Events', 'timestamp': 'Time'},
                          line_shape='spline')
            fig.update_traces(line_color='#d62728')
            fig.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20))
            st.plotly_chart(fig, use_container_width=True)
