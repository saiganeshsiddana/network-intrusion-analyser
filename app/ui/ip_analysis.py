"""IP Analysis UI Module."""

import streamlit as st
import plotly.express as px
from app.analysis.analytics import NetworkAnalytics


def show(db):
    st.markdown('<p class="main-header">🌐 IP Investigation</p>', unsafe_allow_html=True)

    df = db.get_logs_as_dataframe(limit=10000)

    if df.empty:
        st.info("No logs loaded. Upload logs first.")
        return

    analytics = NetworkAnalytics(df)

    # IP selection
    source_ips = sorted(df['source_ip'].unique())
    selected_ip = st.selectbox("Select Source IP to Investigate", source_ips)

    if selected_ip:
        st.markdown(f"## Investigation: {selected_ip}")

        analysis = analytics.analyze_source_ip(selected_ip)

        if not analysis['found']:
            st.warning("IP not found in logs.")
            return

        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Events", analysis['total_events'])
        with col2:
            st.metric("Allowed", analysis['allowed_events'])
        with col3:
            st.metric("Denied", analysis['denied_events'])
        with col4:
            deny_ratio = analysis['denied_events'] / analysis['total_events'] if analysis['total_events'] > 0 else 0
            st.metric("Deny Ratio", f"{deny_ratio:.1%}")

        col5, col6, col7, col8 = st.columns(4)
        with col5:
            st.metric("Unique Destinations", analysis['unique_destinations'])
        with col6:
            st.metric("Unique Ports", analysis['unique_ports'])
        with col7:
            st.metric("First Seen", analysis['first_seen'].strftime('%H:%M:%S'))
        with col8:
            st.metric("Last Seen", analysis['last_seen'].strftime('%H:%M:%S'))

        st.markdown("---")

        # Visualizations
        vcol1, vcol2 = st.columns(2)

        with vcol1:
            st.subheader("Protocol Distribution")
            if analysis['protocols']:
                fig = px.pie(values=list(analysis['protocols'].values()),
                            names=list(analysis['protocols'].keys()))
                fig.update_layout(height=300)
                st.plotly_chart(fig, use_container_width=True)

        with vcol2:
            st.subheader("Top Targeted Ports")
            if analysis['top_ports']:
                top_ports_df = pd.DataFrame(list(analysis['top_ports'].items()),
                                           columns=['Port', 'Count'])
                fig = px.bar(top_ports_df.head(10), x='Port', y='Count')
                fig.update_layout(height=300)
                st.plotly_chart(fig, use_container_width=True)

        # Top destinations
        st.subheader("Top Destination IPs")
        if analysis['top_destinations']:
            dest_df = pd.DataFrame(list(analysis['top_destinations'].items()),
                                  columns=['Destination IP', 'Count'])
            st.dataframe(dest_df.head(15), use_container_width=True)
