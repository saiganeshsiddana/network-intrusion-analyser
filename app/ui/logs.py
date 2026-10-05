"""Log Explorer UI Module."""

import streamlit as st
import pandas as pd


def show(db):
    st.markdown('<p class="main-header">🔍 Log Explorer</p>', unsafe_allow_html=True)

    df = db.get_logs_as_dataframe(limit=10000)

    if df.empty:
        st.info("No logs loaded. Upload logs first.")
        return

    st.markdown(f"**Total Events in Database:** {len(df):,}")

    # Filters
    st.subheader("Filters")
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        source_filter = st.text_input("Source IP", "")
    with col2:
        dest_filter = st.text_input("Destination IP", "")
    with col3:
        protocol_filter = st.selectbox("Protocol", ["All", "TCP", "UDP", "ICMP"])
    with col4:
        action_filter = st.selectbox("Action", ["All", "ALLOW", "DENY"])

    # Apply filters
    filtered_df = df.copy()

    if source_filter:
        filtered_df = filtered_df[filtered_df['source_ip'].str.contains(source_filter, case=False)]
    if dest_filter:
        filtered_df = filtered_df[filtered_df['destination_ip'].str.contains(dest_filter, case=False)]
    if protocol_filter != "All":
        filtered_df = filtered_df[filtered_df['protocol'] == protocol_filter]
    if action_filter != "All":
        filtered_df = filtered_df[filtered_df['action'] == action_filter]

    st.markdown(f"**Filtered Results:** {len(filtered_df):,} events")

    # Display options
    display_limit = st.slider("Display Limit", 10, 500, 100)

    # Show data
    if not filtered_df.empty:
        display_df = filtered_df.head(display_limit)[['timestamp', 'source_ip', 'source_port',
                                                       'destination_ip', 'destination_port',
                                                       'protocol', 'action']]
        st.dataframe(display_df, use_container_width=True, height=500)

        # Export option
        st.markdown("---")
        if st.button("Export Filtered Logs to CSV"):
            from app.reporting.reports import ReportGenerator
            reporter = ReportGenerator()
            export_path = reporter.export_logs_csv(filtered_df, "filtered_logs")
            st.success(f"Exported to: {export_path}")
    else:
        st.warning("No logs match the current filters.")
