"""Reports UI Module."""

import streamlit as st
import pandas as pd
from app.reporting.reports import ReportGenerator
from app.analysis.analytics import NetworkAnalytics


def show(db):
    st.markdown('<p class="main-header">📄 Security Reports</p>', unsafe_allow_html=True)

    df = db.get_logs_as_dataframe(limit=10000)

    if df.empty:
        st.info("No logs loaded. Upload logs first.")
        return

    st.markdown("Generate comprehensive security analysis reports.")

    reporter = ReportGenerator()

    # Generate summary report
    st.subheader("Generate Summary Report")

    if st.button("Generate Full Security Report", type="primary"):
        with st.spinner("Generating report..."):
            analytics = NetworkAnalytics(df)
            stats = analytics.get_summary_stats()

            alerts_df = db.get_alerts()
            incidents_df = db.get_incidents()

            ml_results = st.session_state.get('ml_results', pd.DataFrame())
            if ml_results.empty:
                ml_results = db.get_ml_predictions()

            report_path = reporter.generate_summary_report(stats, alerts_df, incidents_df, ml_results)
            st.success(f"Report generated: {report_path}")

            with open(report_path, 'r') as f:
                st.download_button(
                    label="Download Report CSV",
                    data=f.read(),
                    file_name="security_report.csv",
                    mime="text/csv"
                )

    st.markdown("---")

    # Export options
    st.subheader("Export Options")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("Export Alerts"):
            alerts_df = db.get_alerts()
            if not alerts_df.empty:
                path = reporter.export_alerts_csv(alerts_df)
                st.success(f"Exported to: {path}")
            else:
                st.warning("No alerts to export")

    with col2:
        if st.button("Export Incidents"):
            incidents_df = db.get_incidents()
            if not incidents_df.empty:
                path = reporter.export_incidents_csv(incidents_df)
                st.success(f"Exported to: {path}")
            else:
                st.warning("No incidents to export")

    with col3:
        if st.button("Export All Logs"):
            path = reporter.export_logs_csv(df, "all_logs")
            st.success(f"Exported to: {path}")
