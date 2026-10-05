"""Upload Logs UI Module."""

import streamlit as st
from app.parser.log_parser import LogParser
from app.detection.rules import ThreatDetectionEngine
from app.detection.incidents import IncidentCorrelator
from app.ml.predict import ThreatPredictor
import pandas as pd


def show(db):
    st.markdown('<p class="main-header">📤 Upload Network Logs</p>', unsafe_allow_html=True)

    st.markdown("""
    Upload network log files for analysis. Supported formats:
    - **TXT** - Firewall log format: `YYYY-MM-DD HH:MM:SS SOURCE_IP:PORT -> DEST_IP:PORT PROTOCOL ACTION`
    """)

    tab1, tab2 = st.tabs(["Load Sample Data", "Upload Custom Logs"])

    with tab1:
        st.subheader("Load Sample Dataset")
        st.info("Load the pre-generated sample dataset containing normal traffic and suspicious patterns.")

        if st.button("Load Sample Data", type="primary"):
            with st.spinner("Loading sample data..."):
                parser = LogParser()
                sample_path = "data/sample/network_logs.txt"

                try:
                    parsed_logs, stats = parser.parse_file(sample_path)

                    # Display parsing stats
                    st.success(f"Parsed {stats['parsed']:,} events successfully!")

                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Total Lines", stats['total'])
                    with col2:
                        st.metric("Successfully Parsed", stats['parsed'])
                    with col3:
                        st.metric("Failed/Invalid", stats['failed'])

                    if stats['failed'] > 0:
                        st.warning(f"Failed to parse {stats['failed']} records. Check log format.")
                        with st.expander("Parsing Errors Breakdown"):
                            st.write(f"- Malformed: {stats['malformed']}")
                            st.write(f"- Invalid IP: {stats['invalid_ip']}")
                            st.write(f"- Invalid Port: {stats['invalid_port']}")
                            st.write(f"- Invalid Timestamp: {stats['invalid_timestamp']}")

                    # Clear existing data
                    db.clear_all_events()
                    db.clear_alerts()
                    db.clear_incidents()

                    # Insert into database
                    with st.spinner("Storing in database..."):
                        inserted = db.insert_logs_batch(parsed_logs)
                        st.success(f"Stored {inserted:,} events in database")

                    # Run threat detection
                    with st.spinner("Running threat detection..."):
                        df = db.get_logs_as_dataframe()
                        detector = ThreatDetectionEngine(df)
                        alerts = detector.run_all_detections()

                        st.session_state.alerts = alerts
                        st.session_state.current_df = df

                        # Store alerts in DB
                        for alert in alerts:
                            db.insert_alert({
                                'alert_type': alert.alert_type,
                                'source_ip': alert.source_ip,
                                'destination_ip': alert.destination_ip,
                                'destination_port': alert.destination_port,
                                'severity': alert.severity,
                                'risk_score': alert.risk_score,
                                'event_count': alert.event_count,
                                'first_seen': alert.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
                                'last_seen': alert.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
                                'explanation': alert.explanation,
                                'recommendation': alert.recommendation
                            })

                        st.success(f"Detected {len(alerts)} potential threats")

                    # Correlate incidents
                    with st.spinner("Correlating incidents..."):
                        correlator = IncidentCorrelator(alerts, df)
                        incidents = correlator.correlate_incidents()
                        st.session_state.incidents = incidents

                        # Store incidents in DB
                        for incident in incidents:
                            db.insert_incident({
                                'incident_type': incident.incident_type,
                                'source_ip': incident.source_ip,
                                'destination_ip': incident.destination_ip,
                                'severity': incident.severity,
                                'risk_score': incident.risk_score,
                                'status': incident.status,
                                'first_seen': incident.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
                                'last_seen': incident.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
                                'event_count': incident.event_count,
                                'alert_count': incident.alert_count,
                                'summary': incident.summary,
                                'recommendation': incident.recommendation
                            })

                        st.success(f"Correlated {len(incidents)} incidents")

                    # Run ML predictions
                    with st.spinner("Running ML analysis..."):
                        predictor = ThreatPredictor()
                        ml_results = predictor.predict_source_ips(df)
                        st.session_state.ml_results = ml_results
                        st.success(f"ML analysis complete")

                    st.session_state.logs_loaded = True
                    st.success("✅ Analysis pipeline complete! Navigate to Dashboard or Threat Detection.")

                except Exception as e:
                    st.error(f"Error loading sample data: {str(e)}")

    with tab2:
        st.subheader("Upload Custom Log File")

        uploaded_file = st.file_uploader("Choose a log file", type=['txt'])

        if uploaded_file is not None:
            if st.button("Parse and Analyze", type="primary"):
                with st.spinner("Parsing uploaded file..."):
                    parser = LogParser()

                    try:
                        # Save uploaded file temporarily
                        temp_path = "data/uploaded_logs.txt"
                        with open(temp_path, 'wb') as f:
                            f.write(uploaded_file.getvalue())

                        parsed_logs, stats = parser.parse_file(temp_path)

                        st.success(f"Parsed {stats['parsed']:,} events successfully!")

                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Total Lines", stats['total'])
                        with col2:
                            st.metric("Successfully Parsed", stats['parsed'])
                        with col3:
                            st.metric("Failed/Invalid", stats['failed'])

                        if stats['failed'] > 0:
                            st.warning(f"Failed to parse {stats['failed']} records.")

                        # Clear and insert
                        db.clear_all_events()
                        db.clear_alerts()
                        db.clear_incidents()

                        inserted = db.insert_logs_batch(parsed_logs)
                        st.success(f"Stored {inserted:,} events")

                        # Run analysis pipeline
                        with st.spinner("Running full analysis..."):
                            df = db.get_logs_as_dataframe()
                            detector = ThreatDetectionEngine(df)
                            alerts = detector.run_all_detections()
                            st.session_state.alerts = alerts
                            st.session_state.current_df = df

                            for alert in alerts:
                                db.insert_alert({
                                    'alert_type': alert.alert_type,
                                    'source_ip': alert.source_ip,
                                    'destination_ip': alert.destination_ip,
                                    'destination_port': alert.destination_port,
                                    'severity': alert.severity,
                                    'risk_score': alert.risk_score,
                                    'event_count': alert.event_count,
                                    'first_seen': alert.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
                                    'last_seen': alert.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
                                    'explanation': alert.explanation,
                                    'recommendation': alert.recommendation
                                })

                            correlator = IncidentCorrelator(alerts, df)
                            incidents = correlator.correlate_incidents()
                            st.session_state.incidents = incidents

                            for incident in incidents:
                                db.insert_incident({
                                    'incident_type': incident.incident_type,
                                    'source_ip': incident.source_ip,
                                    'destination_ip': incident.destination_ip,
                                    'severity': incident.severity,
                                    'risk_score': incident.risk_score,
                                    'status': incident.status,
                                    'first_seen': incident.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
                                    'last_seen': incident.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
                                    'event_count': incident.event_count,
                                    'alert_count': incident.alert_count,
                                    'summary': incident.summary,
                                    'recommendation': incident.recommendation
                                })

                            predictor = ThreatPredictor()
                            ml_results = predictor.predict_source_ips(df)
                            st.session_state.ml_results = ml_results

                        st.session_state.logs_loaded = True
                        st.success("✅ Upload and analysis complete!")

                    except Exception as e:
                        st.error(f"Error processing file: {str(e)}")
