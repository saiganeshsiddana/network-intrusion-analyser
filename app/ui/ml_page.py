"""ML Analysis UI Module."""

import streamlit as st
import plotly.express as px
import pandas as pd


def show(db, ml_results):
    st.markdown('<p class="main-header">🤖 Machine Learning Analysis</p>', unsafe_allow_html=True)

    st.markdown("""
    This page shows ML-based threat classification results using a Random Forest classifier.

    **Important:** The ML model is trained on **synthetic labeled data** for educational purposes.
    In production, use real historical labeled attack data.
    """)

    if ml_results.empty:
        st.info("No ML analysis available. Upload and analyze logs first.")
        return

    # Model info
    st.subheader("📊 Model Information")
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Model Type", "Random Forest")
    with col2:
        st.metric("Training Data", "Synthetic")
    with col3:
        suspicious_count = len(ml_results[ml_results['ml_prediction'] == 1])
        st.metric("Suspicious IPs", suspicious_count)

    st.markdown("---")

    # Prediction distribution
    st.subheader("🎯 Prediction Distribution")
    col4, col5 = st.columns(2)

    with col4:
        pred_counts = ml_results['ml_label'].value_counts()
        fig = px.pie(values=pred_counts.values, names=pred_counts.index,
                     color=pred_counts.index,
                     color_discrete_map={'Suspicious': '#d62728', 'Normal': '#2ca02c'})
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)

    with col5:
        st.markdown("**Classification Summary:**")
        st.write(f"- Normal IPs: {len(ml_results[ml_results['ml_prediction'] == 0])}")
        st.write(f"- Suspicious IPs: {len(ml_results[ml_results['ml_prediction'] == 1])}")
        avg_confidence = ml_results['ml_confidence'].mean()
        st.write(f"- Average Confidence: {avg_confidence:.2%}")

    # Feature importance
    st.subheader("📈 Feature Importance")
    from app.ml.predict import ThreatPredictor
    predictor = ThreatPredictor()
    feature_importance = predictor.get_feature_importance()

    if feature_importance:
        feat_df = pd.DataFrame(list(feature_importance.items()),
                              columns=['Feature', 'Importance'])
        feat_df = feat_df.sort_values('Importance', ascending=False)

        fig = px.bar(feat_df, x='Importance', y='Feature', orientation='h')
        fig.update_layout(height=400, yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig, use_container_width=True)

    # Top suspicious IPs by ML
    st.subheader("🔴 Top Suspicious IPs (ML Predictions)")
    suspicious = ml_results[ml_results['ml_prediction'] == 1].head(15)

    if not suspicious.empty:
        display_cols = ['source_ip', 'ml_threat_probability', 'total_connections',
                       'denied_connections', 'unique_dst_ports', 'connections_per_minute']
        st.dataframe(suspicious[display_cols], use_container_width=True)
    else:
        st.success("No suspicious IPs detected by ML model.")

    # Detailed results
    with st.expander("View All ML Results"):
        st.dataframe(ml_results, use_container_width=True, height=400)
