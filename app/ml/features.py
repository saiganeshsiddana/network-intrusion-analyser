"""
Machine Learning Feature Engineering

Extracts features from network traffic for ML-based threat detection.
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Tuple


class FeatureEngineer:
    """Extracts ML features from network log data."""

    def __init__(self, df: pd.DataFrame):
        """
        Initialize with network events DataFrame.

        Expected columns: timestamp, source_ip, destination_ip,
                         source_port, destination_port, protocol, action
        """
        self.df = df
        if not df.empty and 'timestamp' in df.columns:
            self.df['timestamp'] = pd.to_datetime(df['timestamp'])

    def extract_features_per_source(self, time_window_minutes: int = 10) -> pd.DataFrame:
        """
        Extract behavioral features for each source IP.

        Features include:
        - Connection counts
        - Denied connection ratio
        - Unique destination ports
        - Unique destination IPs
        - Protocol diversity
        - Connection frequency
        - Port scan indicators
        """
        if self.df.empty:
            return pd.DataFrame()

        features_list = []

        for source_ip in self.df['source_ip'].unique():
            ip_df = self.df[self.df['source_ip'] == source_ip]

            # Basic counts
            total_connections = len(ip_df)
            denied_connections = len(ip_df[ip_df['action'] == 'DENY'])
            allowed_connections = len(ip_df[ip_df['action'] == 'ALLOW'])

            # Port and destination diversity
            unique_dst_ports = ip_df['destination_port'].nunique()
            unique_dst_ips = ip_df['destination_ip'].nunique()

            # Protocol distribution
            protocol_counts = ip_df['protocol'].value_counts()
            tcp_ratio = protocol_counts.get('TCP', 0) / total_connections if total_connections > 0 else 0
            udp_ratio = protocol_counts.get('UDP', 0) / total_connections if total_connections > 0 else 0

            # Time-based features
            time_span_minutes = (ip_df['timestamp'].max() - ip_df['timestamp'].min()).total_seconds() / 60
            if time_span_minutes == 0:
                time_span_minutes = 1  # Avoid division by zero

            connections_per_minute = total_connections / time_span_minutes

            # Ratios
            deny_ratio = denied_connections / total_connections if total_connections > 0 else 0
            port_diversity_ratio = unique_dst_ports / total_connections if total_connections > 0 else 0

            # Port scanning indicator
            port_scan_score = min(1.0, unique_dst_ports / 50.0)  # Normalize to 0-1

            # Suspicious port access (common attack targets)
            suspicious_ports = [22, 23, 445, 3389, 5900]
            suspicious_port_attempts = len(ip_df[ip_df['destination_port'].isin(suspicious_ports)])
            suspicious_port_ratio = suspicious_port_attempts / total_connections if total_connections > 0 else 0

            features = {
                'source_ip': source_ip,
                'total_connections': total_connections,
                'denied_connections': denied_connections,
                'allowed_connections': allowed_connections,
                'deny_ratio': deny_ratio,
                'unique_dst_ports': unique_dst_ports,
                'unique_dst_ips': unique_dst_ips,
                'port_diversity_ratio': port_diversity_ratio,
                'tcp_ratio': tcp_ratio,
                'udp_ratio': udp_ratio,
                'connections_per_minute': connections_per_minute,
                'time_span_minutes': time_span_minutes,
                'port_scan_score': port_scan_score,
                'suspicious_port_ratio': suspicious_port_ratio
            }

            features_list.append(features)

        return pd.DataFrame(features_list)

    def get_feature_names(self) -> List[str]:
        """Return list of feature names used for ML."""
        return [
            'total_connections',
            'denied_connections',
            'deny_ratio',
            'unique_dst_ports',
            'unique_dst_ips',
            'port_diversity_ratio',
            'tcp_ratio',
            'udp_ratio',
            'connections_per_minute',
            'port_scan_score',
            'suspicious_port_ratio'
        ]
