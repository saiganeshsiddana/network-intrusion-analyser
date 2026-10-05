"""
Analytics Module

Provides Pandas-based analysis of network log data.
Generates statistics, aggregations, and time-series analysis.
"""

import pandas as pd
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta


class NetworkAnalytics:
    """Analytics engine for network log data."""

    def __init__(self, df: pd.DataFrame):
        """
        Initialize analytics with a DataFrame of network events.

        Expected columns: id, timestamp, source_ip, destination_ip,
                         source_port, destination_port, protocol, action
        """
        self.df = df
        if not df.empty and 'timestamp' in df.columns:
            self.df['timestamp'] = pd.to_datetime(df['timestamp'])

    def get_summary_stats(self) -> Dict:
        """Get overall summary statistics."""
        if self.df.empty:
            return {
                'total_events': 0,
                'allowed_events': 0,
                'denied_events': 0,
                'unique_source_ips': 0,
                'unique_destination_ips': 0,
                'unique_destination_ports': 0,
                'protocols': {},
                'time_range': None
            }

        return {
            'total_events': len(self.df),
            'allowed_events': len(self.df[self.df['action'] == 'ALLOW']),
            'denied_events': len(self.df[self.df['action'] == 'DENY']),
            'unique_source_ips': self.df['source_ip'].nunique(),
            'unique_destination_ips': self.df['destination_ip'].nunique(),
            'unique_destination_ports': self.df['destination_port'].nunique(),
            'protocols': self.df['protocol'].value_counts().to_dict(),
            'time_range': {
                'start': self.df['timestamp'].min(),
                'end': self.df['timestamp'].max()
            }
        }

    def get_top_source_ips(self, top_n: int = 10) -> pd.DataFrame:
        """Get top source IPs by event count."""
        if self.df.empty:
            return pd.DataFrame()

        top_ips = self.df.groupby('source_ip').agg({
            'id': 'count',
            'action': lambda x: (x == 'ALLOW').sum(),
            'destination_port': 'nunique'
        }).rename(columns={
            'id': 'total_events',
            'action': 'allowed_events',
            'destination_port': 'unique_ports'
        })

        top_ips['denied_events'] = top_ips['total_events'] - top_ips['allowed_events']
        top_ips = top_ips.sort_values('total_events', ascending=False).head(top_n)
        return top_ips.reset_index()

    def get_top_destination_ips(self, top_n: int = 10) -> pd.DataFrame:
        """Get top destination IPs by event count."""
        if self.df.empty:
            return pd.DataFrame()

        top_ips = self.df.groupby('destination_ip').agg({
            'id': 'count',
            'action': lambda x: (x == 'ALLOW').sum(),
            'source_ip': 'nunique'
        }).rename(columns={
            'id': 'total_events',
            'action': 'allowed_events',
            'source_ip': 'unique_sources'
        })

        top_ips['denied_events'] = top_ips['total_events'] - top_ips['allowed_events']
        top_ips = top_ips.sort_values('total_events', ascending=False).head(top_n)
        return top_ips.reset_index()

    def get_top_destination_ports(self, top_n: int = 15) -> pd.DataFrame:
        """Get most targeted destination ports."""
        if self.df.empty:
            return pd.DataFrame()

        port_stats = self.df.groupby('destination_port').agg({
            'id': 'count',
            'action': lambda x: (x == 'ALLOW').sum(),
            'source_ip': 'nunique'
        }).rename(columns={
            'id': 'total_attempts',
            'action': 'allowed',
            'source_ip': 'unique_sources'
        })

        port_stats['denied'] = port_stats['total_attempts'] - port_stats['allowed']
        port_stats = port_stats.sort_values('total_attempts', ascending=False).head(top_n)
        return port_stats.reset_index()

    def get_protocol_distribution(self) -> Dict:
        """Get protocol distribution."""
        if self.df.empty:
            return {}
        return self.df['protocol'].value_counts().to_dict()

    def get_action_distribution(self) -> Dict:
        """Get ALLOW vs DENY distribution."""
        if self.df.empty:
            return {}
        return self.df['action'].value_counts().to_dict()

    def get_traffic_over_time(self, interval: str = '5min') -> pd.DataFrame:
        """
        Get traffic aggregated over time intervals.

        Args:
            interval: Pandas frequency string ('1min', '5min', '1H', etc.)
        """
        if self.df.empty or 'timestamp' not in self.df.columns:
            return pd.DataFrame()

        df_time = self.df.set_index('timestamp')

        traffic = df_time.groupby([pd.Grouper(freq=interval), 'action']).size().unstack(fill_value=0)

        if 'ALLOW' not in traffic.columns:
            traffic['ALLOW'] = 0
        if 'DENY' not in traffic.columns:
            traffic['DENY'] = 0

        traffic = traffic.reset_index()
        return traffic

    def get_denied_traffic_over_time(self, interval: str = '5min') -> pd.DataFrame:
        """Get denied traffic over time."""
        if self.df.empty:
            return pd.DataFrame()

        denied_df = self.df[self.df['action'] == 'DENY'].copy()
        if denied_df.empty:
            return pd.DataFrame()

        denied_df.set_index('timestamp', inplace=True)
        denied_traffic = denied_df.groupby(pd.Grouper(freq=interval)).size()
        return denied_traffic.reset_index(name='denied_count')

    def analyze_source_ip(self, source_ip: str) -> Dict:
        """Detailed analysis of a specific source IP."""
        ip_df = self.df[self.df['source_ip'] == source_ip]

        if ip_df.empty:
            return {
                'ip': source_ip,
                'found': False
            }

        return {
            'ip': source_ip,
            'found': True,
            'total_events': len(ip_df),
            'allowed_events': len(ip_df[ip_df['action'] == 'ALLOW']),
            'denied_events': len(ip_df[ip_df['action'] == 'DENY']),
            'unique_destinations': ip_df['destination_ip'].nunique(),
            'unique_ports': ip_df['destination_port'].nunique(),
            'protocols': ip_df['protocol'].value_counts().to_dict(),
            'first_seen': ip_df['timestamp'].min(),
            'last_seen': ip_df['timestamp'].max(),
            'top_ports': ip_df['destination_port'].value_counts().head(10).to_dict(),
            'top_destinations': ip_df['destination_ip'].value_counts().head(10).to_dict()
        }

    def get_high_deny_sources(self, min_denies: int = 10) -> pd.DataFrame:
        """Get source IPs with high number of denied connections."""
        if self.df.empty:
            return pd.DataFrame()

        denied_df = self.df[self.df['action'] == 'DENY']

        if denied_df.empty:
            return pd.DataFrame()

        deny_counts = denied_df.groupby('source_ip').agg({
            'id': 'count',
            'destination_port': 'nunique',
            'destination_ip': 'nunique'
        }).rename(columns={
            'id': 'denied_count',
            'destination_port': 'unique_ports',
            'destination_ip': 'unique_destinations'
        })

        deny_counts = deny_counts[deny_counts['denied_count'] >= min_denies]
        deny_counts = deny_counts.sort_values('denied_count', ascending=False)
        return deny_counts.reset_index()

    def get_port_scan_candidates(self, min_unique_ports: int = 10) -> pd.DataFrame:
        """
        Identify potential port scanning behavior.
        Sources that contact many different ports.
        """
        if self.df.empty:
            return pd.DataFrame()

        port_diversity = self.df.groupby('source_ip').agg({
            'destination_port': 'nunique',
            'id': 'count',
            'action': lambda x: (x == 'DENY').sum()
        }).rename(columns={
            'destination_port': 'unique_ports',
            'id': 'total_events',
            'action': 'denied_events'
        })

        candidates = port_diversity[port_diversity['unique_ports'] >= min_unique_ports]
        candidates = candidates.sort_values('unique_ports', ascending=False)
        return candidates.reset_index()

    def get_connection_frequency(self, source_ip: str, time_window_minutes: int = 5) -> List[Dict]:
        """
        Analyze connection frequency for a source IP within time windows.
        Returns list of high-frequency periods.
        """
        ip_df = self.df[self.df['source_ip'] == source_ip].copy()

        if ip_df.empty:
            return []

        ip_df.set_index('timestamp', inplace=True)

        # Count connections per time window
        freq = ip_df.groupby(pd.Grouper(freq=f'{time_window_minutes}min')).size()

        # Identify high-frequency windows (>= 20 connections per window)
        high_freq = freq[freq >= 20]

        results = []
        for timestamp, count in high_freq.items():
            results.append({
                'timestamp': timestamp,
                'connection_count': int(count),
                'window_minutes': time_window_minutes
            })

        return results
