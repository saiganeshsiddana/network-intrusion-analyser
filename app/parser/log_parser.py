"""
Network Log Parser

Parses firewall/network log entries using regex.
Validates and normalizes log data into structured format.
"""

import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ParsedLog:
    """Structured representation of a parsed log entry."""
    timestamp: datetime
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    action: str
    raw_log: str
    is_valid: bool = True
    error_message: Optional[str] = None


class LogParser:
    """
    Parses network logs from text format.

    Expected format:
    YYYY-MM-DD HH:MM:SS SOURCE_IP:PORT -> DEST_IP:PORT PROTOCOL ACTION

    Example:
    2024-10-01 09:00:01 203.0.113.5:45123 -> 10.0.1.15:443 TCP ALLOW
    """

    def __init__(self):
        # Regex pattern for log format
        self.log_pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'  # Timestamp
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)\s+->\s+'  # Source IP:Port
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)\s+'  # Dest IP:Port
            r'(TCP|UDP|ICMP)\s+'  # Protocol
            r'(ALLOW|DENY)'  # Action
        )

        # IP validation regex
        self.ip_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )

        self.stats = {
            'total': 0,
            'parsed': 0,
            'failed': 0,
            'invalid_ip': 0,
            'invalid_port': 0,
            'invalid_timestamp': 0,
            'malformed': 0
        }

    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format and range."""
        if not self.ip_pattern.match(ip):
            return False

        octets = ip.split('.')
        for octet in octets:
            if int(octet) > 255:
                return False
        return True

    def validate_port(self, port: int) -> bool:
        """Validate port number range."""
        return 1 <= port <= 65535

    def validate_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse and validate timestamp."""
        try:
            return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None

    def parse_line(self, line: str) -> ParsedLog:
        """
        Parse a single log line.

        Returns ParsedLog object with validation status.
        """
        self.stats['total'] += 1

        line = line.strip()
        if not line:
            self.stats['failed'] += 1
            return ParsedLog(
                timestamp=datetime.now(),
                source_ip="",
                source_port=0,
                destination_ip="",
                destination_port=0,
                protocol="",
                action="",
                raw_log=line,
                is_valid=False,
                error_message="Empty line"
            )

        match = self.log_pattern.match(line)

        if not match:
            self.stats['failed'] += 1
            self.stats['malformed'] += 1
            return ParsedLog(
                timestamp=datetime.now(),
                source_ip="",
                source_port=0,
                destination_ip="",
                destination_port=0,
                protocol="",
                action="",
                raw_log=line,
                is_valid=False,
                error_message="Malformed log entry"
            )

        # Extract components
        timestamp_str, src_ip, src_port_str, dst_ip, dst_port_str, protocol, action = match.groups()

        # Validate timestamp
        timestamp = self.validate_timestamp(timestamp_str)
        if not timestamp:
            self.stats['failed'] += 1
            self.stats['invalid_timestamp'] += 1
            return ParsedLog(
                timestamp=datetime.now(),
                source_ip=src_ip,
                source_port=int(src_port_str),
                destination_ip=dst_ip,
                destination_port=int(dst_port_str),
                protocol=protocol,
                action=action,
                raw_log=line,
                is_valid=False,
                error_message="Invalid timestamp format"
            )

        # Validate IPs
        if not self.validate_ip(src_ip):
            self.stats['failed'] += 1
            self.stats['invalid_ip'] += 1
            return ParsedLog(
                timestamp=timestamp,
                source_ip=src_ip,
                source_port=int(src_port_str),
                destination_ip=dst_ip,
                destination_port=int(dst_port_str),
                protocol=protocol,
                action=action,
                raw_log=line,
                is_valid=False,
                error_message=f"Invalid source IP: {src_ip}"
            )

        if not self.validate_ip(dst_ip):
            self.stats['failed'] += 1
            self.stats['invalid_ip'] += 1
            return ParsedLog(
                timestamp=timestamp,
                source_ip=src_ip,
                source_port=int(src_port_str),
                destination_ip=dst_ip,
                destination_port=int(dst_port_str),
                protocol=protocol,
                action=action,
                raw_log=line,
                is_valid=False,
                error_message=f"Invalid destination IP: {dst_ip}"
            )

        # Validate ports
        src_port = int(src_port_str)
        dst_port = int(dst_port_str)

        if not self.validate_port(src_port):
            self.stats['failed'] += 1
            self.stats['invalid_port'] += 1
            return ParsedLog(
                timestamp=timestamp,
                source_ip=src_ip,
                source_port=src_port,
                destination_ip=dst_ip,
                destination_port=dst_port,
                protocol=protocol,
                action=action,
                raw_log=line,
                is_valid=False,
                error_message=f"Invalid source port: {src_port}"
            )

        if not self.validate_port(dst_port):
            self.stats['failed'] += 1
            self.stats['invalid_port'] += 1
            return ParsedLog(
                timestamp=timestamp,
                source_ip=src_ip,
                source_port=src_port,
                destination_ip=dst_ip,
                destination_port=dst_port,
                protocol=protocol,
                action=action,
                raw_log=line,
                is_valid=False,
                error_message=f"Invalid destination port: {dst_port}"
            )

        # Successfully parsed and validated
        self.stats['parsed'] += 1
        return ParsedLog(
            timestamp=timestamp,
            source_ip=src_ip,
            source_port=src_port,
            destination_ip=dst_ip,
            destination_port=dst_port,
            protocol=protocol,
            action=action,
            raw_log=line,
            is_valid=True
        )

    def parse_file(self, file_path: str) -> Tuple[List[ParsedLog], Dict]:
        """
        Parse entire log file.

        Returns:
            Tuple of (list of ParsedLog objects, statistics dict)
        """
        parsed_logs = []

        # Reset stats
        self.stats = {
            'total': 0,
            'parsed': 0,
            'failed': 0,
            'invalid_ip': 0,
            'invalid_port': 0,
            'invalid_timestamp': 0,
            'malformed': 0
        }

        try:
            with open(file_path, 'r') as f:
                for line in f:
                    parsed_log = self.parse_line(line)
                    parsed_logs.append(parsed_log)

        except FileNotFoundError:
            raise FileNotFoundError(f"Log file not found: {file_path}")
        except Exception as e:
            raise Exception(f"Error reading log file: {str(e)}")

        return parsed_logs, self.stats.copy()

    def get_stats(self) -> Dict:
        """Get current parsing statistics."""
        return self.stats.copy()

    def reset_stats(self):
        """Reset parsing statistics."""
        self.stats = {
            'total': 0,
            'parsed': 0,
            'failed': 0,
            'invalid_ip': 0,
            'invalid_port': 0,
            'invalid_timestamp': 0,
            'malformed': 0
        }
