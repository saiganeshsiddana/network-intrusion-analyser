"""
Synthetic Network Log Data Generator

Generates realistic firewall/network logs for demonstration purposes.
Includes normal traffic and suspicious patterns (port scanning, brute force, etc.)
"""

import random
import datetime
from pathlib import Path
from typing import List, Tuple


class LogGenerator:
    """Generates synthetic network logs with realistic patterns."""

    def __init__(self):
        # Internal network ranges
        self.internal_ips = [f"10.0.{random.randint(0,10)}.{random.randint(1,254)}"
                            for _ in range(20)]

        # External IPs (some suspicious, some normal)
        self.external_ips = [
            f"203.0.113.{i}" for i in range(1, 11)  # Normal external
        ] + [
            f"198.51.100.{i}" for i in range(20, 30)  # Suspicious sources
        ] + [
            f"192.0.2.{i}" for i in range(50, 60)  # Potential scanners
        ]

        # Common legitimate services
        self.common_ports = [80, 443, 22, 25, 53, 3306, 5432, 8080, 8443]

        # Protocols
        self.protocols = ["TCP", "UDP", "ICMP"]

        # Actions
        self.actions = ["ALLOW", "DENY"]

    def generate_timestamp(self, base_time: datetime.datetime, offset_seconds: int) -> str:
        """Generate timestamp with offset."""
        timestamp = base_time + datetime.timedelta(seconds=offset_seconds)
        return timestamp.strftime("%Y-%m-%d %H:%M:%S")

    def generate_normal_traffic(self, count: int, base_time: datetime.datetime) -> List[str]:
        """Generate normal network traffic patterns."""
        logs = []
        time_offset = 0

        for _ in range(count):
            src_ip = random.choice(self.internal_ips + self.external_ips[:10])
            dst_ip = random.choice(self.internal_ips)
            src_port = random.randint(1024, 65535)
            dst_port = random.choice(self.common_ports)
            protocol = random.choice(["TCP", "UDP"])
            action = "ALLOW" if random.random() > 0.1 else "DENY"  # 90% allowed

            timestamp = self.generate_timestamp(base_time, time_offset)
            log = f"{timestamp} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {protocol} {action}"
            logs.append(log)

            time_offset += random.randint(1, 10)

        return logs

    def generate_port_scan(self, base_time: datetime.datetime, start_offset: int) -> List[str]:
        """Generate port scanning pattern."""
        logs = []
        scanner_ip = random.choice(self.external_ips[10:])  # Suspicious IP
        target_ip = random.choice(self.internal_ips)
        src_port = random.randint(40000, 50000)

        # Scan common ports rapidly
        ports_to_scan = list(range(20, 100)) + [139, 445, 3389, 5900, 8080]
        random.shuffle(ports_to_scan)

        time_offset = start_offset
        for port in ports_to_scan[:50]:  # Scan 50 ports
            timestamp = self.generate_timestamp(base_time, time_offset)
            protocol = "TCP"
            action = "DENY"  # Most scan attempts denied

            log = f"{timestamp} {scanner_ip}:{src_port} -> {target_ip}:{port} {protocol} {action}"
            logs.append(log)

            time_offset += random.uniform(0.1, 2)  # Rapid scanning

        return logs

    def generate_brute_force(self, base_time: datetime.datetime, start_offset: int) -> List[str]:
        """Generate brute force pattern (repeated connection attempts)."""
        logs = []
        attacker_ip = random.choice(self.external_ips[10:])
        target_ip = random.choice(self.internal_ips)
        target_port = 22  # SSH

        time_offset = start_offset
        for _ in range(100):  # 100 attempts
            src_port = random.randint(30000, 40000)
            timestamp = self.generate_timestamp(base_time, time_offset)
            protocol = "TCP"
            action = "DENY"

            log = f"{timestamp} {attacker_ip}:{src_port} -> {target_ip}:{target_port} {protocol} {action}"
            logs.append(log)

            time_offset += random.uniform(0.5, 3)

        return logs

    def generate_high_frequency(self, base_time: datetime.datetime, start_offset: int) -> List[str]:
        """Generate high-frequency connection pattern."""
        logs = []
        source_ip = random.choice(self.external_ips[15:])
        target_ip = random.choice(self.internal_ips)
        target_port = random.choice([80, 443])

        time_offset = start_offset
        for _ in range(200):  # Rapid connections
            src_port = random.randint(20000, 30000)
            timestamp = self.generate_timestamp(base_time, time_offset)
            protocol = "TCP"
            action = random.choice(["ALLOW", "DENY"])

            log = f"{timestamp} {source_ip}:{src_port} -> {target_ip}:{target_port} {protocol} {action}"
            logs.append(log)

            time_offset += random.uniform(0.1, 0.5)  # Very rapid

        return logs

    def generate_dataset(self, output_path: str, total_events: int = 10000):
        """Generate complete dataset with mixed traffic."""
        print(f"Generating {total_events} log events...")

        base_time = datetime.datetime(2024, 10, 1, 9, 0, 0)
        all_logs = []

        # Calculate distribution
        normal_count = int(total_events * 0.70)  # 70% normal
        port_scan_instances = 3
        brute_force_instances = 2
        high_freq_instances = 2

        # Generate normal traffic
        print("Generating normal traffic...")
        all_logs.extend(self.generate_normal_traffic(normal_count, base_time))

        # Generate suspicious patterns at different times
        print("Generating port scanning patterns...")
        for i in range(port_scan_instances):
            offset = random.randint(1000, 8000)
            all_logs.extend(self.generate_port_scan(base_time, offset))

        print("Generating brute force patterns...")
        for i in range(brute_force_instances):
            offset = random.randint(2000, 7000)
            all_logs.extend(self.generate_brute_force(base_time, offset))

        print("Generating high-frequency patterns...")
        for i in range(high_freq_instances):
            offset = random.randint(3000, 6000)
            all_logs.extend(self.generate_high_frequency(base_time, offset))

        # Sort by timestamp for realism
        print("Sorting logs by timestamp...")
        all_logs.sort(key=lambda x: x.split()[0:2])

        # Write to file
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        print(f"Writing logs to {output_path}...")
        with open(output_path, 'w') as f:
            for log in all_logs:
                f.write(log + '\n')

        print(f"[OK] Generated {len(all_logs)} log entries")
        print(f"  - Normal traffic: ~{normal_count}")
        print(f"  - Port scans: {port_scan_instances} instances")
        print(f"  - Brute force: {brute_force_instances} instances")
        print(f"  - High frequency: {high_freq_instances} instances")
        print(f"\nDataset saved to: {output_path}")


if __name__ == "__main__":
    generator = LogGenerator()
    generator.generate_dataset("data/sample/network_logs.txt", total_events=10000)
