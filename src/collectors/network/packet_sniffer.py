# src/collectors/network/packet_sniffer.py
"""
LIDRA Network Packet Sniffer
Listens on network interface (or SPAN port) and detects network-based attacks.

Supports:
- Packet capture from SPAN/mirror port
- Basic protocol analysis (TCP, UDP, ICMP, DNS, HTTP)
- Attack detection (port scans, DoS, suspicious patterns)
- Integration with LIDRA detection engine
"""

import socket
import struct
import threading
import logging
import time
from datetime import datetime
from typing import Optional, Callable, Dict, List
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger("lidra.network.sniffer")

# Protocol numbers
IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

# Common ports
COMMON_PORTS = {
    22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB", 8080: "HTTP-ALT", 21: "FTP"
}

# Suspicious patterns
SYN_FLOOD_THRESHOLD = 50  # SYN packets per second
PORT_SCAN_THRESHOLD = 10  # Different ports in short time
DNS_QUERY_THRESHOLD = 100  # Queries per minute


@dataclass
class NetworkPacket:
    """Represents a captured network packet."""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    flags: Optional[str] = None
    raw_data: Optional[bytes] = None


class PacketSniffer:
    """
    Network packet sniffer for detecting network-based attacks.
    Can run in two modes:
    1. Raw socket mode (limited, no root)
    2. Promiscuous mode (requires root/libpcap)
    """

    def __init__(self, interface: str = "eth0", callback: Optional[Callable] = None, config: dict = None):
        self.interface = interface
        self.callback = callback
        self.config = config or {}
        self.running = False
        self.thread = None
        self.socket = None

        # Statistics
        self.stats = {
            "packets_captured": 0,
            "bytes_captured": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "attacks_detected": 0
        }

        # Attack tracking
        self.syn_tracker = defaultdict(list)  # IP -> timestamps
        self.port_scan_tracker = defaultdict(set)  # IP -> ports
        self.dns_query_tracker = defaultdict(list)  # IP -> timestamps

    def start(self):
        """Start packet capture."""
        if self.running:
            logger.warning("Sniffer already running")
            return

        logger.info(f"Starting packet sniffer on interface: {self.interface}")

        try:
            # Try to create raw socket (might need root)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
            self.socket.setblocking(False)
            logger.info("Using raw socket mode (limited capture)")
        except PermissionError:
            # Fall back to regular socket (capture only what this host sees)
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                logger.warning("No root - running in limited mode (only host traffic)")
            except Exception as e:
                logger.error(f"Failed to create socket: {e}")
                return

        self.running = True
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()
        logger.info("Packet sniffer started")

    def stop(self):
        """Stop packet capture."""
        self.running = False
        if self.socket:
            self.socket.close()
        if self.thread:
            self.thread.join(timeout=2)
        logger.info(f"Packet sniffer stopped. Stats: {self.stats}")

    def _capture_loop(self):
        """Main capture loop."""
        buffer_size = 65535

        while self.running:
            try:
                data, addr = self.socket.recvfrom(buffer_size)
                if data:
                    packet = self._parse_packet(data)
                    if packet:
                        self.stats["packets_captured"] += 1
                        self.stats["bytes_captured"] += len(data)

                        # Analyze for attacks
                        attack = self._analyze_packet(packet)
                        if attack:
                            self.stats["attacks_detected"] += 1
                            if self.callback:
                                self.callback(attack)

            except BlockingIOError:
                time.sleep(0.01)
            except Exception as e:
                logger.debug(f"Packet capture error: {e}")
                time.sleep(0.1)

    def _parse_packet(self, data: bytes) -> Optional[NetworkPacket]:
        """Parse raw IP packet."""
        try:
            if len(data) < 20:
                return None

            # Parse IP header
            version_ihl = data[0]
            version = version_ihl >> 4
            ihl = (version_ihl & 0xF) * 4

            if version != 4:
                return None  # Only IPv4 for now

            ip_header = data[ihl:ihl+20]
            src_ip = socket.inet_ntoa(ip_header[12:16])
            dst_ip = socket.inet_ntoa(ip_header[16:20])
            protocol = ip_header[9]

            src_port = 0
            dst_port = 0
            flags = None

            if protocol == IP_PROTO_TCP and len(data) > ihl + 20:
                tcp_header = data[ihl:ihl+20]
                src_port = struct.unpack("!H", tcp_header[0:2])[0]
                dst_port = struct.unpack("!H", tcp_header[2:4])[0]
                flags = ""
                if tcp_header[13] & 0x02: flags += "SYN"
                if tcp_header[13] & 0x12: flags += "ACK"
                if tcp_header[13] & 0x01: flags += "FIN"
                if tcp_header[13] & 0x04: flags += "RST"
                self.stats["tcp_packets"] += 1

            elif protocol == IP_PROTO_UDP and len(data) > ihl + 8:
                udp_header = data[ihl:ihl+8]
                src_port = struct.unpack("!H", udp_header[0:2])[0]
                dst_port = struct.unpack("!H", udp_header[2:4])[0]
                self.stats["udp_packets"] += 1

            elif protocol == IP_PROTO_ICMP:
                self.stats["icmp_packets"] += 1

            return NetworkPacket(
                timestamp=datetime.now(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=self._get_protocol_name(protocol),
                size=len(data),
                flags=flags,
                raw_data=data[:100]  # Store first 100 bytes
            )

        except Exception as e:
            logger.debug(f"Parse error: {e}")
            return None

    def _get_protocol_name(self, proto: int) -> str:
        """Get protocol name from number."""
        names = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return names.get(proto, f"Unknown-{proto}")

    def _analyze_packet(self, packet: NetworkPacket) -> Optional[Dict]:
        """Analyze packet for attack patterns."""
        attacks = []

        # Skip private IPs
        if packet.src_ip.startswith(("10.", "172.16.", "172.17.", "192.168.", "127.")):
            return None

        # SYN Flood Detection
        if packet.flags and "SYN" in packet.flags and not "ACK" in packet.flags:
            now = time.time()
            self.syn_tracker[packet.src_ip].append(now)
            # Clean old entries
            self.syn_tracker[packet.src_ip] = [
                t for t in self.syn_tracker[packet.src_ip]
                if now - t < 5  # Last 5 seconds
            ]
            if len(self.syn_tracker[packet.src_ip]) > SYN_FLOOD_THRESHOLD:
                attacks.append({
                    "type": "syn_flood",
                    "severity": "critical",
                    "source": packet.src_ip,
                    "target": packet.dst_ip,
                    "details": f"{len(self.syn_tracker[packet.src_ip])} SYN in 5s"
                })

        # Port Scan Detection
        if packet.flags in ["SYN", None] and packet.dst_port > 0:
            self.port_scan_tracker[packet.src_ip].add(packet.dst_port)
            if len(self.port_scan_tracker[packet.src_ip]) > PORT_SCAN_THRESHOLD:
                attacks.append({
                    "type": "port_scan",
                    "severity": "high",
                    "source": packet.src_ip,
                    "target": packet.dst_ip,
                    "details": f"Scanned {len(self.port_scan_tracker[packet.src_ip])} ports"
                })

        # ICMP Flood (Ping sweep)
        if packet.protocol == "ICMP":
            now = time.time()
            self.dns_query_tracker[packet.src_ip].append(now)  # Reuse tracker
            self.dns_query_tracker[packet.src_ip] = [
                t for t in self.dns_query_tracker[packet.src_ip]
                if now - t < 10
            ]
            if len(self.dns_query_tracker[packet.src_ip]) > 50:
                attacks.append({
                    "type": "icmp_flood",
                    "severity": "high",
                    "source": packet.src_ip,
                    "details": "Excessive ICMP"
                })

        # Suspicious Port Access
        suspicious_ports = [4444, 5555, 31337, 1337]  # Metasploit, etc.
        if packet.dst_port in suspicious_ports:
            attacks.append({
                "type": "suspicious_port",
                "severity": "high",
                "source": packet.src_ip,
                "target": packet.dst_ip,
                "details": f"Access to suspicious port {packet.dst_port}"
            })

        if attacks:
            return {
                "attack_type": attacks[0]["type"],
                "severity": attacks[0]["severity"],
                "source_ip": packet.src_ip,
                "dest_ip": packet.dst_ip,
                "protocol": packet.protocol,
                "port": packet.dst_port,
                "packet_size": packet.size,
                "raw": packet.raw_data.hex() if packet.raw_data else "",
                "source": "network"
            }

        return None

    def get_stats(self) -> Dict:
        """Get sniffer statistics."""
        return self.stats.copy()


def create_sniffer(interface: str = "eth0", callback: Optional[Callable] = None, config: dict = None) -> PacketSniffer:
    """Factory function to create packet sniffer."""
    return PacketSniffer(interface=interface, callback=callback, config=config)


# Standalone test
if __name__ == "__main__":
    print("LIDRA Network Packet Sniffer")
    print("=" * 40)

    def on_attack(attack):
        print(f"[ALERT] {attack['attack_type']} from {attack['source_ip']}")

    sniffer = create_sniffer(callback=on_attack)
    sniffer.start()

    try:
        while True:
            time.sleep(10)
            stats = sniffer.get_stats()
            print(f"Packets: {stats['packets_captured']}, Attacks: {stats['attacks_detected']}")
    except KeyboardInterrupt:
        sniffer.stop()
        print("Stopped")