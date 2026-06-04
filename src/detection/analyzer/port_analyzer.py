import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

_KNOWN_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 123: "ntp", 143: "imap",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}


class PortAnalyzer:
    def __init__(self):
        self._port_scan_tracker: Dict[str, Set[int]] = defaultdict(set)
        self._port_scan_time: Dict[str, float] = {}
        self._service_mismatch: Dict[str, List[Tuple[int, str]]] = defaultdict(list)
        self._last_cleanup = time.time()
        self._lock = Lock()
        self._cleanup_interval = 60
        self._scan_threshold = 15
        self._window = 10

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        with self._lock:
            return self._analyze_locked(packet)
    def _analyze_locked(self, packet: Dict) -> Optional[List[Dict]]:
        detections = []
        self._cleanup_if_needed()

        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        dst_port = packet.get("dst_port", 0)
        src_port = packet.get("src_port", 0)
        protocol = packet.get("protocol", "")
        flags = packet.get("flags", "")

        scan_detection = self._check_port_scan(src_ip, dst_port, flags)
        if scan_detection:
            detections.append(scan_detection)

        hop_detection = self._check_port_hopping(src_ip, dst_ip, dst_port, protocol)
        if hop_detection:
            detections.append(hop_detection)

        service_detection = self._check_service_mismatch(
            src_ip, dst_port, src_port, protocol
        )
        if service_detection:
            detections.append(service_detection)

        return detections if detections else None

    def _check_port_scan(self, ip: str, port: int, flags: str) -> Optional[Dict]:
        now = time.time()
        elapsed = now - self._port_scan_time.get(ip, now)

        if "S" in flags and "A" in flags:
            self._port_scan_time[ip] = now
            return None

        if elapsed > self._window:
            self._port_scan_tracker[ip] = set()
            self._port_scan_time[ip] = now

        self._port_scan_tracker[ip].add(port)
        count = len(self._port_scan_tracker[ip])

        if count >= self._scan_threshold:
            ports_sorted = sorted(self._port_scan_tracker[ip])
            severity = "high" if count >= 50 else "medium"
            return {
                "attack_type": "port_scan",
                "severity": severity,
                "source_ip": ip,
                "details": f"Port scan: {count} ports [{ports_sorted[0]}-{ports_sorted[-1]}] in {elapsed:.1f}s",
            }
        return None

    def _check_port_hopping(self, src_ip: str, dst_ip: str, port: int, protocol: str) -> Optional[Dict]:
        now = time.time()
        key = (src_ip, dst_ip)
        self._port_scan_tracker[key].add(port)
        count = len(self._port_scan_tracker[key])

        if count >= 5 and count % 5 == 0:
            return {
                "attack_type": "port_hopping",
                "severity": "medium",
                "source_ip": src_ip,
                "details": f"Port hopping: {count} different ports to {dst_ip}",
            }
        return None

    def _check_service_mismatch(self, ip: str, dst_port: int, src_port: int, protocol: str) -> Optional[Dict]:
        if dst_port in _KNOWN_SERVICES:
            expected_service = _KNOWN_SERVICES[dst_port]
            if protocol == "tcp" and src_port < 1024:
                return {
                    "attack_type": "service_mismatch",
                    "severity": "medium",
                    "source_ip": ip,
                    "details": f"Privileged src port {src_port} to {_KNOWN_SERVICES[dst_port]} ({dst_port})",
                }
        return None

    def _cleanup_if_needed(self):
        now = time.time()
        if now - self._last_cleanup > self._cleanup_interval:
            cutoff = now - self._window * 2
            stale = [ip for ip, t in self._port_scan_time.items() if t < cutoff]
            for ip in stale:
                del self._port_scan_tracker[ip]
                del self._port_scan_time[ip]
            self._last_cleanup = now
