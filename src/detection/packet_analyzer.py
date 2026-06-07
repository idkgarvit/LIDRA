import logging
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set
from utils.config_loader import get_cfg

logger = logging.getLogger(__name__)


def _get_threshold(key, default):
    return get_cfg(f"thresholds.{key}", default)


class PacketAnalyzer:
    def __init__(self, config: dict, rate_limiter=None, blocklist=None):
        self._config = config
        self._rate_limiter = rate_limiter
        self._blocklist = blocklist
        self._syn_tracker: Dict[str, int] = defaultdict(int)
        self._syn_window: Dict[str, float] = {}
        self._port_scan_tracker: Dict[str, Set[int]] = defaultdict(set)
        self._port_scan_time: Dict[str, float] = {}
        self._cleanup_interval = 60
        self._last_cleanup = time.time()

    def analyze_header(self, packet: Dict) -> Optional[Dict]:
        if not packet:
            return None

        self._cleanup_if_needed()

        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        dst_port = packet.get("dst_port", 0)
        flags = packet.get("flags", "")
        protocol = packet.get("protocol", "tcp")

        blocklist_result = self._check_known_bad_ip(src_ip)
        if blocklist_result:
            return blocklist_result

        if protocol == "tcp":
            is_syn = "S" in flags and "A" not in flags
            if is_syn:
                syn_result = self._check_syn_flood(src_ip)
                if syn_result:
                    return syn_result

                scan_result = self._check_port_scan(src_ip, dst_port)
                if scan_result:
                    return scan_result

            flag_result = self._check_invalid_flags(flags)
            if flag_result:
                return flag_result

        frag_result = self._check_fragmentation(packet)
        if frag_result:
            return frag_result

        proto_result = self._check_protocol_anomaly(packet)
        if proto_result:
            return proto_result

        return None

    def _check_syn_flood(self, ip: str) -> Optional[Dict]:
        now = time.time()
        elapsed = now - self._syn_window.get(ip, now)
        if elapsed > 10:
            self._syn_tracker[ip] = 0
            self._syn_window[ip] = now

        self._syn_tracker[ip] += 1
        if self._syn_tracker[ip] > _get_threshold("syn_flood", 100):
            return {
                "attack_type": "syn_flood",
                "severity": "high",
                "source_ip": ip,
                "details": f"SYN flood: {self._syn_tracker[ip]} SYNs in {elapsed:.1f}s",
            }
        return None

    def _check_port_scan(self, ip: str, port: int) -> Optional[Dict]:
        now = time.time()
        elapsed = now - self._port_scan_time.get(ip, now)
        if elapsed > 10:
            self._port_scan_tracker[ip] = set()
            self._port_scan_time[ip] = now

        self._port_scan_tracker[ip].add(port)
        if len(self._port_scan_tracker[ip]) >= _get_threshold("port_scan", 20):
            return {
                "attack_type": "port_scan",
                "severity": "medium",
                "source_ip": ip,
                "details": f"Port scan: {len(self._port_scan_tracker[ip])} ports in {elapsed:.1f}s",
            }
        return None

    def _check_invalid_flags(self, flags: str) -> Optional[Dict]:
        if not flags:
            return None
        if flags == "FIN" or (len(flags) == 0):
            return None
        if set(flags).issubset({"F", "S", "R", "P", "A", "U", "E", "C", "N"}):
            pass
        flag_set = set(flags.upper().replace(" ", ""))
        unusual_combos = [
            ({"F", "S"}, "XMAS scan (FIN+SYN)"),
            ({"F", "U"}, "XMAS scan (FIN+URG)"),
            ({"P", "U"}, "XMAS scan (PSH+URG)"),
            ({"F", "P", "U"}, "XMAS scan (FIN+PSH+URG)"),
            ({"F", "S", "R", "P", "A", "U"}, "Full XMAS scan"),
        ]
        for combo, desc in unusual_combos:
            if combo.issubset(flag_set):
                return {
                    "attack_type": "xmas_scan",
                    "severity": "medium",
                    "source_ip": "",
                    "details": desc,
                }
        return None

    def _check_fragmentation(self, packet: Dict) -> Optional[Dict]:
        frag_offset = packet.get("frag_offset", 0)
        if frag_offset > 0:
            return None
        return None

    def _check_protocol_anomaly(self, packet: Dict) -> Optional[Dict]:
        protocol = packet.get("protocol", "")
        if protocol not in ("tcp", "udp", "icmp"):
            return {
                "attack_type": "protocol_anomaly",
                "severity": "low",
                "source_ip": packet.get("src_ip", ""),
                "details": f"Unusual protocol: {protocol}",
            }
        return None

    def _check_known_bad_ip(self, ip: str) -> Optional[Dict]:
        if self._blocklist and self._blocklist.is_blocked(ip):
            return {
                "attack_type": "blocked_ip_traffic",
                "severity": "high",
                "source_ip": ip,
                "details": f"Blocklisted IP attempted traffic",
            }
        return None

    def _cleanup_if_needed(self):
        now = time.time()
        if now - self._last_cleanup > self._cleanup_interval:
            cutoff = now - 10
            stale_syn = [ip for ip, t in self._syn_window.items() if t < cutoff]
            for ip in stale_syn:
                del self._syn_tracker[ip]
                del self._syn_window[ip]
            stale_port = [ip for ip, t in self._port_scan_time.items() if t < cutoff]
            for ip in stale_port:
                del self._port_scan_tracker[ip]
                del self._port_scan_time[ip]
            self._last_cleanup = now
