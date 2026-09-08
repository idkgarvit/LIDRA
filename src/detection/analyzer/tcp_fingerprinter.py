import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_INVALID_FLAGS = [
    "FS", "FR", "SR",
]


class TCPFingerprinter:
    def __init__(self):
        self._source_ttls: Dict[str, List[int]] = defaultdict(list)
        self._source_isns: Dict[str, List[int]] = defaultdict(list)
        self._source_ips: Dict[str, int] = defaultdict(int)
        self._last_cleanup = time.time()
        self._lock = Lock()

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        with self._lock:
            return self._analyze_locked(packet)

    def _analyze_locked(self, packet: Dict) -> Optional[List[Dict]]:
        detections = []
        self._cleanup_if_needed()
        protocol = packet.get("protocol", "")
        if protocol != "tcp":
            return None

        src_ip = packet.get("src_ip", "")
        flags = packet.get("flags", "")
        ttl = packet.get("ttl", 0)
        tcp_seq = packet.get("tcp_seq", 0)
        src_port = packet.get("src_port", 0)
        dst_port = packet.get("dst_port", 0)

        r = self._check_flag_anomalies(flags)
        if r:
            detections.append(r)

        r = self._check_ttl_jitter(src_ip, ttl)
        if r:
            detections.append(r)

        r = self._check_isn_randomness(src_ip, tcp_seq, flags)
        if r:
            detections.append(r)

        r = self._check_rare_port_pairing(src_port, dst_port)
        if r:
            detections.append(r)

        return detections if detections else None

    @staticmethod
    def _check_flag_anomalies(flags: str) -> Optional[Dict]:
        if not flags or len(flags) < 2:
            return None
        for invalid in _INVALID_FLAGS:
            if invalid in flags:
                return {
                    "attack_type": "invalid_tcp_flags",
                    "severity": "medium",
                    "source_ip": "",
                    "details": f"Invalid flag combo: {flags} (possible scan/spoof)",
                }
        return None

    def _check_ttl_jitter(self, ip: str, ttl: int) -> Optional[Dict]:
        if ttl == 0:
            return None
        self._source_ttls[ip].append(ttl)
        recent = self._source_ttls[ip][-10:]
        if len(recent) >= 3:
            unique = set(recent)
            if len(unique) > 1:
                expected = max(recent)
                anomalies = [t for t in recent if abs(t - expected) > 5]
                if len(anomalies) >= 2:
                    return {
                        "attack_type": "ttl_inconsistency",
                        "severity": "medium",
                        "source_ip": ip,
                        "details": f"TTL jitter: values {unique} (possible spoofing/covert)",
                    }
        return None

    def _check_isn_randomness(self, ip: str, seq: int, flags: str) -> Optional[Dict]:
        if "S" not in flags or "A" in flags:
            return None
        self._source_isns[ip].append(seq)
        recent = self._source_isns[ip][-5:]
        if len(recent) >= 4:
            gaps = [abs(recent[i + 1] - recent[i]) for i in range(len(recent) - 1)]
            # Suspicious patterns:
            #   1. All gaps <100 = spoofed packet with constant counter
            #   2. Zero gaps = identical ISNs (replay/duplication)
            #   3. All gaps equal = predictable linear pattern
            if all(g == 0 for g in gaps):
                return {
                    "attack_type": "low_entropy_isn",
                    "severity": "high",
                    "source_ip": ip,
                    "details": f"Identical ISNs in {len(gaps)} samples (possible replay/spoofing)",
                }
            if all(g < 100 for g in gaps):
                return {
                    "attack_type": "low_entropy_isn",
                    "severity": "high",
                    "source_ip": ip,
                    "details": f"ISN increments <100 in {len(gaps)} samples (likely spoofed counter)",
                }
            if len(set(gaps)) == 1 and gaps[0] < 10000:
                return {
                    "attack_type": "low_entropy_isn",
                    "severity": "high",
                    "source_ip": ip,
                    "details": f"Predictable ISN deltas (constant {gaps[0]}) in {len(gaps)} samples",
                }
        return None

    @staticmethod
    def _check_rare_port_pairing(src_port: int, dst_port: int) -> Optional[Dict]:
        if src_port < 1024 and dst_port < 1024 and src_port != dst_port:
            if src_port in (22, 80, 443) or dst_port in (22, 80, 443):
                return {
                    "attack_type": "rare_port_pairing",
                    "severity": "low",
                    "source_ip": "",
                    "details": f"Both ports privileged: {src_port}:{dst_port} (possible tunneling)",
                }
        return None

    def _cleanup_if_needed(self):
        if time.time() - self._last_cleanup > 60:
            self._source_ttls.clear()
            self._source_isns.clear()
            self._source_ips.clear()
            self._last_cleanup = time.time()
