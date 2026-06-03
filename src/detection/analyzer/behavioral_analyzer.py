import logging
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class BehavioralAnalyzer:
    def __init__(self):
        self._syn_rates: Dict[str, deque] = defaultdict(lambda: deque(maxlen=60))
        self._packet_rates: Dict[str, deque] = defaultdict(lambda: deque(maxlen=120))
        self._payload_sizes: Dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self._protocol_use: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._conn_durations: Dict[str, deque] = defaultdict(lambda: deque(maxlen=30))
        self._conn_open: Dict[str, float] = {}
        self._last_cleanup = time.time()

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        detections = []
        self._cleanup_if_needed()
        src_ip = packet.get("src_ip", "")
        flags = packet.get("flags", "")
        protocol = packet.get("protocol", "")

        r = self._check_syn_burst(src_ip, flags)
        if r:
            detections.append(r)

        r = self._check_packet_burst(src_ip)
        if r:
            detections.append(r)

        r = self._check_payload_bias(src_ip, packet)
        if r:
            detections.append(r)

        r = self._check_proto_switch(src_ip, packet)
        if r:
            detections.append(r)

        if "S" in flags and "A" not in flags:
            self._conn_open[src_ip] = time.time()
        if "F" in flags or "R" in flags:
            if src_ip in self._conn_open:
                duration = time.time() - self._conn_open[src_ip]
                self._conn_durations[src_ip].append(duration)
                del self._conn_open[src_ip]
                r = self._check_short_connections(src_ip, duration)
                if r:
                    detections.append(r)

        self._packet_rates[src_ip].append(time.time())
        return detections if detections else None

    def _check_syn_burst(self, ip: str, flags: str) -> Optional[Dict]:
        if "S" not in flags or "A" in flags:
            return None
        now = time.time()
        self._syn_rates[ip].append(now)
        recent = [t for t in self._syn_rates[ip] if now - t < 5]
        if len(recent) >= 50:
            return {
                "attack_type": "syn_burst",
                "severity": "high",
                "source_ip": ip,
                "details": f"SYN flood/burst: {len(recent)} SYNs in 5s (possible port scan or DoS)",
            }
        if len(recent) >= 20:
            return {
                "attack_type": "syn_burst",
                "severity": "medium",
                "source_ip": ip,
                "details": f"Elevated SYN rate: {len(recent)} SYNs in 5s (possible scan)",
            }
        return None

    def _check_packet_burst(self, ip: str) -> Optional[Dict]:
        now = time.time()
        recent = [t for t in self._packet_rates[ip] if now - t < 3]
        if len(recent) >= 500:
            return {
                "attack_type": "packet_burst",
                "severity": "medium",
                "source_ip": ip,
                "details": f"Packet burst: {len(recent)} pkts in 3s (possible DoS)",
            }
        return None

    @staticmethod
    def _check_payload_bias(ip: str, packet: Dict) -> Optional[Dict]:
        payload = packet.get("payload", b"")
        plen = len(payload) if payload else 0
        if plen == 0:
            return None
        flags = packet.get("flags", "")
        if "P" in flags and plen == 1:
            return {
                "attack_type": "slow_drip",
                "severity": "medium",
                "source_ip": ip,
                "details": f"1-byte PUSH payload (slow loris/drip attack)",
            }
        return None

    def _check_proto_switch(self, ip: str, packet: Dict) -> Optional[Dict]:
        proto = packet.get("protocol", "")
        self._protocol_use[ip][proto] += 1
        total = sum(self._protocol_use[ip].values())
        if total > 20:
            count = len(self._protocol_use[ip])
            if count >= 3:
                protos = list(self._protocol_use[ip].keys())
                return {
                    "attack_type": "proto_scan",
                    "severity": "low",
                    "source_ip": ip,
                    "details": f"Multi-protocol usage: {protos} (possible probing)",
                }
        return None

    @staticmethod
    def _check_short_connections(ip: str, duration: float) -> Optional[Dict]:
        if duration < 0.5:
            return {
                "attack_type": "short_connection",
                "severity": "low",
                "source_ip": ip,
                "details": f"Connection closed in {duration*1000:.0f}ms (possible scan)",
            }
        return None

    def _cleanup_if_needed(self):
        if time.time() - self._last_cleanup > 120:
            self._syn_rates.clear()
            self._packet_rates.clear()
            self._payload_sizes.clear()
            self._protocol_use.clear()
            self._conn_durations.clear()
            self._conn_open.clear()
            self._last_cleanup = time.time()
