import logging
import time
from collections import defaultdict
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class CovertDetector:
    def __init__(self):
        self._seq_anomalies: Dict[str, List[int]] = defaultdict(list)
        self._ttl_anomalies: Dict[str, List[int]] = defaultdict(list)
        self._ack_anomalies: Dict[str, List[int]] = defaultdict(list)
        self._last_cleanup = time.time()

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        detections = []
        self._cleanup_if_needed()
        src_ip = packet.get("src_ip", "")
        protocol = packet.get("protocol", "")

        if protocol != "tcp":
            return None

        tcp_seq = packet.get("tcp_seq", 0)
        tcp_ack = packet.get("tcp_ack", 0)
        ttl = packet.get("ttl", 0)
        flags = packet.get("flags", "")
        payload = packet.get("payload", b"")
        payload_len = len(payload) if payload else 0

        r = self._check_seq_covert(src_ip, tcp_seq)
        if r:
            detections.append(r)

        r = self._check_ack_covert(src_ip, tcp_ack, flags)
        if r:
            detections.append(r)

        r = self._check_ttl_covert(src_ip, ttl)
        if r:
            detections.append(r)

        r = self._check_header_covert(payload, payload_len)
        if r:
            detections.append(r)

        return detections if detections else None

    def _check_seq_covert(self, ip, seq):
        anomalies = []
        last_bytes = seq & 0xFF
        self._seq_anomalies[ip].append(last_bytes)
        recent = self._seq_anomalies[ip][-20:]
        if len(recent) >= 5:
            for i in range(len(recent) - 1):
                diff = (recent[i + 1] - recent[i]) & 0xFF
                if diff > 1 and chr(diff) in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":
                    anomalies.append(chr(diff))
            if len(anomalies) >= 4:
                data = "".join(anomalies[-8:])
                return {"attack_type": "seq_covert_channel", "severity": "high", "source_ip": ip,
                        "details": f"Seq number encoding: '{data}'"}
        return None

    def _check_ack_covert(self, ip, ack, flags):
        if "A" not in flags:
            return None
        last_bytes = ack & 0xFF
        self._ack_anomalies[ip].append(last_bytes)
        recent = self._ack_anomalies[ip][-20:]
        if len(recent) >= 5:
            diffs = [(recent[i + 1] - recent[i]) & 0xFF for i in range(len(recent) - 1)]
            non_zero = [d for d in diffs if d != 0]
            if len(non_zero) >= 4:
                chars = "".join(chr(d) for d in non_zero[-8:] if 32 <= d <= 126)
                if len(chars) >= 3:
                    return {"attack_type": "ack_covert_channel", "severity": "high", "source_ip": ip,
                            "details": f"ACK number encoding: '{chars}'"}
        return None

    def _check_ttl_covert(self, ip, ttl):
        self._ttl_anomalies[ip].append(ttl)
        recent = self._ttl_anomalies[ip][-10:]
        if len(recent) >= 5 and len(set(recent)) >= 4:
            return {"attack_type": "ttl_covert_channel", "severity": "medium", "source_ip": ip,
                    "details": f"TTL manipulation: values {set(recent)} over {len(recent)} pkts"}
        return None

    @staticmethod
    def _check_header_covert(payload, plen):
        if not payload or plen < 20:
            return None
        try:
            text = payload.decode("utf-8", errors="replace")
            lines = text.split("\r\n")
            for line in lines:
                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip().lower()
                    val = val.strip()
                    if key in ("x-", "x-custom", "x-data", "x-forwarded-for"):
                        if len(val) > 50 and sum(c.isprintable() for c in val) / len(val) > 0.9:
                            return {"attack_type": "header_covert_channel", "severity": "medium",
                                    "source_ip": "", "details": f"Suspicious header {key}: {val[:80]}"}
        except Exception:
            pass
        return None

    def _cleanup_if_needed(self):
        if time.time() - self._last_cleanup > 60:
            self._seq_anomalies.clear()
            self._ack_anomalies.clear()
            self._ttl_anomalies.clear()
            self._last_cleanup = time.time()
