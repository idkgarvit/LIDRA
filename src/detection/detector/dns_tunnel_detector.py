import logging
import math
import time
import struct
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


_TXT_SIZE_THRESHOLD = 512
_ENTROPY_THRESHOLD = 4.0
_NXDOMAIN_RATIO_THRESHOLD = 0.2
_BEACON_WINDOW = 5.0


class DNSTunnelDetector:
    def __init__(self):
        self._query_counts: Dict[str, int] = defaultdict(int)
        self._txt_sizes: Dict[str, List[int]] = defaultdict(list)
        self._nxdomain_counts: Dict[str, List[bool]] = defaultdict(list)
        self._query_times: Dict[str, List[float]] = defaultdict(list)
        self._seen_domains: Dict[str, Set[str]] = defaultdict(set)
        self._last_cleanup = time.time()
        self._lock = Lock()
        self._cleanup_interval = 60

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        self._cleanup_if_needed()
        if packet.get("protocol", "") != "dns" and packet.get("dst_port", 0) != 53:
            return None
        payload = packet.get("payload", b"")
        if not payload:
            return None
        detections = []
        domain = self._extract_domain(payload)
        if not domain:
            return None
        src_ip = packet.get("src_ip", "")
        now = time.time()
        with self._lock:
            self._query_counts[domain] += 1
            self._seen_domains[src_ip].add(domain)
            self._query_times[domain].append(now)
            r = self._check_entropy(domain, src_ip)
            if r:
                detections.append(r)
            r = self._check_txt_size(payload, domain, src_ip, packet)
            if r:
                detections.append(r)
            r = self._check_nxdomain(payload, domain, src_ip)
            if r:
                detections.append(r)
            r = self._check_beaconing(domain, src_ip)
            if r:
                detections.append(r)
        return detections if detections else None

    def _extract_domain(self, payload: bytes) -> Optional[str]:
        try:
            if len(payload) < 12:
                return None
            offset = 12
            labels = []
            while offset < len(payload):
                length = payload[offset]
                if length == 0:
                    break
                if length & 0xC0:
                    offset += 2
                    break
                offset += 1
                if offset + length > len(payload):
                    return None
                labels.append(payload[offset:offset + length].decode("ascii", errors="replace"))
                offset += length
            return ".".join(labels) if labels else None
        except Exception as e:
            logger.warning(f"[DNS-Tunnel] Domain extraction failed: {e}")
            return None

    def _check_entropy(self, domain: str, src_ip: str) -> Optional[Dict]:
        name = domain.split(".")[0] if "." in domain else domain
        entropy = shannon_entropy(name)
        if entropy > _ENTROPY_THRESHOLD:
            return {
                "attack_type": "dns_tunnel_high_entropy",
                "severity": "high",
                "source_ip": src_ip,
                "details": f"High entropy domain: {name} ({entropy:.2f} bits/char)",
                "confidence": min(0.5 + (entropy - 4.0) * 0.15, 0.95),
                "mitre": ["T1572"],
            }
        return None

    def _check_txt_size(self, payload: bytes, domain: str, src_ip: str, packet: Dict) -> Optional[Dict]:
        qtype = self._extract_qtype(payload)
        if qtype != 16:
            return None
        answer_section = self._extract_answer(payload)
        if answer_section and len(answer_section) > _TXT_SIZE_THRESHOLD:
            self._txt_sizes[domain].append(len(answer_section))
            recent = self._txt_sizes[domain][-5:]
            avg_size = sum(recent) / len(recent) if recent else 0
            if avg_size > _TXT_SIZE_THRESHOLD:
                return {
                    "attack_type": "dns_tunnel_large_txt",
                    "severity": "high",
                    "source_ip": src_ip,
                    "details": f"Large TXT records for {domain}: avg {avg_size:.0f}B",
                    "confidence": min(0.5 + (avg_size - 512) / 2048, 0.95),
                    "mitre": ["T1572"],
                }
        return None

    def _check_nxdomain(self, payload: bytes, domain: str, src_ip: str) -> Optional[Dict]:
        rcode = payload[3] & 0x0F if len(payload) > 3 else 0
        is_nx = rcode == 3
        self._nxdomain_counts[domain].append(is_nx)
        recent = self._nxdomain_counts[domain][-50:]
        if len(recent) >= 10:
            ratio = sum(recent) / len(recent)
            if ratio > _NXDOMAIN_RATIO_THRESHOLD:
                return {
                    "attack_type": "dns_tunnel_nxdomain",
                    "severity": "medium",
                    "source_ip": src_ip,
                    "details": f"High NXDOMAIN ratio for {domain}: {ratio:.0%}",
                    "confidence": min(0.4 + ratio * 0.5, 0.9),
                    "mitre": ["T1572"],
                }
        return None

    def _check_beaconing(self, domain: str, src_ip: str) -> Optional[Dict]:
        times = self._query_times[domain]
        if len(times) < 5:
            return None
        recent = times[-10:]
        gaps = [recent[i + 1] - recent[i] for i in range(len(recent) - 1)]
        if not gaps:
            return None
        avg_gap = sum(gaps) / len(gaps)
        variance = sum((g - avg_gap) ** 2 for g in gaps) / len(gaps)
        if avg_gap > 1 and variance < _BEACON_WINDOW:
            return {
                "attack_type": "dns_beaconing",
                "severity": "medium",
                "source_ip": src_ip,
                "details": f"DNS beaconing to {domain}: every {avg_gap:.1f}s",
                "confidence": min(0.3 + (1.0 - variance / _BEACON_WINDOW) * 0.5, 0.85),
                "mitre": ["T1572"],
            }
        return None

    @staticmethod
    def _extract_qtype(payload: bytes) -> int:
        try:
            if len(payload) < 14:
                return 0
            questions = payload[4:6]
            num_q = struct.unpack(">H", questions)[0] if len(payload) > 5 else 1
            if num_q == 0:
                return 0
            offset = 12
            while offset < len(payload):
                length = payload[offset]
                if length == 0:
                    offset += 1
                    break
                if length & 0xC0:
                    offset += 2
                    break
                offset += 1 + length
            if offset + 4 <= len(payload):
                return struct.unpack(">H", payload[offset:offset + 2])[0]
            return 0
        except Exception as e:
            logger.warning(f"[DNS-Tunnel] _extract_qtype failed: {e}")
            return 0

    @staticmethod
    def _extract_answer(payload: bytes) -> Optional[bytes]:
        try:
            if len(payload) < 12:
                return None
            offset = 12
            while offset < len(payload):
                length = payload[offset]
                if length == 0:
                    offset += 1
                    break
                if length & 0xC0:
                    offset += 2
                    break
                offset += 1 + length
            offset += 4
            ancount = struct.unpack(">H", payload[6:8])[0]
            for _ in range(ancount):
                if offset + 12 > len(payload):
                    return None
                name_compressed = (payload[offset] & 0xC0) == 0xC0
                if name_compressed:
                    offset += 2
                else:
                    while offset < len(payload) and payload[offset] != 0:
                        offset += 1 + payload[offset]
                    offset += 1
                atype = struct.unpack(">H", payload[offset:offset + 2])[0]
                rdlength = struct.unpack(">H", payload[offset + 8:offset + 10])[0]
                offset += 10
                if offset + rdlength <= len(payload) and atype == 16:
                    return payload[offset:offset + rdlength]
                offset += rdlength
            return None
        except Exception as e:
            logger.warning(f"[DNS-Tunnel] _extract_answer failed: {e}")
            return None

    def _cleanup_if_needed(self):
        if time.time() - self._last_cleanup > self._cleanup_interval:
            with self._lock:
                cutoff = time.time() - 3600
                self._query_counts.clear()
                self._txt_sizes.clear()
                self._nxdomain_counts.clear()
                self._query_times = {k: [t for t in v if t > cutoff] for k, v in self._query_times.items()}
                self._seen_domains.clear()
                self._last_cleanup = time.time()
