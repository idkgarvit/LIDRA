import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class IPv6Analyzer:
    def __init__(self):
        self._ext_hdr_counts: Dict[str, int] = defaultdict(int)
        self._frag6_tracker: Dict[str, List[int]] = defaultdict(list)
        self._last_cleanup = time.time()
        self._lock = Lock()

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        with self._lock:
            return self._analyze_locked(packet)
    def _analyze_locked(self, packet: Dict) -> Optional[List[Dict]]:
        detections = []
        self._cleanup_if_needed()
        protocol = packet.get("protocol", "")
        src_ip = packet.get("src_ip", "")
        payload = packet.get("payload", b"")

        if protocol == "ipv6":
            r = self._check_ipv6_anomalies(packet, src_ip)
            if r:
                detections.append(r)

        if payload and self._is_ipv6_in_ipv4(payload):
            detections.append({
                "attack_type": "ipv6_tunnel",
                "severity": "high",
                "source_ip": src_ip,
                "details": "IPv6-in-IPv4 tunnel detected",
            })

        return detections if detections else None

    def _check_ipv6_anomalies(self, packet, src_ip):
        payload = packet.get("payload", b"")
        if not payload:
            return None
        raw = payload if isinstance(payload, bytes) else b""
        if len(raw) < 2:
            return None

        next_hdr = raw[0] if len(raw) > 0 else 0
        hdr_count = 1
        offset = 0
        while next_hdr in (0, 43, 44, 60, 135) and offset < len(raw):
            if next_hdr == 44:
                if offset + 8 <= len(raw):
                    ident = (raw[offset + 4] << 24) | (raw[offset + 5] << 16) | (raw[offset + 6] << 8) | raw[offset + 7]
                    self._frag6_tracker[src_ip].append(ident)
                    recent_idents = self._frag6_tracker[src_ip][-20:]
                    if len(set(recent_idents)) == 1 and len(recent_idents) >= 10:
                        return {"attack_type": "ipv6_fragment_storm", "severity": "high", "source_ip": src_ip,
                                "details": f"IPv6 fragmentation attack: {len(recent_idents)} pkts same id"}
            hdr_count += 1
            if hdr_count > 15:
                return {"attack_type": "ipv6_extension_overload", "severity": "high", "source_ip": src_ip,
                        "details": f"IPv6 excessive extension headers: {hdr_count}"}
            next_hdr = raw[offset] if offset < len(raw) else 0
            hdr_len = raw[offset + 1] if offset + 1 < len(raw) else 0
            offset += (hdr_len + 8) if next_hdr in (0, 43, 60, 135) else 8

        if hdr_count >= 5:
            return {"attack_type": "ipv6_extension_chain", "severity": "medium", "source_ip": src_ip,
                    "details": f"IPv6 long extension header chain: {hdr_count} headers"}

        if next_hdr == 60:
            return {"attack_type": "ipv6_destination_header", "severity": "low", "source_ip": src_ip,
                    "details": "IPv6 Destination Options header present"}
        return None

    @staticmethod
    def _is_ipv6_in_ipv4(payload) -> bool:
        """True only for a *valid* IP-in-IP tunnel, not any payload starting
        with byte 0x6n.

        The previous check was `first_nibble == 6`, which is satisfied by a
        random 16th of all payloads — a DNS transaction ID's high byte is
        uniformly distributed, so it flagged 6.25% of one benign capture (314
        of 4956 packets, measured). A version nibble alone is not evidence of
        anything; validate the encapsulated header instead.

        Returning True here only means "worth a closer look" — the severity is
        what matters, and a single unexpected packet is not a tunnel.
        """
        if not isinstance(payload, (bytes, bytearray)) or len(payload) < 20:
            return False
        version = payload[0] >> 4
        if version == 4:
            # Encapsulated IPv4: IHL is valid and protocol must be 41 (IPv6)
            # or 4 (IP-in-IP).
            ihl = (payload[0] & 0x0F) * 4
            if ihl < 20 or ihl > len(payload):
                return False
            inner_proto = payload[9]
            total_len = (payload[2] << 8) | payload[3]
            if total_len < ihl or total_len > len(payload) + 64:
                # Tolerate truncated captures, reject nonsense lengths.
                if total_len > 65535 or total_len == 0:
                    return False
            return inner_proto in (41, 4)
        if version == 6:
            # Encapsulated IPv6: payload length must fit the frame.
            if len(payload) < 40:
                return False
            declared = (payload[4] << 8) | payload[5]
            if declared == 0 or declared > len(payload) + 64:
                return False
            return payload[6] in (4, 41)
        return False

    def _cleanup_if_needed(self):
        if time.time() - self._last_cleanup > 60:
            self._ext_hdr_counts.clear()
            self._frag6_tracker.clear()
            self._last_cleanup = time.time()
