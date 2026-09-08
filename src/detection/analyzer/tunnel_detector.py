import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class TunnelDetector:
    def __init__(self):
        self._dns_high_vol: Dict[str, int] = defaultdict(int)
        self._dns_large: Dict[str, List[int]] = defaultdict(list)
        self._icmp_large: Dict[str, List[int]] = defaultdict(list)
        self._last_cleanup = time.time()
        self._lock = Lock()

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        with self._lock:
            return self._analyze_locked(packet)

    def _analyze_locked(self, packet: Dict) -> Optional[List[Dict]]:
        detections = []
        self._cleanup_if_needed()
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        dst_port = packet.get("dst_port", 0)
        protocol = packet.get("protocol", "")
        payload = packet.get("payload", b"")
        plen = len(payload) if payload else 0

        if protocol == "dns" or dst_port == 53:
            r = self._dns_tunnel(src_ip, dst_ip, plen)
            if r:
                detections.append(r)
        if protocol == "icmp":
            r = self._icmp_tunnel(src_ip, plen)
            if r:
                detections.append(r)
        if dst_port in {80, 443, 8080, 8443}:
            r = self._http_tunnel(src_ip, payload, plen)
            if r:
                detections.append(r)
        return detections if detections else None

    def _dns_tunnel(self, ip, dst, plen):
        self._dns_high_vol[ip] += 1
        if self._dns_high_vol[ip] > 300:
            self._dns_high_vol[ip] = 0
            return {"attack_type": "dns_tunnel", "severity": "high", "source_ip": ip,
                    "details": "DNS flood >300 queries (possible tunnel)"}
        if plen > 200:
            self._dns_large[ip].append(plen)
            recent = self._dns_large[ip][-10:]
            if sum(recent) / len(recent) > 200 and len(recent) >= 5:
                return {"attack_type": "dns_tunnel", "severity": "critical", "source_ip": ip,
                        "details": f"Avg DNS query {sum(recent)//len(recent)} bytes (data exfil)"}
        return None

    def _icmp_tunnel(self, ip, plen):
        if plen > 500:
            return {"attack_type": "icmp_tunnel", "severity": "high", "source_ip": ip,
                    "details": f"Large ICMP payload: {plen}B"}
        self._icmp_large[ip].append(plen)
        recent = self._icmp_large[ip][-20:]
        if len(recent) >= 10 and sum(recent) / len(recent) > 100:
            return {"attack_type": "icmp_tunnel", "severity": "medium", "source_ip": ip,
                    "details": f"Consistent large ICMP: avg {sum(recent)//len(recent)}B over {len(recent)} pkts"}
        return None

    def _http_tunnel(self, ip, payload, plen):
        if not payload:
            return None
        if plen > 50000:
            return {"attack_type": "http_tunnel", "severity": "medium", "source_ip": ip,
                    "details": f"Large HTTP payload: {plen}B"}
        try:
            text = payload.decode("utf-8", errors="replace")
            for line in text.split("\r\n"):
                ll = line.lower()
                if any(x in ll for x in ("x-tunnel", "proxy-authorization", "proxy-connection")):
                    return {"attack_type": "http_tunnel", "severity": "high", "source_ip": ip,
                            "details": f"Tunnel header: {line.strip()[:80]}"}
                if ll.startswith("content-type:") and "application/octet-stream" in ll:
                    return {"attack_type": "http_tunnel", "severity": "high", "source_ip": ip,
                            "details": "Binary content-type in HTTP (possible tunnel)"}
        except Exception as e:
            logger.warning(f"[TunnelDetector] HTTP tunnel parse failed: {e}")
        return None

    def _cleanup_if_needed(self):
        now = time.time()
        if now - self._last_cleanup > 60:
            self._dns_high_vol.clear()
            self._dns_large.clear()
            self._icmp_large.clear()
            self._last_cleanup = now
