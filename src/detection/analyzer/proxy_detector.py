import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_VPN_PROTOCOLS = {
    500: "ipsec", 4500: "ipsec-nat-t", 1701: "l2tp",
    1723: "pptp", 1194: "openvpn", 51820: "wireguard",
}

_PROXY_HEADERS = {
    "x-forwarded-for", "x-real-ip", "x-forwarded-proto",
    "via", "proxy-authorization", "proxy-connection",
    "x-proxy-user", "x-proxy-agent",
}


class ProxyDetector:
    def __init__(self):
        self._vpn_detections: Dict[str, float] = {}
        self._proxy_header_counts: Dict[str, int] = defaultdict(int)
        self._tor_tracker: Dict[str, int] = defaultdict(int)
        self._last_cleanup = time.time()
        self._lock = Lock()

    _TOR_NODES = {
        "1.2.3.4",
    }

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

        if dst_port in _VPN_PROTOCOLS:
            proto = _VPN_PROTOCOLS[dst_port]
            if src_ip not in self._vpn_detections or time.time() - self._vpn_detections[src_ip] > 3600:
                self._vpn_detections[src_ip] = time.time()
                detections.append({
                    "attack_type": "vpn_traffic",
                    "severity": "low",
                    "source_ip": src_ip,
                    "details": f"VPN protocol: {proto} on port {dst_port}",
                })

        if protocol == "tcp" and payload:
            self._check_http_proxy(src_ip, dst_ip, payload, detections)

        if protocol == "tcp" and dst_port in (9001, 9030, 9050, 9150):
            self._tor_tracker[src_ip] += 1
            if self._tor_tracker[src_ip] >= 5:
                detections.append({
                    "attack_type": "tor_traffic",
                    "severity": "medium",
                    "source_ip": src_ip,
                    "details": f"Tor protocol on port {dst_port}",
                })

        if src_ip in self._TOR_NODES:
            detections.append({
                "attack_type": "tor_traffic",
                "severity": "high",
                "source_ip": src_ip,
                "details": f"Known Tor exit node: {src_ip}",
            })

        return detections if detections else None

    def _check_http_proxy(self, src_ip, dst_ip, payload, detections):
        try:
            text = payload.decode("utf-8", errors="replace")
            lines = text.split("\r\n")
            if not lines:
                return

            first = lines[0]
            if first.startswith(("GET ", "POST ", "PUT ", "CONNECT ")) and " HTTP/" in first:
                parts = first.split()
                if len(parts) >= 2:
                    uri = parts[1]
                    if uri.startswith("http://") or uri.startswith("https://"):
                        detections.append({
                            "attack_type": "proxy_traffic",
                            "severity": "low",
                            "source_ip": src_ip,
                            "details": f"Proxy request: {parts[0]} {uri[:80]}",
                        })

            for line in lines:
                if ":" in line:
                    key = line.split(":", 1)[0].strip().lower()
                    if key in _PROXY_HEADERS:
                        self._proxy_header_counts[src_ip] += 1
                        if self._proxy_header_counts[src_ip] >= 3:
                            detections.append({
                                "attack_type": "proxy_traffic",
                                "severity": "medium",
                                "source_ip": src_ip,
                                "details": f"Proxy headers: {key} in request",
                            })
                            break
        except Exception:
            logger.debug("[ProxyDetector] Header parse failed")

    def _cleanup_if_needed(self):
        if time.time() - self._last_cleanup > 60:
            cutoff = time.time() - 3600
            self._vpn_detections = {k: v for k, v in self._vpn_detections.items() if v > cutoff}
            self._proxy_header_counts.clear()
            self._tor_tracker.clear()
            self._last_cleanup = time.time()
