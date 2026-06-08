import logging
import re
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_CL_TE_RE = re.compile(r'Content-Length:\s*(\d+)', re.IGNORECASE)
_TE_RE = re.compile(r'Transfer-Encoding:\s*([^\r\n]+)', re.IGNORECASE)
_CL_RE = re.compile(r'content-length', re.IGNORECASE)


def detect_http_smuggling(headers: Dict[str, str]) -> Optional[Tuple[str, float]]:
    raw_headers_str = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
    has_cl = _CL_TE_RE.search(raw_headers_str)
    has_te = _TE_RE.search(raw_headers_str)
    if has_cl and has_te:
        te_value = has_te.group(1).strip().lower()
        if "," in te_value or te_value == "chunked":
            return ("http_smuggling_cl_te", 0.9)
    cl_count = len(_CL_RE.findall(raw_headers_str))
    if cl_count > 1:
        return ("http_smuggling_dual_cl", 0.85)
    return None


def detect_h2_rapid_reset(events: List[float], threshold: int = 100, window: float = 1.0) -> bool:
    now = time.time()
    recent = [t for t in events if now - t < window]
    return len(recent) > threshold


class SmugglingDetector:
    def __init__(self):
        self._h2_resets: Dict[str, List[float]] = defaultdict(list)
        self._ws_upgrades: Dict[str, float] = {}
        self._quic_sessions: Dict[str, float] = {}
        self._lock = Lock()

    def analyze_http(self, headers: Dict[str, str], src_ip: str) -> Optional[Dict]:
        result = detect_http_smuggling(headers)
        if result:
            attack_type, confidence = result
            return {
                "attack_type": attack_type,
                "severity": "critical",
                "source_ip": src_ip,
                "details": f"HTTP smuggling: {attack_type}",
                "confidence": confidence,
                "mitre": ["T1190"],
            }
        return None

    def track_h2_reset(self, src_ip: str):
        with self._lock:
            self._h2_resets[src_ip].append(time.time())
            if detect_h2_rapid_reset(self._h2_resets[src_ip]):
                self._h2_resets[src_ip].clear()
                return {
                    "attack_type": "h2_rapid_reset",
                    "severity": "critical",
                    "source_ip": src_ip,
                    "details": "HTTP/2 rapid reset attack (>100 RST_STREAM/s)",
                    "confidence": 0.95,
                    "mitre": ["T1190"],
                }
        return None

    def track_ws_upgrade(self, src_ip: str, headers: Dict[str, str]):
        upgrade = headers.get("upgrade", "").lower()
        connection = headers.get("connection", "").lower()
        if upgrade == "websocket" and "upgrade" in connection:
            with self._lock:
                self._ws_upgrades[src_ip] = time.time()
            return {
                "attack_type": "websocket_upgrade",
                "severity": "low",
                "source_ip": src_ip,
                "details": "WebSocket upgrade request",
                "confidence": 0.3,
                "mitre": [],
            }
        return None

    def track_quic_fallback(self, src_ip: str, is_quic: bool, is_tcp: bool):
        with self._lock:
            if is_quic:
                self._quic_sessions[src_ip] = time.time()
            if is_tcp and src_ip in self._quic_sessions:
                elapsed = time.time() - self._quic_sessions[src_ip]
                if elapsed < 2.0:
                    del self._quic_sessions[src_ip]
                    return {
                        "attack_type": "quic_tcp_fallback",
                        "severity": "medium",
                        "source_ip": src_ip,
                        "details": f"QUIC→TCP fallback in {elapsed:.1f}s (protocol downgrade)",
                        "confidence": 0.6,
                        "mitre": ["T1190"],
                    }
        return None

    def cleanup(self):
        with self._lock:
            cutoff = time.time() - 300
            self._h2_resets = {k: v for k, v in self._h2_resets.items() if v and v[-1] > cutoff}
            self._ws_upgrades = {k: v for k, v in self._ws_upgrades.items() if v > cutoff}
            self._quic_sessions = {k: v for k, v in self._quic_sessions.items() if v > cutoff}
