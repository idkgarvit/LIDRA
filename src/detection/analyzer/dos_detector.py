import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class DoSDetector:
    def __init__(self, config: Optional[Dict] = None):
        cfg = config or {}
        self._syn_limit = cfg.get("syn_rate_limit", 200)
        self._conn_limit = cfg.get("conn_rate_limit", 500)
        self._bw_limit = cfg.get("bandwidth_limit_mbps", 100) * 1_000_000 // 8
        self._icmp_limit = cfg.get("icmp_rate_limit", 100)
        self._window = cfg.get("window_seconds", 10)
        self._syn: Dict[str, List[float]] = defaultdict(list)
        self._conn: Dict[str, List[float]] = defaultdict(list)
        self._icmp: Dict[str, List[float]] = defaultdict(list)
        self._bw: Dict[str, List[tuple]] = defaultdict(list)
        self._last_cleanup = time.time()
        self._lock = Lock()

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        with self._lock:
            return self._analyze_locked(packet)

    def _analyze_locked(self, packet: Dict) -> Optional[List[Dict]]:
        detections = []
        self._maybe_cleanup()
        ip = packet.get("src_ip", "")
        proto = packet.get("protocol", "")
        flags = packet.get("flags", "")
        plen = packet.get("payload_len", 0) or packet.get("raw_len", 0)
        now = time.time()

        if proto == "tcp" and flags == "S":
            self._syn[ip].append(now)
            rate = self._rate(self._syn[ip], self._window)
            if rate > self._syn_limit:
                detections.append({"attack_type": "syn_flood", "severity": "critical",
                                   "source_ip": ip, "details": f"SYN flood: {rate:.0f}/s"})

        self._conn[ip].append(now)
        rate = self._rate(self._conn[ip], self._window)
        if rate > self._conn_limit:
            detections.append({"attack_type": "connection_flood", "severity": "high",
                               "source_ip": ip, "details": f"Pkt flood: {rate:.0f}/s"})

        if proto == "icmp":
            self._icmp[ip].append(now)
            rate = self._rate(self._icmp[ip], self._window)
            if rate > self._icmp_limit:
                detections.append({"attack_type": "icmp_flood", "severity": "high",
                                   "source_ip": ip, "details": f"ICMP flood: {rate:.0f}/s"})

        self._bw[ip].append((now, plen))
        bps = self._bandwidth(self._bw[ip], self._window)
        if bps > self._bw_limit:
            detections.append({"attack_type": "bandwidth_attack", "severity": "high",
                               "source_ip": ip, "details": f"BW: {bps//1000}KB/s"})

        return detections if detections else None

    @staticmethod
    def _rate(timestamps: List[float], window: float) -> float:
        cutoff = time.time() - window
        recent = [t for t in timestamps if t > cutoff]
        timestamps[:] = recent
        return len(recent) / window if window else 0

    @staticmethod
    def _bandwidth(entries: List[tuple], window: float) -> int:
        cutoff = time.time() - window
        recent = [(t, b) for t, b in entries if t > cutoff]
        entries[:] = recent
        total = sum(b for _, b in recent)
        return int(total / window) if window else 0

    def _maybe_cleanup(self):
        if time.time() - self._last_cleanup > 60:
            self._syn.clear()
            self._conn.clear()
            self._icmp.clear()
            self._bw.clear()
            self._last_cleanup = time.time()
