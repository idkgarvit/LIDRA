import logging
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Deque, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class DoSDetector:
    def __init__(self, config: Optional[Dict] = None):
        cfg = config or {}
        self._syn_limit = cfg.get("syn_rate_limit", 200)
        self._conn_limit = cfg.get("conn_rate_limit", 500)
        self._bw_limit = cfg.get("bandwidth_limit_mbps", 100) * 1_000_000 // 8
        self._icmp_limit = cfg.get("icmp_rate_limit", 100)
        self._window = cfg.get("window_seconds", 10)
        # ponytail: time-ordered deques + left-prune = amortized O(1) per
        # packet. The old full-list scan + slice-copy per packet went O(n^2)
        # under flood (5000-entry windows re-scanned per SYN) and stalled
        # NFQUEUE verdicts. _bw_total keeps bandwidth O(1) too.
        self._syn: Dict[str, Deque[float]] = defaultdict(deque)
        self._conn: Dict[str, Deque[float]] = defaultdict(deque)
        self._icmp: Dict[str, Deque[float]] = defaultdict(deque)
        self._bw: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self._bw_total: Dict[str, int] = defaultdict(int)
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
            # ponytail: 10s-average hides sub-second bursts (ping -f -c 200 =
            # ~200pps for 1s reads as 20/s). Flag the burst itself too.
            # Walk from the right (time-ordered) — O(burst), not O(window).
            burst = 0
            for t in reversed(self._icmp[ip]):
                if t > now - 1:
                    burst += 1
                else:
                    break
            if rate > self._icmp_limit or burst >= 50:
                detections.append({"attack_type": "icmp_flood", "severity": "high",
                                   "source_ip": ip, "details": f"ICMP flood: {rate:.0f}/s (burst {burst}/s)"})

        self._bw[ip].append((now, plen))
        self._bw_total[ip] += plen
        bps = self._bandwidth(ip, self._bw[ip], self._bw_total, self._window)
        if bps > self._bw_limit:
            detections.append({"attack_type": "bandwidth_attack", "severity": "high",
                               "source_ip": ip, "details": f"BW: {bps//1000}KB/s"})

        return detections if detections else None

    @staticmethod
    def _rate(entries: Deque[float], window: float) -> float:
        cutoff = time.time() - window
        while entries and entries[0] <= cutoff:
            entries.popleft()
        return len(entries) / window if window else 0

    @staticmethod
    def _bandwidth(ip: str, entries: Deque[Tuple[float, int]],
                   totals: Dict[str, int], window: float) -> int:
        cutoff = time.time() - window
        while entries and entries[0][0] <= cutoff:
            _, b = entries.popleft()
            totals[ip] -= b
        return int(totals[ip] / window) if window else 0

    def _maybe_cleanup(self):
        if time.time() - self._last_cleanup > 60:
            self._syn.clear()
            self._conn.clear()
            self._icmp.clear()
            self._bw.clear()
            self._bw_total.clear()
            self._last_cleanup = time.time()
