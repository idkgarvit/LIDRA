import logging
import math
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class CovertDetector:
    def __init__(self, config: dict = None):
        # ponytail: bounded deques — unbounded .append + per-packet full
        # scans (welford over a 300s window) went O(n^2) under flood and
        # stalled packet verdicts. 64 recent samples cover every threshold
        # below (max need: 25); 1000-sample baselines stay valid.
        self._seq_anomalies: Dict[str, deque] = defaultdict(lambda: deque(maxlen=64))
        self._ack_anomalies: Dict[str, deque] = defaultdict(lambda: deque(maxlen=64))
        self._ttl_anomalies: Dict[str, deque] = defaultdict(lambda: deque(maxlen=64))
        self._last_cleanup = time.time()
        self._lock = Lock()
        cfg = config or {}
        thresholds = cfg.get("thresholds", {})
        self._seq_threshold = thresholds.get("seq_covert_chars", 8)
        self._seq_samples = thresholds.get("seq_covert_samples", 10)
        self._ack_threshold = thresholds.get("ack_covert_chars", 15)
        self._ack_samples = thresholds.get("ack_covert_samples", 10)
        self._ttl_window = thresholds.get("ttl_covert_window", 15)
        self._ttl_variations = thresholds.get("ttl_covert_variations", 6)
        self._window = cfg.get("adaptive_window", 300)
        self._seq_baseline: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._ack_baseline: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._ttl_baseline: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        # ponytail: running [n, mean, M2] per (baseline, ip) — reverse-Welford
        # on expiry keeps 3σ checks O(1). Recomputing over the 1000-entry
        # window 2×/packet cost 7.4s per 65k SYNs in profiler.
        self._wstats: Dict[tuple, list] = {}

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        with self._lock:
            return self._analyze_locked(packet)

    def _analyze_locked(self, packet: Dict) -> Optional[List[Dict]]:
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

    @staticmethod
    def _evict(stats, x):
        # ponytail: single removal path — both time-expiry and maxlen-eviction
        # must reverse-update, else stats desync from deque contents.
        n, mean, m2 = stats
        if n > 1:
            delta = x - mean
            mean -= delta / (n - 1)
            m2 -= delta * (x - mean)
            n -= 1
        else:
            n, mean, m2 = 0, 0.0, 0.0
        stats[:] = [n, mean, m2 if m2 > 0 else 0.0]

    def _prune(self, dq, stats, now):
        cutoff = now - self._window
        while dq and dq[0][0] < cutoff:
            _, x = dq.popleft()
            self._evict(stats, x)

    def _is_adaptive_outlier(self, ip, baseline_map, value, now=None):
        if now is None:
            now = time.time()
        dq = baseline_map[ip]
        key = (id(baseline_map), ip)
        stats = self._wstats.get(key)
        if stats is None:
            stats = [0, 0.0, 0.0]
            self._wstats[key] = stats
        self._prune(dq, stats, now)
        n, mean, m2 = stats
        outlier = False
        if n >= 3:
            std = math.sqrt(m2 / (n - 1)) if m2 > 0 else 0.0
            outlier = (value != mean) if std == 0 else abs(value - mean) > 3 * std
        n += 1
        delta = value - mean
        mean += delta / n
        m2 += delta * (value - mean)
        stats[:] = [n, mean, m2]
        if len(dq) == dq.maxlen:
            _, x = dq.popleft()
            self._evict(stats, x)
        dq.append((now, value))
        return outlier

    def _check_seq_covert(self, ip, seq):
        last_bytes = seq & 0xFF
        self._seq_anomalies[ip].append(last_bytes)
        recent = list(self._seq_anomalies[ip])[-25:]
        adaptive_hit = self._is_adaptive_outlier(ip, self._seq_baseline, last_bytes)
        if len(recent) >= self._seq_samples:
            chars = []
            for i in range(len(recent) - 1):
                diff = (recent[i + 1] - recent[i]) & 0xFF
                if 32 <= diff <= 126:
                    chars.append(chr(diff))
            if len(chars) >= self._seq_threshold and adaptive_hit:
                data = "".join(chars[-self._seq_threshold:])
                distinct = len(set(data))
                if distinct > max(3, len(data) * 0.7):
                    return None
                return {"attack_type": "seq_covert_channel", "severity": "high", "source_ip": ip,
                        "details": f"Seq number encoding: '{data}'"}
        return None

    def _check_ack_covert(self, ip, ack, flags):
        if "A" not in flags:
            return None
        last_bytes = ack & 0xFF
        self._ack_anomalies[ip].append(last_bytes)
        recent = list(self._ack_anomalies[ip])[-25:]
        adaptive_hit = self._is_adaptive_outlier(ip, self._ack_baseline, last_bytes)
        if len(recent) >= self._ack_samples:
            chars = []
            for i in range(len(recent) - 1):
                diff = (recent[i + 1] - recent[i]) & 0xFF
                if 32 <= diff <= 126:
                    chars.append(chr(diff))
            if len(chars) >= self._ack_threshold and adaptive_hit:
                data = "".join(chars[-self._ack_threshold:])
                distinct = len(set(data))
                if distinct > max(3, len(data) * 0.7):
                    return None
                return {"attack_type": "ack_covert_channel", "severity": "high", "source_ip": ip,
                        "details": f"ACK number encoding: '{data}'"}
        return None

    def _check_ttl_covert(self, ip, ttl):
        self._ttl_anomalies[ip].append(ttl)
        recent = list(self._ttl_anomalies[ip])[-self._ttl_window:]
        adaptive_hit = self._is_adaptive_outlier(ip, self._ttl_baseline, ttl)
        if len(recent) >= self._ttl_window and len(set(recent)) >= self._ttl_variations and adaptive_hit:
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
        except Exception as e:
            logger.warning(f"[Covert] Header parse failed: {e}")
        return None

    def _cleanup_if_needed(self):
        if time.time() - self._last_cleanup > 60:
            self._seq_anomalies.clear()
            self._ack_anomalies.clear()
            self._ttl_anomalies.clear()
            now = time.time()
            for baseline in (self._seq_baseline, self._ack_baseline, self._ttl_baseline):
                for ip, dq in baseline.items():
                    key = (id(baseline), ip)
                    stats = self._wstats.get(key)
                    if stats is None:
                        stats = [0, 0.0, 0.0]
                        self._wstats[key] = stats
                    self._prune(dq, stats, now)
                    if not dq:
                        del self._wstats[key]
            self._last_cleanup = time.time()
