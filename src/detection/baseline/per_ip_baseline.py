import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class WelfordOnline:
    """Online Welford algorithm for streaming mean/variance."""
    def __init__(self):
        self._n = 0
        self._mean = 0.0
        self._m2 = 0.0

    def update(self, value: float):
        self._n += 1
        delta = value - self._mean
        self._mean += delta / self._n
        delta2 = value - self._mean
        self._m2 += delta * delta2

    @property
    def mean(self) -> float:
        return self._mean

    @property
    def variance(self) -> float:
        return self._m2 / self._n if self._n > 1 else 0.0

    @property
    def std(self) -> float:
        return self.variance ** 0.5

    @property
    def n(self) -> int:
        return self._n

    def z_score(self, value: float) -> float:
        if self._n < 5 or self.std < 0.001:
            return 0.0
        return (value - self._mean) / self.std


class PerIPBaseline:
    def __init__(self, config: dict = None):
        self._config = config or {}
        self._pps: Dict[str, WelfordOnline] = defaultdict(WelfordOnline)
        self._bps: Dict[str, WelfordOnline] = defaultdict(WelfordOnline)
        self._cpm: Dict[str, WelfordOnline] = defaultdict(WelfordOnline)
        self._protocol_dist: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._hour_activity: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        self._window_pps: Dict[str, List[Tuple[float, int, int]]] = defaultdict(list)
        self._lock = Lock()
        self._last_cleanup = time.time()
        self._last_hour = -1
        self._adaptive_rate = config.get("adaptive_rate", 0.05) if config else 0.05
        self._z_threshold = config.get("z_threshold", 3.0) if config else 3.0

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        self._cleanup_if_needed()
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        protocol = packet.get("protocol", "")
        plen = len(packet.get("payload", b"")) + 40
        now = time.time()
        hour = time.localtime(now).tm_hour

        detections = []

        if not src_ip:
            return None

        with self._lock:
            self._hour_activity[src_ip][hour] += 1
            self._protocol_dist[src_ip][protocol] += 1
            self._window_pps[src_ip].append((now, plen, 1))

            recent = [(t, b, c) for t, b, c in self._window_pps[src_ip] if now - t < 60]
            self._window_pps[src_ip] = recent

            if len(recent) >= 10:
                window_pps = sum(c for _, _, c in recent) / 60
                window_bps = sum(b for _, b, _ in recent) * 8 / 60

                pps_z = self._pps[src_ip].z_score(window_pps)
                if abs(pps_z) > self._z_threshold:
                    detections.append({
                        "attack_type": "baseline_pps_anomaly",
                        "severity": "medium" if abs(pps_z) < 5 else "high",
                        "source_ip": src_ip,
                        "details": f"PPS Z-score={pps_z:.1f} (baseline {self._pps[src_ip].mean:.1f}, current {window_pps:.1f})",
                        "confidence": min(0.5 + abs(pps_z) * 0.07, 0.95),
                        "mitre": [],
                    })

                bps_z = self._bps[src_ip].z_score(window_bps)
                if abs(bps_z) > self._z_threshold:
                    detections.append({
                        "attack_type": "baseline_bps_anomaly",
                        "severity": "medium" if abs(bps_z) < 5 else "high",
                        "source_ip": src_ip,
                        "details": f"BPS Z-score={bps_z:.1f} (baseline {self._bps[src_ip].mean:.0f}, current {window_bps:.0f})",
                        "confidence": min(0.5 + abs(bps_z) * 0.07, 0.95),
                        "mitre": [],
                    })

                if self._pps[src_ip].n < 50 or abs(pps_z) < self._z_threshold:
                    lr = self._adaptive_rate / (1 + abs(pps_z)) if abs(pps_z) > 1 else self._adaptive_rate
                    self._pps[src_ip].update(window_pps)
                    self._bps[src_ip].update(window_bps)

            if self._last_hour != hour and self._hour_activity[src_ip].get(hour, 0) < 2:
                near_midnight = hour < 6 or hour > 22
                if near_midnight and self._hour_activity[src_ip].get(hour, 0) > 0:
                    total_hours = len([h for h, c in self._hour_activity[src_ip].items() if c > 0])
                    if total_hours > 0:
                        ratio = sum(1 for h in range(24) if self._hour_activity[src_ip].get(h, 0) > 0) / 24
                        if ratio < 0.3:
                            detections.append({
                                "attack_type": "unusual_hours_activity",
                                "severity": "low",
                                "source_ip": src_ip,
                                "details": f"Unusual activity at hour {hour}:00 (normally {ratio:.0%} of hours active)",
                                "confidence": 0.3,
                                "mitre": [],
                            })

            self._last_hour = hour

        return detections if detections else None

    def _cleanup_if_needed(self):
        if time.time() - self._last_cleanup > 300:
            with self._lock:
                cutoff = time.time() - 86400
                stale = [k for k, v in self._window_pps.items() if not v or v[-1][0] < cutoff]
                for k in stale:
                    del self._window_pps[k]
                    del self._pps[k]
                    del self._bps[k]
                    del self._cpm[k]
                    if k in self._protocol_dist:
                        del self._protocol_dist[k]
                    if k in self._hour_activity:
                        del self._hour_activity[k]
                self._last_cleanup = time.time()
