import logging
import time
from collections import defaultdict
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class TimingAnalyzer:
    def __init__(self):
        self._slow_loris: Dict[str, List[float]] = defaultdict(list)
        self._inter_arrival: Dict[str, List[float]] = defaultdict(list)
        self._time_gaps: Dict[str, List[float]] = defaultdict(list)
        self._last_cleanup = time.time()

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        detections = []
        self._cleanup_if_needed()

        src_ip = packet.get("src_ip", "")
        protocol = packet.get("protocol", "")
        flags = packet.get("flags", "")
        payload = packet.get("payload", b"")

        now = time.time()

        r = self._check_slow_loris(src_ip, now, flags, payload)
        if r:
            detections.append(r)

        r = self._check_timing_gap(src_ip, now, flags)
        if r:
            detections.append(r)

        r = self._check_inter_arrival(src_ip, now)
        if r:
            detections.append(r)

        return detections if detections else None

    def _check_slow_loris(self, ip, now, flags, payload):
        if "S" in flags and "A" not in flags:
            self._slow_loris[ip].append(now)
            recent_syn = self._slow_loris[ip][-20:]
            if len(recent_syn) >= 10:
                window = recent_syn[-1] - recent_syn[0]
                if window < 0.5:
                    return None
                rate = len(recent_syn) / window if window > 0 else 0
                if rate > 50:
                    self._slow_loris[ip] = []
                    return {
                        "attack_type": "slow_loris",
                        "severity": "high",
                        "source_ip": ip,
                        "details": f"Slow loris: {rate:.0f} partial connections/sec",
                    }
        return None

    def _check_timing_gap(self, ip, now, flags):
        self._time_gaps[ip].append(now)
        recent = self._time_gaps[ip][-30:]
        if len(recent) >= 3:
            gaps = [recent[i + 1] - recent[i] for i in range(len(recent) - 1)]
            max_gap = max(gaps)
            min_gap = min(gaps)
            if max_gap > 10 and min_gap < 0.1:
                return {
                    "attack_type": "timing_evasion",
                    "severity": "medium",
                    "source_ip": ip,
                    "details": f"Timing gap: bursts ({min_gap*1000:.0f}ms) with pauses ({max_gap:.0f}s)",
                }
        return None

    def _check_inter_arrival(self, ip, now):
        self._inter_arrival[ip].append(now)
        recent = self._inter_arrival[ip][-50:]
        if len(recent) >= 10:
            intervals = [recent[i + 1] - recent[i] for i in range(len(recent) - 1)]
            if intervals:
                avg = sum(intervals) / len(intervals)
                if avg > 5 and avg < 30:
                    variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
                    if variance < 0.1:
                        return {
                            "attack_type": "timed_probe",
                            "severity": "medium",
                            "source_ip": ip,
                            "details": f"Uniform timing: avg {avg*1000:.0f}ms ±{variance**0.5*1000:.0f}ms (scripted)",
                        }
        return None

    def _cleanup_if_needed(self):
        if time.time() - self._last_cleanup > 60:
            for store in (self._slow_loris, self._inter_arrival, self._time_gaps):
                cutoff = time.time() - 120
                stale = [k for k, v in store.items() if not v or v[-1] < cutoff]
                for k in stale:
                    del store[k]
            self._last_cleanup = time.time()
