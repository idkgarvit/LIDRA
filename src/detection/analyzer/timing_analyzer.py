import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Default per-IP suppression window after a timing alert fires. Without this,
# a detector whose sliding window keeps holding the trigger condition reports
# the same episode on every packet in that window (measured: 121 alerts in
# 120s on idle WiFi — see tests/test_timing_analyzer.py).
DEFAULT_COOLDOWN_SECONDS = 300.0

# A host is only "pacing" traffic if it is quiet overall. A busy host with
# bursty traffic is normal and must not be flagged.
MAX_PACKETS_FOR_EVASION = 60

# Minimum burst/pause alternations before the pattern is considered scripted.
MIN_ALTERNATIONS = 3


class TimingAnalyzer:
    def __init__(self, skip_ips: Optional[List[str]] = None,
                 cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS):
        self._slow_loris: Dict[str, List[float]] = defaultdict(list)
        self._inter_arrival: Dict[str, List[float]] = defaultdict(list)
        self._time_gaps: Dict[str, List[float]] = defaultdict(list)
        self._last_cleanup = time.time()
        self._lock = Lock()
        self._skip_ips: List[str] = skip_ips or []
        self._cooldown = float(cooldown_seconds)
        # ip -> {attack_type: last_alert_monotonic}
        self._last_alert: Dict[str, Dict[str, float]] = defaultdict(dict)

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        with self._lock:
            return self._analyze_locked(packet)

    def _suppressed(self, ip: str, attack_type: str) -> bool:
        """True if this IP+type alerted within the cooldown window."""
        last = self._last_alert.get(ip, {}).get(attack_type)
        if last is None:
            return False
        return (time.monotonic() - last) < self._cooldown

    def _mark_alert(self, ip: str, attack_type: str):
        self._last_alert[ip][attack_type] = time.monotonic()

    def _analyze_locked(self, packet: Dict) -> Optional[List[Dict]]:
        detections = []
        self._cleanup_if_needed()

        src_ip = packet.get("src_ip") or ""
        protocol = packet.get("protocol") or ""
        flags = packet.get("flags") or ""
        payload = packet.get("payload") or b""
        if not isinstance(payload, (bytes, bytearray)):
            payload = b""

        if not src_ip:
            return None
        if src_ip in self._skip_ips:
            return None

        # Skip keepalive traffic (SSH, IRC PING/PONG) to avoid FP
        if payload:
            try:
                text = bytes(payload).decode("utf-8", errors="replace").strip()
            except Exception:
                text = ""
            if text in ("\x00", "") and protocol in ("tcp",):
                return None
            if text.upper() in ("PING", "PONG"):
                return None
            if protocol == "ssh" or bytes(payload)[:8].find(b"SSH-") != -1:
                return None

        now = time.time()

        r = self._check_slow_loris(src_ip, now, flags, payload)
        if r and not self._suppressed(src_ip, r["attack_type"]):
            self._mark_alert(src_ip, r["attack_type"])
            detections.append(r)

        r = self._check_timing_gap(src_ip, now, flags)
        if r and not self._suppressed(src_ip, r["attack_type"]):
            self._mark_alert(src_ip, r["attack_type"])
            # Clear the sample so the same episode cannot re-trigger the
            # moment the cooldown lapses.
            self._time_gaps[src_ip] = []
            detections.append(r)

        r = self._check_inter_arrival(src_ip, now)
        if r and not self._suppressed(src_ip, r["attack_type"]):
            self._mark_alert(src_ip, r["attack_type"])
            self._inter_arrival[src_ip] = []
            detections.append(r)

        return detections if detections else None

    def _check_slow_loris(self, ip, now, flags, payload):
        if "S" in str(flags) and "A" not in str(flags):
            self._slow_loris[ip].append(now)
            recent_syn = self._slow_loris[ip][-20:]
            if len(recent_syn) >= 10:
                window = recent_syn[-1] - recent_syn[0]
                # Guard is div-by-zero protection only. The old 0.5s guard made
                # rate > 50 unreachable (20 samples / 0.5s = 40/s max), so this
                # detector could never fire — dead code in production.
                if window < 0.05:
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
        """Detect repeated burst/pause alternation from a quiet host.

        The previous condition — "the largest gap exceeds 10s and the smallest
        is under 0.1s" — is satisfied by any host that goes idle and then sends
        two packets close together. That is not an attack, it is every device
        with a keepalive timer, and because the sliding window kept holding the
        condition the detector re-fired on every subsequent packet (measured
        ~1 alert/second on idle WiFi).

        Timing evasion is the *repeated* alternation: send a short burst to
        stay under a rate threshold, sleep, repeat. So require several complete
        alternations, and require the host to be quiet — a busy host's bursts
        are just traffic.
        """
        self._time_gaps[ip].append(now)
        recent = self._time_gaps[ip][-60:]
        if len(recent) < 6:
            return None

        # A host generating real volume is not hiding in the gaps.
        if len(recent) > MAX_PACKETS_FOR_EVASION:
            return None

        gaps = [recent[i + 1] - recent[i] for i in range(len(recent) - 1)]
        if not gaps:
            return None

        bursts = sum(1 for g in gaps if g < 0.1)
        # Pauses are bounded above: evasion sleeps just long enough to reset a
        # rate window (seconds). A 30s+ gap is an idle host with a keepalive
        # timer, not an attacker pacing bursts — the old unbounded `> 5s`
        # counted both, which is why idle WiFi alerted once per second.
        pauses = sum(1 for g in gaps if 1.0 <= g <= 15.0)

        # Need genuine alternation, not one pause followed by chatter.
        alternations = min(bursts, pauses)
        if alternations < MIN_ALTERNATIONS:
            return None

        # Both behaviours must be present in quantity; a single long sleep in
        # an otherwise steamy flow is not evasion.
        if bursts / len(gaps) < 0.2 or pauses / len(gaps) < 0.2:
            return None

        return {
            "attack_type": "timing_evasion",
            "severity": "medium",
            "source_ip": ip,
            "details": (
                f"Repeated burst/pause pacing from a low-volume host: "
                f"{bursts} bursts under 100ms alternating with {pauses} "
                f"pauses of 1-15s across {len(recent)} packets"
            ),
        }

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
            cutoff = time.time() - 120
            for store in (self._slow_loris, self._inter_arrival, self._time_gaps):
                stale = [k for k, v in store.items() if not v or v[-1] < cutoff]
                for k in stale:
                    del store[k]
            # Prune cooldown entries whose window has lapsed so this dict does
            # not grow without bound on a busy sensor.
            for ip in list(self._last_alert.keys()):
                live = {t: ts for t, ts in self._last_alert[ip].items()
                        if (time.monotonic() - ts) < self._cooldown}
                if live:
                    self._last_alert[ip] = live
                else:
                    del self._last_alert[ip]
            self._last_cleanup = time.time()
