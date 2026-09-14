import logging
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Per-IP, per-detector suppression window. Same defect class as
# timing_analyzer: a detector whose sliding window keeps holding its trigger
# condition re-reported on every subsequent packet. These detectors all keep
# their window after firing, so an IP that ever crossed a threshold stayed a
# permanent detection source — on a live run that turned into tens of
# thousands of identical alert rows per hour.
DEFAULT_COOLDOWN_SECONDS = 300.0


class BehavioralAnalyzer:
    def __init__(self, cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS):
        self._syn_rates: Dict[str, deque] = defaultdict(lambda: deque(maxlen=60))
        self._packet_rates: Dict[str, deque] = defaultdict(lambda: deque(maxlen=120))
        self._protocol_use: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._conn_durations: Dict[str, deque] = defaultdict(lambda: deque(maxlen=30))
        self._conn_open: Dict[str, float] = {}
        self._last_cleanup = time.time()
        self._lock = Lock()
        self._cooldown = float(cooldown_seconds)
        self._last_alert: Dict[str, Dict[str, float]] = defaultdict(dict)

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        with self._lock:
            return self._analyze_locked(packet)

    def _suppressed(self, ip: str, attack_type: str) -> bool:
        last = self._last_alert.get(ip, {}).get(attack_type)
        if last is None:
            return False
        return (time.monotonic() - last) < self._cooldown

    def _keep(self, detections: List[Dict], ip: str,
              reset: Optional[str] = None) -> Optional[List[Dict]]:
        """Drop detections still inside their cooldown; record the rest.

        `reset` names the sample store to clear so the same episode cannot
        re-trigger the moment the cooldown lapses.
        """
        kept = []
        for d in detections:
            atype = d.get("attack_type", "unknown")
            if self._suppressed(ip, atype):
                continue
            self._last_alert[ip][atype] = time.monotonic()
            kept.append(d)
            if reset == "syn" and atype == "syn_burst":
                self._syn_rates[ip].clear()
            elif reset == "pkt" and atype == "packet_burst":
                self._packet_rates[ip].clear()
            elif reset == "conn" and atype == "short_connection":
                self._conn_durations[ip].clear()
        return kept if kept else None

    def _analyze_locked(self, packet: Dict) -> Optional[List[Dict]]:
        detections = []
        self._cleanup_if_needed()
        src_ip = packet.get("src_ip") or ""
        dst_ip = packet.get("dst_ip") or ""
        dst_port = packet.get("dst_port") or 0
        flags = packet.get("flags") or ""

        if not src_ip:
            return None

        # Skip broadcast/multicast/DHCP traffic to avoid FP
        if dst_ip.startswith("255.") or dst_ip.startswith("224.") or dst_ip.startswith("239."):
            return None
        if dst_ip == "0.0.0.0" or dst_ip == "255.255.255.255":
            return None
        if dst_port in (67, 68, 5353, 1900):
            return None

        r = self._check_syn_burst(src_ip, flags)
        if r:
            detections.append(r)

        r = self._check_packet_burst(src_ip)
        if r:
            detections.append(r)

        r = self._check_payload_bias(src_ip, packet)
        if r:
            detections.append(r)

        r = self._check_proto_switch(src_ip, packet)
        if r:
            detections.append(r)

        if "S" in str(flags) and "A" not in str(flags):
            self._conn_open[src_ip] = time.time()
        if "F" in str(flags) or "R" in str(flags):
            if src_ip in self._conn_open:
                duration = time.time() - self._conn_open[src_ip]
                self._conn_durations[src_ip].append(duration)
                del self._conn_open[src_ip]
                r = self._check_short_connections(src_ip, duration)
                if r:
                    detections.append(r)

        self._packet_rates[src_ip].append(time.time())
        kept = self._keep(detections, src_ip, reset="syn")
        if kept is None:
            return None
        # Apply the remaining per-type resets/cooldowns recorded inside _keep.
        return kept

    def _check_syn_burst(self, ip: str, flags: str) -> Optional[Dict]:
        if "S" not in str(flags) or "A" in str(flags):
            return None
        now = time.time()
        self._syn_rates[ip].append(now)
        recent = [t for t in self._syn_rates[ip] if now - t < 5]
        if len(recent) >= 50:
            return {
                "attack_type": "syn_burst",
                "severity": "high",
                "source_ip": ip,
                "details": f"SYN flood/burst: {len(recent)} SYNs in 5s (possible port scan or DoS)",
            }
        if len(recent) >= 20:
            return {
                "attack_type": "syn_burst",
                "severity": "medium",
                "source_ip": ip,
                "details": f"Elevated SYN rate: {len(recent)} SYNs in 5s (possible scan)",
            }
        return None

    def _check_packet_burst(self, ip: str) -> Optional[Dict]:
        now = time.time()
        recent = [t for t in self._packet_rates[ip] if now - t < 3]
        if len(recent) >= 500:
            return {
                "attack_type": "packet_burst",
                "severity": "medium",
                "source_ip": ip,
                "details": f"Packet burst: {len(recent)} pkts in 3s (possible DoS)",
            }
        return None

    @staticmethod
    def _check_payload_bias(ip: str, packet: Dict) -> Optional[Dict]:
        payload = packet.get("payload") or b""
        if not isinstance(payload, (bytes, bytearray)):
            return None
        plen = len(payload)
        if plen == 0:
            return None
        flags = str(packet.get("flags") or "")
        if "P" in flags and plen == 1:
            return {
                "attack_type": "slow_drip",
                "severity": "medium",
                "source_ip": ip,
                "details": "1-byte PUSH payload (slow loris/drip attack)",
            }
        return None

    def _check_proto_switch(self, ip: str, packet: Dict) -> Optional[Dict]:
        """Flag multi-protocol use only once the host is clearly probing.

        The old version returned on every packet once the host had used 3
        protocols and 20 total packets, and `_protocol_use` was never cleared
        outside the 120s full reset — so any device speaking e.g. TCP+UDP+DNS
        became a permanent `proto_scan` source. It also counts a *rising*
        protocol count as evidence, which is the opposite of the stated intent.
        """
        proto = packet.get("protocol") or "unknown"
        self._protocol_use[ip][proto] += 1
        total = sum(self._protocol_use[ip].values())
        if total < 50:
            return None
        count = len(self._protocol_use[ip])
        if count < 3:
            return None
        if self._suppressed(ip, "proto_scan"):
            return None
        return {
            "attack_type": "proto_scan",
            "severity": "low",
            "source_ip": ip,
            "details": f"Multi-protocol usage: {list(self._protocol_use[ip].keys())} (possible probing)",
        }

    def _check_short_connections(self, ip: str, duration: float) -> Optional[Dict]:
        # A single short connection is normal HTTP. Only flag if MANY
        # recent connections from the same IP are short — that's the
        # actual scan pattern.
        if duration >= 0.5:
            return None
        recent = self._conn_durations[ip]
        if len(recent) < 10:
            return None
        short_count = sum(1 for d in recent if d < 0.5)
        if short_count >= 10:
            return {
                "attack_type": "short_connection",
                "severity": "medium",
                "source_ip": ip,
                "details": f"{short_count}/{len(recent)} recent connections closed in <500ms (possible scan)",
            }
        return None

    def _cleanup_if_needed(self):
        if time.time() - self._last_cleanup > 120:
            self._syn_rates.clear()
            self._packet_rates.clear()
            self._protocol_use.clear()
            self._conn_durations.clear()
            self._conn_open.clear()
            self._last_cleanup = time.time()
        # Prune lapsed cooldowns so the dict cannot grow without bound.
        for ip in list(self._last_alert.keys()):
            live = {t: ts for t, ts in self._last_alert[ip].items()
                    if (time.monotonic() - ts) < self._cooldown}
            if live:
                self._last_alert[ip] = live
            else:
                del self._last_alert[ip]
