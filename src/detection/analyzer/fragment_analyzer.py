import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class FragmentAnalyzer:
    def __init__(self):
        self._frag_tracker: Dict[str, List[Dict]] = defaultdict(list)
        self._last_cleanup = time.time()
        self._lock = Lock()
        self._cleanup_interval = 60

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        with self._lock:
            return self._analyze_locked(packet)
    def _analyze_locked(self, packet: Dict) -> Optional[List[Dict]]:
        detections = []
        self._cleanup_if_needed()

        frag_offset = packet.get("frag_offset", 0)
        more_frags = packet.get("more_fragments", False) or (
            packet.get("flags", "") and "M" in packet.get("flags", "")
        )
        payload_len = packet.get("payload_len", 0)
        total_len = packet.get("raw_len", 0)
        protocol = packet.get("protocol", "")
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        ident = packet.get("ip_id", 0)

        if not frag_offset and not more_frags:
            return None

        frag_key = (src_ip, dst_ip, ident, protocol)
        entry = {
            "offset": frag_offset,
            "more": more_frags,
            "len": payload_len or total_len,
            "time": time.time(),
        }
        self._frag_tracker[frag_key].append(entry)

        entries = self._frag_tracker[frag_key]

        if len(entries) > 64:
            detections.append({
                "attack_type": "fragment_storm",
                "severity": "high",
                "source_ip": src_ip,
                "details": f"Excessive fragments: {len(entries)} for {ident}",
            })
            self._frag_tracker[frag_key] = []

        offsets = sorted(e["offset"] for e in entries)
        for i in range(len(offsets) - 1):
            if offsets[i] == offsets[i + 1]:
                detections.append({
                    "attack_type": "fragment_overlap",
                    "severity": "high",
                    "source_ip": src_ip,
                    "details": f"Overlapping fragments at offset {offsets[i]}",
                })
                break

        if len(entries) >= 2:
            first_end = entries[0]["offset"] + entries[0]["len"]
            for e in entries[1:]:
                if e["offset"] < first_end:
                    detections.append({
                        "attack_type": "fragment_overlap",
                        "severity": "high",
                        "source_ip": src_ip,
                        "details": f"Tiny fragment overlap offset={e['offset']}",
                    })
                    break

        if entries and entries[-1]["len"] < 100 and entries[-1]["more"]:
            detections.append({
                "attack_type": "tiny_fragment",
                "severity": "medium",
                "source_ip": src_ip,
                "details": f"Tiny fragment: {entries[-1]['len']} bytes, abuse overlap",
            })

        prev_total = sum(e["len"] for e in entries)
        if prev_total > 65535 and protocol == "tcp":
            detections.append({
                "attack_type": "fragment_oversize",
                "severity": "critical",
                "source_ip": src_ip,
                "details": f"Reassembled size {prev_total} exceeds 65535",
            })

        return detections if detections else None

    def _cleanup_if_needed(self):
        now = time.time()
        if now - self._last_cleanup > self._cleanup_interval:
            cutoff = now - 120
            stale = [k for k, v in self._frag_tracker.items()
                     if not v or v[-1]["time"] < cutoff]
            for k in stale:
                del self._frag_tracker[k]
            self._last_cleanup = now
