"""Alert gate — one place that stops detectors repeating themselves.

Every analyzer in `src/detection/` keeps its evidence in a sliding window. When
that window starts matching, it keeps matching: the condition that triggered the
alert is still in the window on the next packet, and the packet after that. So a
detector does not report an *episode*, it reports every packet in that episode.

Measured consequences on the bundled corpora before this gate:

| capture                  | detector   | alerts | distinct sources |
|--------------------------|------------|--------|------------------|
| nmap_syn_scan (1 attacker)| syn_flood  | 3,202  | 1                |
| nmap_syn_scan             | port_scan  | 2,718  | 1                |
| nmap_syn_scan             | low_entropy_isn | 2,648 | 1               |
| benign web_traffic        | low_entropy_isn | 71  | 24               |
| idle WiFi, 120s, live     | timing_evasion | 121  | few              |

Fixing that detector-by-detector means editing ~15 files and re-deriving each
one's window-reset semantics, and the next analyzer added reintroduces the bug.
This gate sits where detections are collected, so the behaviour is uniform.

Design:

* **Per (source IP, attack type), not global.** Two attackers stay two alerts;
  a new attack type from the same host is not suppressed by an older one.
* **Cooldown, not "once ever".** A sustained attack still re-alerts periodically
  so a dashboard shows it is ongoing. `ALERT_COOLDOWN_SECONDS`.
* **First sighting always passes.** No cold-start blind spot — the gate never
  delays or drops the initial detection.
* **Bounded memory.** Entries are pruned on a timer; a busy sensor with many
  source IPs cannot grow the table without limit.
* **Never raises.** It sits on the verdict path.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# How long one (ip, attack_type) pair stays quiet after alerting. Long enough
# that a flood produces a handful of alerts instead of thousands, short enough
# that an ongoing attack still refreshes on a dashboard.
ALERT_COOLDOWN_SECONDS = 300.0

# Prune the table at most this often.
_PRUNE_INTERVAL_SECONDS = 60.0

# Hard cap. If a sensor is seeing more distinct (ip, type) pairs than this, the
# entries are being pruned anyway; the cap stops unbounded growth if pruning is
# somehow starved.
_MAX_ENTRIES = 50_000


class AlertGate:
    """Suppress repeated alerts for the same source and attack type."""

    def __init__(self, cooldown_seconds: float = ALERT_COOLDOWN_SECONDS):
        self._cooldown = float(cooldown_seconds)
        self._last: Dict[Tuple[str, str], float] = {}
        self._lock = threading.Lock()
        self._last_prune = time.monotonic()
        # Observability: how much noise this gate is absorbing. Surfaced in
        # stats so "detections" and "alerts" can be told apart.
        self.suppressed_total = 0
        self.passed_total = 0

    def filter(self, detections: Optional[List[Dict]],
               source_ip: str = "") -> Optional[List[Dict]]:
        """Return only the detections that should become alerts.

        Detections that are pure detail (no attack_type) are passed through.
        """
        if not detections:
            return None

        now = time.monotonic()
        passed: List[Dict] = []
        suppressed = 0

        with self._lock:
            self._prune_locked(now)
            for d in detections:
                atype = d.get("attack_type")
                if not atype:
                    passed.append(d)
                    continue
                ip = d.get("source_ip") or source_ip or "unknown"
                key = (ip, atype)
                last = self._last.get(key)
                if last is not None and (now - last) < self._cooldown:
                    suppressed += 1
                    continue
                # Keep the earliest timestamp for the key so a sustained attack
                # does not keep pushing its own re-alert further into the future.
                self._last[key] = now
                passed.append(d)

            self.passed_total += len(passed)
            self.suppressed_total += suppressed

        return passed if passed else None

    def _prune_locked(self, now: float):
        if (now - self._last_prune) < _PRUNE_INTERVAL_SECONDS and \
                len(self._last) < _MAX_ENTRIES:
            return
        cutoff = now - self._cooldown
        stale = [k for k, ts in self._last.items() if ts < cutoff]
        for k in stale:
            del self._last[k]
        if len(self._last) > _MAX_ENTRIES:
            # Keep the most recent entries; the rest are about to expire anyway.
            newest = sorted(self._last.items(), key=lambda kv: kv[1], reverse=True)
            self._last = dict(newest[:_MAX_ENTRIES])
        self._last_prune = now

    def stats(self) -> Dict:
        with self._lock:
            return {
                "alerts_passed": self.passed_total,
                "alerts_suppressed": self.suppressed_total,
                "tracked_pairs": len(self._last),
                "cooldown_seconds": self._cooldown,
            }

    def reset(self):
        with self._lock:
            self._last.clear()
