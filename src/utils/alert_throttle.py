"""Per-(attack_type, ip) alert cooldown — one alert per incident, not per packet.

Without this a single nmap run emits ~1300 identical alerts (DB spam,
webhook rate-limit bans, real signal buried). Forensics are unaffected:
every detection is still recorded in the attacks table.
"""

import time


class AlertThrottle:
    def __init__(self, cooldown_seconds: int = 900, max_keys: int = 10000):
        self.cooldown = cooldown_seconds
        self.max_keys = max_keys
        self._last: dict = {}

    def allow(self, attack_type: str, ip: str) -> bool:
        """True if an alert for this key may fire now (records the firing)."""
        now = time.monotonic()
        key = f"{attack_type}:{ip}"
        if now - self._last.get(key, 0) < self.cooldown:
            return False
        if len(self._last) >= self.max_keys:
            # ponytail: dict prune, not LRU — unbounded growth is the only
            # risk here and a full reset is the cheapest correct bound.
            self._last.clear()
        self._last[key] = now
        return True
