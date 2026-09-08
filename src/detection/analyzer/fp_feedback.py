import logging
import time
from threading import Lock
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class FPFeedback:
    def __init__(self, config: Optional[Dict] = None):
        cfg = config or {}
        self._max_unconfirmed = cfg.get("max_unconfirmed", 3)
        self._max_unconfirmed_escalated = cfg.get("max_unconfirmed_escalated", 6)
        self._multiplier_step = cfg.get("multiplier_step", 1.5)
        self._cleanup_age = cfg.get("cleanup_age_seconds", 3600)
        self._lock = Lock()
        self._records: Dict[Tuple[str, str], Dict] = {}

    def record_detection(self, ip: str, attack_type: str) -> None:
        with self._lock:
            self._maybe_cleanup()
            key = (ip, attack_type)
            now = time.time()
            if key in self._records:
                self._records[key]["count"] += 1
                self._records[key]["last_seen"] = now
            else:
                self._records[key] = {
                    "count": 1,
                    "first_seen": now,
                    "last_seen": now,
                }

    def confirm_true_positive(self, ip: str, attack_type: str) -> None:
        with self._lock:
            self._records.pop((ip, attack_type), None)

    def get_raised_thresholds(self) -> Dict[str, float]:
        with self._lock:
            self._maybe_cleanup()
            multipliers: Dict[str, float] = {}
            type_max: Dict[str, int] = {}
            for (ip, atype), rec in self._records.items():
                c = rec["count"]
                if c >= self._max_unconfirmed:
                    if atype not in type_max or c > type_max[atype]:
                        type_max[atype] = c
            for atype, count in type_max.items():
                if count >= self._max_unconfirmed_escalated:
                    multipliers[atype] = self._multiplier_step * 2
                else:
                    multipliers[atype] = self._multiplier_step
            return multipliers

    def is_dampened(self, ip: str, attack_type: str) -> bool:
        with self._lock:
            rec = self._records.get((ip, attack_type))
            if rec is None:
                return False
            return rec["count"] >= self._max_unconfirmed

    def _maybe_cleanup(self):
        cutoff = time.time() - self._cleanup_age
        self._records = {
            k: v for k, v in self._records.items() if v["last_seen"] > cutoff
        }
