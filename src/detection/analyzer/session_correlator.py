import logging
import time
import re
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# The SQL-comment token `/*` must not match the ordinary HTTP header
# `Accept: */*`. That value appears on essentially every browser request, so
# the old alternation fired on every `GET / HTTP/1.1` and produced 18
# high-severity `session_correlated_sql_attack` alerts on a *benign* capture
# (docs/PRODUCTION_READINESS.md §3.3). A `/*` that is itself preceded by `*`
# is the tail of `*/*`, not a comment opener — hence the lookbehind.
_PARTIAL_SQL = re.compile(
    r"(\bunion\b|\bselect\b|\bfrom\b|\bwhere\b|\bdrop\b|\binsert\b|\bdelete\b|"
    r"'|--|(?<!\*)/\*|@@|0x[0-9a-f]|\bor\b|\band\b)",
    re.IGNORECASE
)
_PARTIAL_XSS = re.compile(
    r"(script|javascript|on\w+\s*=|alert\(|eval\(|prompt|document\.)",
    re.IGNORECASE
)
_PARTIAL_CMD = re.compile(
    r"(;|\||`|\$\(|&&|\|\||/bin/|/usr/|\.sh|cmd|powershell|wget|curl)",
    re.IGNORECASE
)
_PARTIAL_TRAVERSAL = re.compile(
    r"(\.\.|etc/|passwd|shadow|\.env|boot\.ini|win\.ini)",
    re.IGNORECASE
)


class SessionCorrelator:
    def __init__(self, window: int = 30, threshold: int = 5):
        self._window = window
        self._threshold = threshold
        self._fragments: Dict[str, List[Tuple[float, str, str]]] = defaultdict(list)
        self._last_cleanup = time.time()
        self._seen_combos: set = set()
        self._lock = Lock()

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        with self._lock:
            return self._analyze_locked(packet)

    def _analyze_locked(self, packet: Dict) -> Optional[List[Dict]]:
        self._cleanup_if_needed()
        payload = packet.get("payload", b"")
        if not payload:
            return None
        text = payload.decode("utf-8", errors="replace")
        src_ip = packet.get("src_ip", "")
        now = time.time()

        categories = []
        for category, pattern in [
            ("sql", _PARTIAL_SQL),
            ("xss", _PARTIAL_XSS),
            ("cmd", _PARTIAL_CMD),
            ("traversal", _PARTIAL_TRAVERSAL),
        ]:
            if pattern.search(text):
                categories.append(category)

        if not categories:
            return None

        for cat in categories:
            combo = (src_ip, cat)
            if combo in self._seen_combos:
                continue
            self._fragments[src_ip].append((now, cat, text[:100]))
            recent = [(t, c, _) for t, c, _ in self._fragments[src_ip] if now - t < self._window]
            cat_count = sum(1 for _, c, _ in recent if c == cat)
            if cat_count >= self._threshold:
                self._seen_combos.add(combo)
                return [{
                    "attack_type": f"session_correlated_{cat}_attack",
                    "severity": "high",
                    "source_ip": src_ip,
                    "details": f"{cat.upper()} fragments across {cat_count} requests in {self._window}s",
                }]

        return None

    def _cleanup_if_needed(self):
        if time.time() - self._last_cleanup > 60:
            self._fragments.clear()
            self._seen_combos.clear()
            self._last_cleanup = time.time()
