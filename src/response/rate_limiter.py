import time
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class RateInfo:
    ip: str
    packet_count: int = 0
    syn_count: int = 0
    byte_count: int = 0
    window_start: float = 0.0
    last_packet: float = 0.0
    is_throttled: bool = False


class RateLimiter:
    def __init__(self, config: dict):
        self._lock = Lock()
        self._windows: Dict[str, RateInfo] = {}
        self._config = config
        self._packets_per_sec = config.get("packets_per_sec", 1000)
        self._syns_per_sec = config.get("syns_per_sec", 100)
        self._bytes_per_sec = config.get("bytes_per_sec", 10 * 1024 * 1024)
        self._window_seconds = config.get("window_seconds", 60)

    def check(self, ip: str, packet_type: str = "", byte_count: int = 0) -> Tuple[bool, RateInfo]:
        now = time.time()
        with self._lock:
            info = self._windows.get(ip)
            if not info:
                info = RateInfo(ip=ip, window_start=now, last_packet=now)
                self._windows[ip] = info

            elapsed = now - info.window_start
            if elapsed > self._window_seconds:
                info.packet_count = 0
                info.syn_count = 0
                info.byte_count = 0
                info.window_start = now
                info.is_throttled = False

            info.packet_count += 1
            info.byte_count += byte_count
            info.last_packet = now

            if packet_type == "syn":
                info.syn_count += 1

            rate = info.packet_count / max(elapsed, 0.1)
            syn_rate = info.syn_count / max(elapsed, 0.1)
            byte_rate = info.byte_count / max(elapsed, 0.1)

            if rate > self._packets_per_sec or syn_rate > self._syns_per_sec or byte_rate > self._bytes_per_sec:
                info.is_throttled = True
                return (True, info)

            info.is_throttled = False
            return (False, info)

    def get_rate(self, ip: str) -> Optional[RateInfo]:
        with self._lock:
            info = self._windows.get(ip)
            if info:
                now = time.time()
                elapsed = now - info.window_start
                if elapsed > self._window_seconds:
                    del self._windows[ip]
                    return None
            return info

    def get_top_talkers(self, n: int = 10) -> List[RateInfo]:
        with self._lock:
            now = time.time()
            sorted_windows = sorted(
                (info for info in self._windows.values()
                 if now - info.window_start <= self._window_seconds),
                key=lambda x: x.packet_count,
                reverse=True
            )
            return sorted_windows[:n]

    def cleanup_stale(self, window_seconds: int = 60):
        with self._lock:
            now = time.time()
            stale = [ip for ip, info in self._windows.items()
                     if now - info.last_packet > window_seconds]
            for ip in stale:
                del self._windows[ip]
            if stale:
                logger.debug(f"[RateLimiter] Cleaned {len(stale)} stale entries")
