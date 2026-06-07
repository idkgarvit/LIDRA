# src/intel/threat_intel.py
"""Threat Intelligence integration for LIDRA."""

from abc import ABC, abstractmethod
from typing import Optional, Dict
import logging
import threading
import time

logger = logging.getLogger(__name__)


class ThreatIntelProvider(ABC):
    """Base class for threat intelligence providers."""

    @abstractmethod
    def lookup_ip(self, ip: str) -> Optional[Dict]:
        pass

    @abstractmethod
    def report_ip(self, ip: str, category: int, comment: str = "") -> bool:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass


class ThreatIntelOrchestrator:
    """Orchestrates multiple threat intel providers with bounded, time-aware cache.

    Cache entries expire after ``cache_ttl_seconds`` (default 1h) so that
    scores from upstream providers can be re-fetched when they change.
    LRU eviction kicks in at ``max_cache`` entries.
    """

    DEFAULT_TTL = 3600
    MAX_CACHE = 10000

    def __init__(self, providers: list, check_on_detect: bool = True,
                 cache_ttl_seconds: int = DEFAULT_TTL, max_cache: int = MAX_CACHE):
        self.providers = providers
        self.check_on_detect = check_on_detect
        self._cache: Dict[str, Dict] = {}
        self._cache_order: list = []
        self._cache_timestamps: Dict[str, float] = {}
        self._cache_ttl = int(cache_ttl_seconds)
        self._max_cache = int(max_cache)
        self._lock = threading.Lock()

    def lookup_ip(self, ip: str) -> Dict:
        with self._lock:
            now = time.time()
            cached = self._cache.get(ip)
            if cached is not None:
                ts = self._cache_timestamps.get(ip, 0)
                if now - ts < self._cache_ttl:
                    try:
                        self._cache_order.remove(ip)
                    except ValueError:
                        pass
                    self._cache_order.append(ip)
                    return cached
                self._cache.pop(ip, None)
                self._cache_timestamps.pop(ip, None)
                try:
                    self._cache_order.remove(ip)
                except ValueError:
                    pass

            if len(self._cache) >= self._max_cache:
                try:
                    old = self._cache_order.pop(0)
                except IndexError:
                    old = None
                if old is not None:
                    self._cache.pop(old, None)
                    self._cache_timestamps.pop(old, None)

        results = {
            'ip': ip,
            'providers_checked': 0,
            'threat_score': 0,
            'is_malicious': False,
            'details': {}
        }

        for provider in self.providers:
            try:
                data = provider.lookup_ip(ip)
                if data:
                    results['providers_checked'] += 1
                    results['details'][provider.name] = data
                    if 'abuse_score' in data:
                        results['threat_score'] = max(results['threat_score'], data['abuse_score'])
                    if 'malicious' in data and data['malicious']:
                        results['is_malicious'] = True
            except Exception as e:
                logger.error(f"{provider.name} lookup failed: {e}")

        if results['threat_score'] >= 50:
            results['is_malicious'] = True

        with self._lock:
            self._cache[ip] = results
            self._cache_timestamps[ip] = time.time()
            try:
                self._cache_order.remove(ip)
            except ValueError:
                pass
            self._cache_order.append(ip)
        return results

    def report_ip(self, ip: str, category: int = 18, comment: str = ""):
        for provider in self.providers:
            try:
                success = provider.report_ip(ip, category, comment)
                if success:
                    logger.info(f"Reported {ip} to {provider.name}")
            except Exception as e:
                logger.error(f"Failed to report to {provider.name}: {e}")

    def invalidate(self, ip: Optional[str] = None) -> None:
        """Drop one or all cache entries (next lookup re-queries providers)."""
        with self._lock:
            if ip is None:
                self._cache.clear()
                self._cache_order.clear()
                self._cache_timestamps.clear()
            else:
                self._cache.pop(ip, None)
                self._cache_timestamps.pop(ip, None)
                try:
                    self._cache_order.remove(ip)
                except ValueError:
                    pass

    def stats(self) -> Dict:
        """Return cache stats (size, oldest entry age, TTL)."""
        with self._lock:
            now = time.time()
            oldest = min(self._cache_timestamps.values()) if self._cache_timestamps else 0
            return {
                "size": len(self._cache),
                "max": self._max_cache,
                "ttl_seconds": self._cache_ttl,
                "oldest_age_seconds": int(now - oldest) if oldest else 0,
            }
