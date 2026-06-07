"""Tests for ThreatIntelOrchestrator TTL cache + invalidate/stats APIs."""

import os
import sys
import time
import unittest
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from intel.threat_intel import ThreatIntelOrchestrator, ThreatIntelProvider


class FakeProvider(ThreatIntelProvider):
    def __init__(self, name="fake", score=80, malicious=True, error=False):
        self._name = name
        self._score = score
        self._malicious = malicious
        self._error = error
        self.lookup_count = 0

    @property
    def name(self) -> str:
        return self._name

    def lookup_ip(self, ip: str):
        self.lookup_count += 1
        if self._error:
            raise RuntimeError("fake upstream failure")
        return {"abuse_score": self._score, "malicious": self._malicious}

    def report_ip(self, ip: str, category: int = 18, comment: str = "") -> bool:
        return True


class TestCacheTTL:
    def test_first_lookup_queries_provider(self):
        p = FakeProvider(score=80, malicious=True)
        orch = ThreatIntelOrchestrator([p], cache_ttl_seconds=60)
        r = orch.lookup_ip("1.2.3.4")
        assert r["threat_score"] == 80
        assert p.lookup_count == 1

    def test_second_lookup_within_ttl_uses_cache(self):
        p = FakeProvider()
        orch = ThreatIntelOrchestrator([p], cache_ttl_seconds=60)
        orch.lookup_ip("1.2.3.4")
        orch.lookup_ip("1.2.3.4")
        orch.lookup_ip("1.2.3.4")
        assert p.lookup_count == 1, "should hit cache on subsequent calls"

    def test_lookup_after_ttl_re_queries(self):
        p = FakeProvider()
        orch = ThreatIntelOrchestrator([p], cache_ttl_seconds=1)
        orch.lookup_ip("1.2.3.4")
        assert p.lookup_count == 1
        time.sleep(1.1)
        orch.lookup_ip("1.2.3.4")
        assert p.lookup_count == 2, "TTL-expired entry should be re-queried"

    def test_score_change_reflected_after_ttl(self):
        p = FakeProvider(score=10, malicious=False)
        orch = ThreatIntelOrchestrator([p], cache_ttl_seconds=1)
        r1 = orch.lookup_ip("1.2.3.4")
        assert r1["threat_score"] == 10
        p._score = 95
        p._malicious = True
        time.sleep(1.1)
        r2 = orch.lookup_ip("1.2.3.4")
        assert r2["threat_score"] == 95
        assert r2["is_malicious"] is True

    def test_max_cache_lru_eviction(self):
        p = FakeProvider(score=1, malicious=False)
        orch = ThreatIntelOrchestrator([p], cache_ttl_seconds=60, max_cache=3)
        for i in range(5):
            orch.lookup_ip(f"1.2.3.{i}")
        stats = orch.stats()
        assert stats["size"] == 3
        assert stats["max"] == 3

    def test_lru_promotes_recently_used(self):
        p = FakeProvider(score=1, malicious=False)
        orch = ThreatIntelOrchestrator([p], cache_ttl_seconds=60, max_cache=3)
        for i in range(3):
            orch.lookup_ip(f"1.2.3.{i}")
        orch.lookup_ip("1.2.3.0")
        orch.lookup_ip("1.2.3.3")
        assert "1.2.3.0" in orch._cache
        assert "1.2.3.1" not in orch._cache
        assert "1.2.3.2" in orch._cache
        assert "1.2.3.3" in orch._cache

    def test_provider_error_does_not_crash(self):
        p = FakeProvider(error=True)
        orch = ThreatIntelOrchestrator([p], cache_ttl_seconds=60)
        r = orch.lookup_ip("1.2.3.4")
        assert r["threat_score"] == 0
        assert r["is_malicious"] is False
        assert r["providers_checked"] == 0

    def test_invalidate_single(self):
        p = FakeProvider()
        orch = ThreatIntelOrchestrator([p], cache_ttl_seconds=3600)
        orch.lookup_ip("1.2.3.4")
        assert p.lookup_count == 1
        orch.invalidate("1.2.3.4")
        orch.lookup_ip("1.2.3.4")
        assert p.lookup_count == 2

    def test_invalidate_all(self):
        p = FakeProvider()
        orch = ThreatIntelOrchestrator([p], cache_ttl_seconds=3600)
        for i in range(3):
            orch.lookup_ip(f"1.2.3.{i}")
        orch.invalidate()
        assert orch.stats()["size"] == 0

    def test_invalidate_missing_key_does_not_raise(self):
        p = FakeProvider()
        orch = ThreatIntelOrchestrator([p], cache_ttl_seconds=3600)
        orch.invalidate("not-cached")
        orch.invalidate()

    def test_stats_shape(self):
        p = FakeProvider()
        orch = ThreatIntelOrchestrator([p], cache_ttl_seconds=1800)
        orch.lookup_ip("1.2.3.4")
        s = orch.stats()
        assert s["size"] == 1
        assert s["max"] == 10000
        assert s["ttl_seconds"] == 1800
        assert s["oldest_age_seconds"] >= 0

    def test_concurrent_lookups_no_duplicate_provider_calls(self):
        import threading
        p = FakeProvider()
        orch = ThreatIntelOrchestrator([p], cache_ttl_seconds=60)
        results = [None] * 20
        def worker(i):
            results[i] = orch.lookup_ip("1.2.3.4")
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert all(r["threat_score"] == 80 for r in results)
        assert p.lookup_count >= 1


class TestDockerfileHealthcheck:
    """Sanity check that the Dockerfile no longer references dead endpoints."""

    def test_dockerfile_does_not_reference_api_stats(self):
        path = os.path.join(os.path.dirname(__file__), "..", "docker", "Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "/api/stats" not in content, "healthcheck still references removed web dashboard"

    def test_dockerfile_uses_sqlite_healthcheck(self):
        path = os.path.join(os.path.dirname(__file__), "..", "docker", "Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "sqlite3" in content

    def test_dockerfile_does_not_switch_to_lidra_user(self):
        path = os.path.join(os.path.dirname(__file__), "..", "docker", "Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "USER lidra" not in content, "misleading non-root user line must be removed"


class TestMainLoopConfig:
    def test_main_loop_section_present(self):
        import yaml
        path = os.path.join(os.path.dirname(__file__), "..", "config", "config.yaml")
        with open(path) as f:
            cfg = yaml.safe_load(f)
        assert "main_loop" in cfg
        assert "cycle_seconds" in cfg["main_loop"]
        assert 1 <= cfg["main_loop"]["cycle_seconds"] <= 600


if __name__ == "__main__":
    unittest.main()
