"""Timing analyzer: the false-positive regression that made LIDRA unusable.

Measured on a live Kali host before this fix: 121 `timing_evasion` alerts in a
120-second window on idle WiFi, ~10.8% of all captured packets, with zero
attacks present. One alert per second from a detector the user cannot turn off
means the tool is uninstalled within a day, regardless of detection rate.

The old condition was "largest gap > 10s and smallest gap < 0.1s among the last
30 packets". Any host that idles and then sends two packets close together
satisfies that, and because the sliding window kept containing the same data
the detector re-fired on every packet after it first triggered.

These tests pin both halves of the fix: real pacing is still caught, and normal
idle traffic produces nothing.
"""

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from detection.analyzer.timing_analyzer import TimingAnalyzer  # noqa: E402


def _pkt(src="203.0.113.5", flags="A", payload=b""):
    return {"src_ip": src, "protocol": "tcp", "flags": flags, "payload": payload}


def _feed(analyzer, ip, timestamps, flags="A"):
    """Feed packets at the given absolute timestamps; return all detections."""
    out = []
    for ts in timestamps:
        # Drive time.time() directly: the analyzer reads wall clock per packet.
        _set_time(ts)
        r = analyzer.analyze(_pkt(src=ip, flags=flags))
        if r:
            out.extend(r)
    return out


_FAKE_NOW = [0.0]


def _set_time(ts):
    _FAKE_NOW[0] = ts


@pytest.fixture(autouse=True)
def _patch_clock(monkeypatch):
    """TimingAnalyzer uses time.time(); drive it deterministically."""
    import detection.analyzer.timing_analyzer as mod
    monkeypatch.setattr(mod.time, "time", lambda: _FAKE_NOW[0])
    monkeypatch.setattr(mod.time, "monotonic", lambda: _FAKE_NOW[0])
    _FAKE_NOW[0] = 1_000_000.0
    yield


class TestIdleHostProducesNothing:
    """The regression that was measured live."""

    def test_keepalive_style_traffic_is_silent(self):
        """A device that idles, wakes, sends a couple of packets, repeats.

        This is what a phone or laptop does on WiFi all day. It must not alert.
        """
        a = TimingAnalyzer()
        ts = []
        t = 1_000_000.0
        for _ in range(20):
            ts.append(t)          # one packet
            ts.append(t + 0.02)   # and another 20ms later (a "burst")
            t += 30               # then half a minute idle
        alerts = _feed(a, "192.168.1.50", ts)
        assert alerts == [], f"idle host flagged: {alerts}"

    def test_single_long_pause_is_silent(self):
        a = TimingAnalyzer()
        ts = [1_000_000.0 + i * 0.01 for i in range(30)]  # a burst
        ts += [1_100_000.0, 1_100_000.02]                 # then one long pause
        assert _feed(a, "192.168.1.51", ts) == []

    def test_busy_host_with_variable_gaps_is_silent(self):
        """Duplicate reports from the live run: normal web browsing."""
        a = TimingAnalyzer()
        ts = []
        t = 1_000_000.0
        for i in range(200):
            ts.append(t)
            t += 0.5 if i % 3 else 12.0   # irregular, high-volume
        assert _feed(a, "192.168.1.52", ts) == []

    def test_repeated_identical_packets_do_not_multiply_alerts(self):
        """The core bug: one episode must not re-report on every packet."""
        a = TimingAnalyzer()
        t = 1_000_000.0
        ts = []
        for _ in range(40):
            ts.append(t)
            ts.append(t + 0.02)
            t += 8
        alerts = _feed(a, "192.168.1.53", ts)
        assert len(alerts) <= 1, f"one episode produced {len(alerts)} alerts"


class TestRealPacingIsStillCaught:
    def test_alternating_burst_and_pause_is_detected(self):
        a = TimingAnalyzer()
        ts = []
        t = 1_000_000.0
        for _ in range(6):
            for _ in range(3):
                ts.append(t)
                t += 0.02      # short burst, under any rate threshold
            t += 8            # then sleep well past it
        alerts = _feed(a, "203.0.113.77", ts)
        assert any(d["attack_type"] == "timing_evasion" for d in alerts), alerts

    def test_slow_loris_still_detected(self):
        a = TimingAnalyzer()
        ts = [1_000_000.0 + i * 0.005 for i in range(25)]  # 200 conn/s of SYNs
        alerts = _feed(a, "203.0.113.78", ts, flags="S")
        assert any(d["attack_type"] == "slow_loris" for d in alerts), alerts


class TestCooldown:
    def test_repeat_episode_is_suppressed_inside_the_window(self):
        a = TimingAnalyzer(cooldown_seconds=300)
        t = 1_000_000.0

        def episode(start, ip):
            out = []
            for _ in range(6):
                for _ in range(3):
                    _set_time(start)
                    r = a.analyze(_pkt(src=ip))
                    if r:
                        out.extend(r)
                    start += 0.02
                start += 8
            return out, start

        first, end = episode(t, "203.0.113.90")
        assert first, "first episode should alert"
        second, _ = episode(end + 1, "203.0.113.90")
        assert second == [], "repeat inside cooldown must be suppressed"

    def test_alerts_again_after_cooldown_expires(self):
        a = TimingAnalyzer(cooldown_seconds=60)
        t = 1_000_000.0

        def episode(start, ip):
            out = []
            for _ in range(6):
                for _ in range(3):
                    _set_time(start)
                    r = a.analyze(_pkt(src=ip))
                    if r:
                        out.extend(r)
                    start += 0.02
                start += 8
            return out, start

        first, end = episode(t, "203.0.113.91")
        assert first
        second, _ = episode(end + 120, "203.0.113.91")  # past the cooldown
        assert second, "a new episode after cooldown should alert"

    def test_cooldown_is_per_ip(self):
        a = TimingAnalyzer(cooldown_seconds=300)
        t = 1_000_000.0

        def episode(start, ip):
            out = []
            for _ in range(6):
                for _ in range(3):
                    _set_time(start)
                    r = a.analyze(_pkt(src=ip))
                    if r:
                        out.extend(r)
                    start += 0.02
                start += 8
            return out, start

        first, end = episode(t, "203.0.113.92")
        assert first
        other, _ = episode(end + 1, "203.0.113.93")
        assert other, "a different host must not inherit the cooldown"


class TestHygiene:
    def test_skip_ips_still_honoured(self):
        a = TimingAnalyzer(skip_ips=["203.0.113.99"])
        t = 1_000_000.0
        out = []
        for _ in range(6):
            for _ in range(3):
                _set_time(t)
                r = a.analyze(_pkt(src="203.0.113.99"))
                if r:
                    out.extend(r)
                t += 0.02
            t += 8
        assert out == []

    def test_never_raises_on_malformed_packet(self):
        a = TimingAnalyzer()
        a.analyze({})
        a.analyze({"src_ip": None, "flags": None, "payload": None})
        a.analyze({"src_ip": "1.2.3.4", "flags": "S", "payload": b"\xff\xfe"})
