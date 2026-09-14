"""Behavioral analyzer: same FP-flood defect class as timing_analyzer.

Every detector here keeps its sliding window after firing and had no
suppression, so an IP that crossed a threshold once stayed a permanent
detection source. `_check_proto_switch` was the worst: it accumulated
`_protocol_use` outside the 120s full reset and returned on every packet once
the host had used 3 protocols, so any device speaking TCP+UDP+DNS emitted a
`proto_scan` detection per packet indefinitely.
"""

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from detection.analyzer.behavioral_analyzer import BehavioralAnalyzer  # noqa: E402

_FAKE_NOW = [1_000_000.0]


@pytest.fixture(autouse=True)
def _patch_clock(monkeypatch):
    import detection.analyzer.behavioral_analyzer as mod
    monkeypatch.setattr(mod.time, "time", lambda: _FAKE_NOW[0])
    monkeypatch.setattr(mod.time, "monotonic", lambda: _FAKE_NOW[0])
    _FAKE_NOW[0] = 1_000_000.0
    yield


def _syn(src="203.0.113.5", dst="198.51.100.9"):
    return {"src_ip": src, "dst_ip": dst, "dst_port": 80,
            "flags": "S", "protocol": "tcp", "payload": b""}


def _run(analyzer, packets):
    out = []
    for p in packets:
        r = analyzer.analyze(p)
        if r:
            out.extend(r)
    return out


class TestProtoScanFlood:
    def test_multi_protocol_host_does_not_alert_per_packet(self):
        """The live defect: hundreds of identical proto_scan alerts."""
        a = BehavioralAnalyzer()
        pkts = []
        for proto in ("tcp", "udp", "dns"):
            for _ in range(80):
                pkts.append({"src_ip": "192.168.1.60", "dst_ip": "198.51.100.9",
                             "dst_port": 443, "flags": "A", "protocol": proto,
                             "payload": b""})
        alerts = _run(a, pkts)
        proto_alerts = [d for d in alerts if d["attack_type"] == "proto_scan"]
        assert len(proto_alerts) <= 1, (
            f"{len(proto_alerts)} proto_scan alerts from one episode"
        )

    def test_low_volume_multi_protocol_host_is_silent(self):
        """A phone doing TCP+UDP+DNS is not probing."""
        a = BehavioralAnalyzer()
        pkts = []
        for proto in ("tcp", "udp", "dns"):
            for _ in range(5):
                pkts.append({"src_ip": "192.168.1.61", "dst_ip": "198.51.100.9",
                             "dst_port": 443, "flags": "A", "protocol": proto,
                             "payload": b""})
        assert _run(a, pkts) == []


class TestSynBurstDoesNotSpam:
    def test_syn_flood_alerts_once_not_per_syn(self):
        a = BehavioralAnalyzer()
        pkts = []
        for _ in range(400):
            _FAKE_NOW[0] += 0.001     # 1000 SYN/s for 0.4s
            pkts.append(_syn(src="203.0.113.10"))
        alerts = _run(a, pkts)
        syn = [d for d in alerts if d["attack_type"] == "syn_burst"]
        assert len(syn) <= 1, f"{len(syn)} syn_burst alerts for one flood"

    def test_real_syn_flood_still_detected(self):
        a = BehavioralAnalyzer()
        alerts = []
        for _ in range(60):
            _FAKE_NOW[0] += 0.01
            r = a.analyze(_syn(src="203.0.113.11"))
            if r:
                alerts.extend(r)
        assert any(d["attack_type"] == "syn_burst" for d in alerts), alerts

    def test_normal_browsing_is_silent(self):
        a = BehavioralAnalyzer()
        for _ in range(10):
            _FAKE_NOW[0] += 20
            a.analyze(_syn(src="192.168.1.70"))
        assert _run(a, []) == []


class TestShortConnections:
    def test_scan_pattern_alerts_once(self):
        a = BehavioralAnalyzer()
        alerts = []
        for _ in range(60):
            _FAKE_NOW[0] += 0.01
            a.analyze({"src_ip": "203.0.113.20", "dst_ip": "198.51.100.9",
                       "dst_port": 22, "flags": "S", "protocol": "tcp",
                       "payload": b""})
            _FAKE_NOW[0] += 0.01
            r = a.analyze({"src_ip": "203.0.113.20", "dst_ip": "198.51.100.9",
                           "dst_port": 22, "flags": "F", "protocol": "tcp",
                           "payload": b""})
            if r:
                alerts.extend(r)
        short = [d for d in alerts if d["attack_type"] == "short_connection"]
        assert len(short) <= 1, f"{len(short)} short_connection alerts"


class TestHygiene:
    def test_broadcast_and_dhcp_skipped(self):
        a = BehavioralAnalyzer()
        for _ in range(100):
            assert a.analyze({"src_ip": "192.168.1.5", "dst_ip": "255.255.255.255",
                              "dst_port": 68, "flags": "", "protocol": "udp",
                              "payload": b""}) is None

    def test_never_raises_on_malformed_packet(self):
        a = BehavioralAnalyzer()
        a.analyze({})
        a.analyze({"src_ip": None, "dst_ip": None, "dst_port": None,
                   "flags": None, "protocol": None, "payload": None})
        a.analyze({"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "dst_port": 80,
                   "flags": "F", "protocol": "tcp", "payload": "a string"})

    def test_cooldown_expires(self):
        a = BehavioralAnalyzer(cooldown_seconds=10)
        first = []
        for _ in range(60):
            _FAKE_NOW[0] += 0.01
            r = a.analyze(_syn(src="203.0.113.30"))
            if r:
                first.extend(r)
        assert first
        _FAKE_NOW[0] += 60          # past the cooldown
        second = []
        for _ in range(60):
            _FAKE_NOW[0] += 0.01
            r = a.analyze(_syn(src="203.0.113.30"))
            if r:
                second.extend(r)
        assert second, "a new burst after cooldown should alert again"
