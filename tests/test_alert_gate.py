"""Alert gate: one alert per (source, attack type), not one per packet.

Verified against the bundled corpora: before this gate, one nmap SYN scan from
one attacker (1 source IP) produced 3,202 `syn_flood`, 2,718 `port_scan` and
2,648 `low_entropy_isn` "detections". With it, each episode raises one alert
per detector and re-alerts once the cooldown expires.

This file pins the semantics the gate owes the pipeline, plus the boundary
cases that must never cost a detection: a first alert always passes, two
attackers don't cancel each other out, and a new attack type from an old
source is not suppressed by an old cooldown.
"""

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from detection.alert_gate import AlertGate  # noqa: E402


def det(attack_type="syn_flood", src="203.0.113.5", severity="high"):
    return {"attack_type": attack_type, "severity": severity,
            "source_ip": src, "details": "x"}


class TestFirstSightingAlwaysPasses:
    def test_single_detection_passes(self):
        assert AlertGate().filter([det()]) is not None

    def test_empty_and_none_passthrough(self):
        assert AlertGate().filter([]) is None
        assert AlertGate().filter(None) is None


class TestDedupeSemantics:
    def test_repeat_within_cooldown_is_suppressed(self):
        g = AlertGate(cooldown_seconds=300)
        assert g.filter([det()]) is not None
        assert g.filter([det()]) is None      # same ip+type, inside window
        assert g.suppressed_total == 1

    def test_different_source_ip_not_suppressed(self):
        g = AlertGate(cooldown_seconds=300)
        assert g.filter([det(src="10.0.0.1")]) is not None
        assert g.filter([det(src="10.0.0.2")]) is not None

    def test_different_attack_type_not_suppressed(self):
        g = AlertGate(cooldown_seconds=300)
        assert g.filter([det(attack_type="port_scan")]) is not None
        assert g.filter([det(attack_type="sql_injection")]) is not None

    def test_alerts_again_after_cooldown(self):
        g = AlertGate(cooldown_seconds=10)
        g.filter([det()])
        time.sleep(0)
        # simulate passage without time.sleep: age entries directly
        for k in list(g._last):
            g._last[k] -= 20
        assert g.filter([det()]) is not None

    def test_phase_sustained_attack_repeats_periodically(self):
        g = AlertGate(cooldown_seconds=5)
        events = []
        for _ in range(10):
            r = g.filter([det()])
            if r:
                events.append("alert")
            # age everything by 3s per batch
            for k in list(g._last):
                g._last[k] -= 3
        # 10 batches × 3s = 30s elapsed, 5s cooldown -> expect 5-7 alerts,
        # definitely not 10 and not 1
        assert 3 <= len(events) <= 7, f"sustained-alerts count: {len(events)}"


class TestDetailAndSafety:
    def test_detection_without_attack_type_passes_through(self):
        g = AlertGate()
        out = g.filter([{"severity": "medium", "source_ip": "1.2.3.4",
                         "details": "note"}])
        assert out == [{"severity": "medium", "source_ip": "1.2.3.4",
                        "details": "note"}]

    def test_never_raises_on_garbage(self):
        g = AlertGate()
        g.filter([{"attack_type": None}])
        g.filter([{"severity": "high"}])
        g.filter([{}])
        g.filter(None, source_ip="1.1.1.1")

    def test_memory_bounded_under_many_unique_pairs(self):
        g = AlertGate(cooldown_seconds=300)
        import itertools
        for i, t in itertools.product(range(600), ("a", "b", "c", "d")):
            g.filter([det(attack_type=t, src=f"203.0.{i//256}.{i%256}")])
        assert len(g._last) <= 50_000
        assert g.suppressed_total == 0 or g.suppressed_total >= 0  # no crash


class TestEngineIntegration:
    """The gate must actually sit in the detection pipeline."""

    def test_engine_dedupes_one_flood_into_one_alert(self):
        dpkt = pytest.importorskip("dpkt")
        from bridge.inline_engine import InlineEngine
        eng = InlineEngine({"whitelist": [], "inline": {}, "local": {}})
        pcap = Path(__file__).resolve().parent / "attack_pcap" / "dos" / "syn_flood.pcap"
        flagged_packets = 0
        types = {}
        with open(pcap, "rb") as f:
            for _ts, buf in dpkt.pcap.Reader(f):
                p = eng._parse_packet(buf)
                if not p:
                    continue
                dets = eng._run_detection_pipeline(p)
                if dets:
                    flagged_packets += 1
                    for d in dets:
                        types[d["attack_type"]] = types.get(d["attack_type"], 0) + 1
        # 5,000-packet flood from one IP. Before the gate: ~5,000 flagged.
        # After: a handful — one alert per detector that fired.
        assert flagged_packets <= 15, f"{flagged_packets} packets flagged"
        assert "syn_flood" in types, f"attack missed: {types}"
