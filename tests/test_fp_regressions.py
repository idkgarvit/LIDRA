"""Regression tests for FP-rate bugs found by the pcap harness.

Each test documents the bug, the broken code, and the fix.
"""
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC))

from bridge.inline_engine import InlineEngine  # noqa: E402
from detection.analyzer.l2_analyzer import L2Analyzer  # noqa: E402
from detection.analyzer.port_analyzer import PortAnalyzer  # noqa: E402
from detection.analyzer.tcp_fingerprinter import TCPFingerprinter  # noqa: E402
from detection.packet_analyzer import PacketAnalyzer  # noqa: E402


def _make_engine():
    config = {
        "inline": {
            "rate_limiting": {"packets_per_second": 10000, "burst": 100},
            "dpi": {"max_reassembly_buffers": 1024},
            "dos": {},
        },
        "whitelist": [],
        "local": {"nfqueue_num": 0},
        "bridge": {"nfqueue_num": 0},
    }
    return InlineEngine(config, db=None, detector=None)


class TestPortAnalyzerFPFixes:
    """port_analyzer was firing port_scan on UDP DNS responses because
    it tracked ANY non-SYN-ACK packet. A DNS server responding to 15+
    different clients (each with a different high source port) was
    being flagged as a 'port scanner'."""

    def test_pure_syn_still_tracked(self):
        pa = PortAnalyzer()
        for port in range(20):
            r = pa._check_port_scan("10.0.0.99", port, "S", "tcp")
            if port >= 14:
                assert r is not None, f"port {port}: scan should fire"
                assert r["attack_type"] == "port_scan"

    def test_syn_ack_not_tracked(self):
        pa = PortAnalyzer()
        for i in range(30):
            r = pa._check_port_scan("10.0.0.99", 40000 + i, "SA", "tcp")
            assert r is None, f"SYN-ACK at port {40000+i} should not be tracked"
        assert pa._port_scan_tracker == {}

    def test_udp_not_tracked(self):
        pa = PortAnalyzer()
        for port in range(100, 130):
            r = pa._check_port_scan("10.0.0.99", port, "", "udp")
            assert r is None
        assert pa._port_scan_tracker == {}

    def test_dns_server_responses_not_flagged(self):
        """Simulate a DNS server responding to 20 different clients
        (each with a unique source port). The server's tracker should
        stay empty because the responses are SYN-ACKs, not SYNs."""
        pa = PortAnalyzer()
        for i in range(20):
            r = pa._check_port_scan("10.0.0.1", 40000 + i, "SA", "tcp")
            assert r is None
        assert pa._port_scan_tracker == {}

    def test_port_hopping_requires_syn(self):
        pa = PortAnalyzer()
        # Many SYN-ACKs to different ports — should NOT fire port_hopping
        for i in range(20):
            r = pa._check_port_hopping("10.0.0.1", "10.0.0.99", 40000 + i, "tcp", "SA")
            assert r is None
        # Many SYNs to different ports — SHOULD fire port_hopping
        # Fires at count % 5 == 0 starting at 5
        fired = False
        for i in range(15):
            r = pa._check_port_hopping("10.0.0.1", "10.0.0.99", 100 + i, "tcp", "S")
            if r is not None and r["attack_type"] == "port_hopping":
                fired = True
        assert fired, "port_hopping should have fired during 15 SYNs"


class TestPacketAnalyzerFPFixes:
    """PacketAnalyzer.analyze_header had the same bug — it called
    _check_port_scan for every TCP packet, not just SYNs. This was
    actually the source of the FPs the harness reported (the engine
    uses PacketAnalyzer, not PortAnalyzer, for the first pass)."""

    def test_syn_ack_packets_dont_trigger_port_scan(self):
        analyzer = PacketAnalyzer(config={})
        for i in range(30):
            pkt = {
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.99",
                "src_port": 80,
                "dst_port": 40000 + i,
                "protocol": "tcp",
                "flags": "SA",
            }
            r = analyzer.analyze_header(pkt)
            assert r is None, f"SYN-ACK should not trigger port_scan"
        assert analyzer._port_scan_tracker == {}

    def test_pure_syn_still_triggers_port_scan(self):
        analyzer = PacketAnalyzer(config={})
        for i in range(25):
            pkt = {
                "src_ip": "10.0.0.99",
                "dst_ip": "10.0.0.1",
                "src_port": 40000 + i,
                "dst_port": 80 + i,
                "protocol": "tcp",
                "flags": "S",
            }
            analyzer.analyze_header(pkt)
        # After 20+ SYNs to different ports, should fire
        r = analyzer.analyze_header({
            "src_ip": "10.0.0.99",
            "dst_ip": "10.0.0.1",
            "src_port": 40100,
            "dst_port": 120,
            "protocol": "tcp",
            "flags": "S",
        })
        assert r is not None
        assert r["attack_type"] == "port_scan"

    def test_ack_does_not_increment_port_scan_tracker(self):
        analyzer = PacketAnalyzer(config={})
        for i in range(50):
            analyzer.analyze_header({
                "src_ip": "10.0.0.99",
                "dst_ip": "10.0.0.1",
                "src_port": 40000,
                "dst_port": 40000 + i,
                "protocol": "tcp",
                "flags": "A",
            })
        assert analyzer._port_scan_tracker == {}


class TestBroadcastStormFPFix:
    """L2Analyzer's broadcast_storm detector counted every packet from
    any source IP. A DNS server doing 500+ responses would be flagged
    as a broadcast storm. The fix: only count packets that are
    actually broadcasts (dst MAC = ff:ff:ff:ff:ff:ff or dst IP
    ending in .255 or 255.255.255.255)."""

    def test_normal_packet_not_counted(self):
        a = L2Analyzer()
        for i in range(1000):
            pkt = {
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.99",
                "src_mac": "aa:bb:cc:dd:ee:ff",
                "dst_mac": "11:22:33:44:55:66",
                "raw_len": 100,
            }
            r = a.analyze(pkt)
        assert a._broadcast_counts == {}

    def test_broadcast_packet_counted(self):
        a = L2Analyzer()
        for i in range(600):
            pkt = {
                "src_ip": "10.0.0.1",
                "dst_ip": "192.168.1.255",  # subnet broadcast
                "src_mac": "aa:bb:cc:dd:ee:ff",
                "raw_mac": "ff:ff:ff:ff:ff:ff",
                "raw_len": 100,
            }
            a.analyze(pkt)
        assert a._broadcast_counts.get("10.0.0.1", 0) == 600

    def test_limited_broadcast(self):
        a = L2Analyzer()
        for i in range(600):
            pkt = {
                "src_ip": "10.0.0.1",
                "dst_ip": "255.255.255.255",
            }
            a.analyze(pkt)
        assert a._broadcast_counts.get("10.0.0.1", 0) == 600

    def test_is_broadcast_helper(self):
        assert L2Analyzer._is_broadcast("192.168.1.255", "") is True
        assert L2Analyzer._is_broadcast("10.0.0.255", "") is True
        assert L2Analyzer._is_broadcast("255.255.255.255", "") is True
        assert L2Analyzer._is_broadcast("ff02::1", "") is True
        assert L2Analyzer._is_broadcast("10.0.0.1", "") is False
        assert L2Analyzer._is_broadcast("", "ff:ff:ff:ff:ff:ff") is True
        assert L2Analyzer._is_broadcast("", "11:22:33:44:55:66") is False


class TestLowEntropyISNFPFix:
    """tcp_fingerprinter fired on any ISN gap <1000 between consecutive
    SYNs. Normal clients in a fast test loop have small ISN gaps
    because the ISN counter doesn't advance much between consecutive
    connections. The fix: only fire on highly suspicious patterns
    (all gaps zero, all gaps <100, or constant gap)."""

    def test_normal_varied_isns_not_flagged(self):
        fp = TCPFingerprinter()
        # Real ISNs from a normal Linux client — varied, large gaps
        seqs = [12345678, 67890123, 87654321, 13579246, 24680135]
        for s in seqs:
            r = fp._check_isn_randomness("10.0.0.1", s, "S")
            assert r is None, f"varied ISN at {s} should not flag"

    def test_identical_isns_flagged(self):
        fp = TCPFingerprinter()
        for s in [100, 100, 100, 100, 100]:
            r = fp._check_isn_randomness("10.0.0.1", s, "S")
        assert r is not None
        assert r["attack_type"] == "low_entropy_isn"
        assert "Identical" in r["details"]

    def test_predictable_counter_flagged(self):
        fp = TCPFingerprinter()
        for s in [100, 200, 300, 400, 500]:  # constant +100
            r = fp._check_isn_randomness("10.0.0.1", s, "S")
        assert r is not None
        assert "Predictable" in r["details"] or "constant" in r["details"]

    def test_tight_counter_flagged(self):
        fp = TCPFingerprinter()
        for s in [1000, 1050, 1100, 1150, 1200]:  # all <100 increments
            r = fp._check_isn_randomness("10.0.0.1", s, "S")
        assert r is not None

    def test_2k_doesnt_fire_on_insufficient_samples(self):
        fp = TCPFingerprinter()
        for s in [100, 100, 100]:  # only 3 samples
            r = fp._check_isn_randomness("10.0.0.1", s, "S")
        assert r is None, "3 samples shouldn't fire (need 4+)"


class TestShortConnectionFPFix:
    """behavioral_analyzer fired short_connection on ANY connection
    closed in <500ms. Normal HTTP requests often complete in <500ms,
    so 200 of 1200 benign web packets were flagged. The fix: only
    fire if 10+ recent connections from the same IP are short."""

    def test_single_short_connection_not_flagged(self):
        from detection.analyzer.behavioral_analyzer import BehavioralAnalyzer
        ba = BehavioralAnalyzer()
        r = ba._check_short_connections("10.0.0.1", 0.1)
        assert r is None

    def test_n_short_connections_flagged(self):
        from detection.analyzer.behavioral_analyzer import BehavioralAnalyzer
        ba = BehavioralAnalyzer()
        for i in range(15):
            ba._conn_durations["10.0.0.1"].append(0.1)
        r = ba._check_short_connections("10.0.0.1", 0.1)
        assert r is not None
        assert r["attack_type"] == "short_connection"

    def test_long_connection_not_flagged(self):
        from detection.analyzer.behavioral_analyzer import BehavioralAnalyzer
        ba = BehavioralAnalyzer()
        for i in range(15):
            ba._conn_durations["10.0.0.1"].append(2.0)
        r = ba._check_short_connections("10.0.0.1", 2.0)
        assert r is None


class TestEndToEndFPImprovement:
    """Run the actual benign pcaps through the engine and verify the
    FP rate is now reasonable."""

    def test_web_traffic_fp_rate(self):
        from pathlib import Path
        import dpkt
        engine = _make_engine()
        flagged = 0
        total = 0
        pcap = Path(__file__).parent / "attack_pcap" / "benign" / "web_traffic.pcap"
        with open(pcap, "rb") as f:
            for ts, buf in dpkt.pcap.Reader(f):
                pkt = engine._parse_packet(buf)
                if not pkt:
                    continue
                total += 1
                detections = engine._run_detection_pipeline(pkt)
                if detections:
                    flagged += 1
        rate = flagged / total
        assert rate < 0.10, f"web_traffic FP rate too high: {flagged}/{total} = {rate:.1%}"

    def test_dns_clean_fp_rate(self):
        from pathlib import Path
        import dpkt
        engine = _make_engine()
        flagged = 0
        total = 0
        pcap = Path(__file__).parent / "attack_pcap" / "tunneling" / "clean.pcap"
        with open(pcap, "rb") as f:
            for ts, buf in dpkt.pcap.Reader(f):
                pkt = engine._parse_packet(buf)
                if not pkt:
                    continue
                total += 1
                detections = engine._run_detection_pipeline(pkt)
                if detections:
                    flagged += 1
        rate = flagged / total
        assert rate < 0.10, f"clean DNS FP rate too high: {flagged}/{total} = {rate:.1%}"
