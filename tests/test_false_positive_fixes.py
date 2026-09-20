"""False-positive fixes from the §3.3 work — benign traffic must stay quiet.

Measured state before this work (docs/PRODUCTION_READINESS.md §3.3):
`web_traffic.pcap` (benign HTTP) flagged 46/1200 packets = **3.83%**, and
because `low_entropy_isn` fires at *high* severity, those were attack rows and
alerts from ordinary browsing. `clean.pcap` was 6/4956 = 0.12%.

Four real defects were found by diagnosis, not by widening a severity filter:

1. **`/*` matched `Accept: */*`.** `session_correlator._PARTIAL_SQL` treated the
   SQL comment opener `/*` as a fragment, but `Accept: */*` — the single most
   common HTTP header value — contains it. Every `GET / HTTP/1.1` therefore
   counted as a SQL fragment, and after 5 requests in 30 s the host was reported
   as `session_correlated_sql_attack` at high severity. 18 of the 46.

2. **A zero ISN is not spoofing.** `tcp_fingerprinter` flagged identical ISNs as
   "possible replay/spoofing". Most pcap writers (and scapy's default) emit
   `seq=0`, and `web_traffic.pcap`, `syn_flood.pcap` and `nmap_syn_scan.pcap` in
   this repo all carry zero ISNs — so the check distinguished nothing. It now
   requires a non-zero sample *and* failed-connection evidence, because a host
   whose handshakes complete is talking to a real peer. 24 of the 46.

3. **Timing detectors measured the wrong clock.** `slow_loris`,
   `short_connection` and `timing_evasion` read `time.time()` — when the
   pipeline ran. Replaying a pcap runs at CPU speed (1200 packets in 0.095 s),
   so every connection looked like a sub-500 ms scan. They now use the capture
   timestamp the engine passes in.

4. **"Low-volume host" only looked at 60 packets.** A DNS resolver sending 2,477
   packets counted as quiet, so ordinary query/response bursts separated by
   idle seconds were reported as scripted `timing_evasion`.

Each fix is pinned below in both directions: benign behaviour is silent, and the
attack it was written to catch still fires.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


# ── 1. the `/*` / `Accept: */*` collision ────────────────────────────────────


class TestSqlCommentDoesNotMatchAcceptHeader:
    def test_ordinary_accept_header_is_not_a_sql_fragment(self):
        from detection.analyzer.session_correlator import _PARTIAL_SQL
        for header in ("Accept: */*",
                       "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n",
                       "GET /a.js HTTP/1.1\r\nAccept: */*\r\nReferer: x\r\n\r\n"):
            assert not _PARTIAL_SQL.search(header), (
                f"{header!r} must not read as a SQL fragment — `*/*` is a normal "
                "Accept header, not a comment opener"
            )

    @pytest.mark.parametrize("payload", [
        "GET /?id=1 UNION SELECT 1,2--",
        "GET /?q=1/**/UNION/**/SELECT",
        "GET /?x=/*!50000UNION*/SELECT",
        "GET /?p=1 OR 1=1",
        "GET /?f=0x41",
    ])
    def test_real_sql_injection_still_matches(self, payload):
        from detection.analyzer.session_correlator import _PARTIAL_SQL
        assert _PARTIAL_SQL.search(payload), f"real SQLi must still be a fragment: {payload}"

    def test_repeated_normal_requests_do_not_correlate_to_sql(self):
        """The full behaviour: 6 ordinary GETs must not raise the high-severity
        session_correlated_sql_attack."""
        from detection.analyzer.session_correlator import SessionCorrelator
        sc = SessionCorrelator(window=30, threshold=5)
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
        results = [
            sc.analyze({"payload": payload, "src_ip": "10.0.0.5"})
            for _ in range(10)
        ]
        assert not any(r for r in results), (
            "ordinary requests must not correlate into a SQL attack"
        )


# ── 2. zero ISNs are a capture artifact, not spoofing ────────────────────────


class TestZeroISNIsNotSpoofing:
    def test_all_zero_isns_never_flag(self):
        """web_traffic / syn_flood / nmap_syn_scan all carry seq=0."""
        from detection.analyzer.tcp_fingerprinter import TCPFingerprinter
        fp = TCPFingerprinter()
        for _ in range(8):
            fp._track_handshakes(
                {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "flags": "S"}, "S")
            assert fp._check_isn_randomness("10.0.0.1", 0, "S") is None

    def test_nonzero_counter_with_unanswered_syns_still_flags(self):
        """The attack this detector exists for must still fire."""
        from detection.analyzer.tcp_fingerprinter import TCPFingerprinter
        fp = TCPFingerprinter()
        r = None
        for seq in (1000, 1050, 1100, 1150, 1200):
            fp._track_handshakes(
                {"src_ip": "10.9.9.9", "dst_ip": "10.0.0.2", "flags": "S"}, "S")
            r = fp._check_isn_randomness("10.9.9.9", seq, "S")
        assert r is not None, "a predictable non-zero counter must still flag"
        assert r["attack_type"] == "low_entropy_isn"

    def test_completed_handshakes_veto_the_alert(self):
        """A host whose connections complete is talking to a real peer."""
        from detection.analyzer.tcp_fingerprinter import TCPFingerprinter
        fp = TCPFingerprinter()
        r = None
        for seq in (1000, 1050, 1100, 1150, 1200):
            fp._track_handshakes(
                {"src_ip": "10.9.9.9", "dst_ip": "10.0.0.2", "flags": "S"}, "S")
            # the server answers, so the flow is real
            fp._track_handshakes(
                {"src_ip": "10.0.0.2", "dst_ip": "10.9.9.9", "flags": "SA"}, "SA")
            r = fp._check_isn_randomness("10.9.9.9", seq, "S")
        assert r is None, (
            "predictable ISNs plus completed handshakes must not be called spoofing"
        )


# ── 3 & 4. timing detectors use the capture clock and real host volume ───────


class TestTimingDetectorsUseCaptureClock:
    def test_behavioral_uses_capture_ts_over_wall_clock(self):
        """Packets that are far apart in capture time must not be 'short' just
        because the replay ran fast."""
        from detection.analyzer.behavioral_analyzer import BehavioralAnalyzer
        ba = BehavioralAnalyzer()
        base = 1_700_000_000.0
        # 12 connections, each lasting 5 s of *capture* time
        for i in range(12):
            t0 = base + i * 10
            ba.analyze({"src_ip": "10.0.0.9", "dst_ip": "10.0.0.2",
                        "dst_port": 80, "flags": "S", "capture_ts": t0})
            ba.analyze({"src_ip": "10.0.0.9", "dst_ip": "10.0.0.2",
                        "dst_port": 80, "flags": "F", "capture_ts": t0 + 5.0})
        assert ba._check_short_connections("10.0.0.9", 5.0) is None
        assert all(d >= 0.5 for d in ba._conn_durations["10.0.0.9"]), (
            "connection durations must be measured on the capture clock"
        )

    def test_dns_query_response_is_not_timing_evasion(self):
        """A query 0 ms before its response, then 10 s idle, repeated, is a
        resolver — not scripted pacing."""
        from detection.analyzer.timing_analyzer import TimingAnalyzer
        ta = TimingAnalyzer()
        # 2477 packets' worth of volume, as the real resolver in clean.pcap has
        ta._packet_totals["10.0.0.6"] = 2477
        t = 0.0
        r = None
        for _ in range(40):
            r = ta._check_timing_gap("10.0.0.6", t, "")
            t += 0.0        # query and response back to back
            r = ta._check_timing_gap("10.0.0.6", t, "")
            t += 10.0       # then idle
        assert r is None, "a busy resolver must not read as timing evasion"

    def test_busy_host_is_not_low_volume(self):
        """A host with real volume is not hiding in the gaps.

        Regression: the "low-volume host" guard only inspected the last 60
        packets, so clean.pcap's DNS resolver — 2,477 packets — counted as quiet
        and its ordinary query bursts were reported as scripted pacing. Measured
        on the real capture: 2 `timing_evasion` alerts without this guard, 0
        with it.
        """
        from detection.analyzer.timing_analyzer import TimingAnalyzer
        ta = TimingAnalyzer()
        # Same burst/pause shape that fires for a quiet host...
        t = 0.0
        for _ in range(3):
            for _ in range(4):
                ta._check_timing_gap("10.0.0.6", t, "")
                t += 0.0
            t += 6.0
            ta._check_timing_gap("10.0.0.6", t, "")
        # ...but this host has already sent far more than the volume cap.
        ta._packet_totals["10.0.0.6"] = 2477          # a real resolver's volume
        assert ta._check_timing_gap("10.0.0.6", t + 6.0, "") is None, (
            "a host that has sent 2,477 packets is not a low-volume pacer"
        )

    def test_real_paced_evasion_still_fires(self):
        """Bursts of >=3 packets alternating with 1-15 s pauses, from a host
        that genuinely is low volume (fewer than 60 packets total)."""
        from detection.analyzer.timing_analyzer import TimingAnalyzer
        ta = TimingAnalyzer()
        t = 0.0
        fired = None
        for _ in range(3):              # 3 alternations = 12 packets total
            for _ in range(4):          # a burst of 4 packets
                r = ta._check_timing_gap("10.7.7.7", t, "")
                fired = fired or r
                t += 0.0
            t += 6.0                    # then a 6 s pause
            r = ta._check_timing_gap("10.7.7.7", t, "")
            fired = fired or r
        assert ta._packet_totals["10.7.7.7"] < 60, "fixture must stay low-volume"
        assert fired is not None, "scripted burst/pause pacing must still be caught"
        assert fired["attack_type"] == "timing_evasion"


class TestSlowLorisNeedsPartialConnections:
    def test_completing_client_is_not_slow_loris(self):
        """136 SYN/s is only a slow-loris if the connections stay half-open."""
        from detection.analyzer.timing_analyzer import TimingAnalyzer
        ta = TimingAnalyzer()
        # The peer is answering this host's SYNs.
        ta._syn_answered["10.0.0.45"] = 12
        t = 0.0
        r = None
        for _ in range(20):
            r = ta._check_slow_loris("10.0.0.45", t, "S", b"")
            t += 0.005
        assert r is None, (
            "a fast client whose handshakes complete is not holding connections open"
        )

    def test_unanswered_syn_flood_still_flags(self):
        """No SYN-ACKs come back, so the connections stay half-open."""
        from detection.analyzer.timing_analyzer import TimingAnalyzer
        ta = TimingAnalyzer()
        t = 0.0
        fired = None
        for _ in range(25):                 # keep the window fed
            r = ta._check_slow_loris("10.9.9.99", t, "S", b"")
            fired = fired or r
            t += 0.005
        assert not ta._syn_answered.get("10.9.9.99"), (
            "fixture must have no answering peer"
        )
        assert fired is not None, "an unanswered SYN flood must still be caught"
        assert fired["attack_type"] == "slow_loris"
        assert fired["severity"] == "high"


class TestUnusualHoursNeedsARealBaseline:
    """Two defects found by running the suite at 04:00 on a live ns harness.

    `unusual_hours_activity` fired on ordinary traffic at 04:00 — a benign TLS
    ClientHello and benign DNS both tripped it. Two causes:

      1. `hour < 6 or hour > 22` marked 00:00-05:59 as "near midnight" for
         *every* host, so night shifts, backups and cron all alerted.
      2. No floor on observations: a fresh sensor has almost no active hours, so
         `ratio` was tiny for whatever hour it happened to be running in.
    """

    def _baseline(self):
        from detection.baseline.per_ip_baseline import PerIPBaseline
        return PerIPBaseline()

    def test_fresh_sensor_does_not_flag_the_current_hour(self):
        """A brand-new baseline has no history; it must not accuse anyone."""
        b = self._baseline()
        pkt = {"src_ip": "203.0.113.9", "protocol": "tcp", "payload": b"x" * 100}
        findings = []
        for _ in range(20):
            findings.extend(b.analyze(pkt) or [])
        assert not any(
            d.get("attack_type") == "unusual_hours_activity" for d in findings
        ), "a fresh baseline must not report unusual hours"

    def test_small_hours_are_not_an_anomaly_on_their_own(self, monkeypatch):
        """Activity at 04:00 with a real baseline that covers other hours must
        not be flagged merely because the hour is small."""
        import time as _time
        from detection.baseline.per_ip_baseline import PerIPBaseline
        b = PerIPBaseline()
        # Give this host a broad, real baseline: active across many hours.
        for h in range(7, 22):
            b._hour_activity["10.0.0.5"][h] = 500
        b._hour_activity["10.0.0.5"][4] = 0
        monkeypatch.setattr(_time, "localtime",
                            lambda *a, **k: _time.struct_time(
                                (2026, 1, 1, 4, 0, 0, 0, 0, 0)))
        b._last_hour = 3
        out = b.analyze({"src_ip": "10.0.0.5", "protocol": "tcp", "payload": b"x" * 60})
        # With 15 of 24 hours active, ratio = 0.625 > 0.3, so no finding.
        assert not out or not any(
            d.get("attack_type") == "unusual_hours_activity" for d in out
        )

    def test_insufficient_history_never_fires(self):
        b = self._baseline()
        b._hour_activity["10.0.0.6"][4] = 1
        b._hour_activity["10.0.0.6"][10] = 1
        b._last_hour = 3
        assert b._min_hour_observations > 2, "guard must require real history"
        out = b.analyze({"src_ip": "10.0.0.6", "protocol": "tcp", "payload": b"y" * 60})
        assert not out or not any(
            d.get("attack_type") == "unusual_hours_activity" for d in out
        )


# ── the capture-level guard: benign stays quiet end to end ───────────────────


BENIGN = Path(__file__).resolve().parent / "attack_pcap"


@pytest.mark.parametrize("name,path,budget", [
    ("web_traffic", BENIGN / "benign" / "web_traffic.pcap", 0.005),
    ("clean", BENIGN / "tunneling" / "clean.pcap", 0.005),
    ("https_traffic", BENIGN / "benign" / "https_traffic.pcap", 0.0),
])
def test_benign_captures_stay_under_budget(name, path, budget):
    """End-to-end: replay a benign capture through the real pipeline and assert
    the actionable-false-positive rate. `info` observations are excluded — they
    are telemetry, not accusations (see tests/test_observation_severity.py)."""
    if not path.exists():
        pytest.skip(f"{path.name} not present")
    dpkt = pytest.importorskip("dpkt")
    from bridge.inline_engine import InlineEngine
    from utils.severity import is_actionable_severity

    engine = InlineEngine({
        "inline": {"rate_limiting": {"packets_per_second": 10000, "burst": 100},
                   "dpi": {"max_reassembly_buffers": 1024}, "dos": {}},
        "whitelist": [], "local": {"nfqueue_num": 0}, "bridge": {"nfqueue_num": 0},
    }, db=None, detector=None)

    flagged = total = 0
    types = {}
    with open(path, "rb") as fh:
        for ts, buf in dpkt.pcap.Reader(fh):
            pkt = engine._parse_packet(buf, capture_ts=ts)
            if not pkt:
                continue
            total += 1
            dets = engine._run_detection_pipeline(pkt)
            if dets and any(is_actionable_severity(d.get("severity", "medium"))
                            for d in dets):
                flagged += 1
                for d in dets:
                    types[d["attack_type"]] = types.get(d["attack_type"], 0) + 1

    rate = flagged / total if total else 0.0
    assert rate <= budget, (
        f"{name}: {flagged}/{total} = {rate:.2%} actionable false positives "
        f"(budget {budget:.2%}); detectors firing: {types}"
    )