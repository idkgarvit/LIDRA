"""Observations are not attacks — severity semantics at the response boundary.

Context (docs/PRODUCTION_READINESS.md §0.1):

``TLSFingerprinter.analyze()`` returns a ``tls_fingerprint`` detection at
severity ``info`` for **any** parseable ClientHello — that is the JA4
passthrough, and it is deliberate: the fingerprint of ordinary HTTPS is useful
telemetry. The defect was that nothing downstream distinguished an observation
from an accusation. ``core/agent_base.py`` writes the attacker/attacks row
*before* the ``severity in ("high", "critical") and verdict == "drop"`` gate, so
every ordinary HTTPS connection created an attacker row and an attack row. The
"attackers" figure in ``lidra status`` therefore grew with normal browsing.

These tests pin the rule in both directions, through the real
``InlineEngine`` -> ``_apply_verdict`` -> ``_handle_detection_event`` chain,
against a ``tmp_path`` database (never ``data/lidra.db``; ``conftest.py`` fails
the suite if anything writes there):

* benign  — a normal ClientHello over 443 creates no rows, no alert, no block;
* malicious — a known-bad JA4 still reaches the alert gate, so a later
  "cleanup" cannot fix the leak by silencing the response path.
"""

from __future__ import annotations

import socket
import struct
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import dpkt  # noqa: E402

import detection.fingerprint.tls_fingerprinter as tfp  # noqa: E402
from bridge.inline_engine import InlineEngine  # noqa: E402
from database.db import LIDRADatabase  # noqa: E402
from utils.severity import is_actionable_severity  # noqa: E402

# ── TLS ClientHello construction ─────────────────────────────────────────────


def _sni_ext(host: bytes = b"example.com"):
    inner = b"\x00" + struct.pack(">H", len(host)) + host
    return (0x00, struct.pack(">H", len(inner)) + inner)


def make_client_hello(ciphers=None, exts=None, version=0x0303) -> bytes:
    """A well-formed TLS ClientHello record (no SNI unless asked for)."""
    ciphers = ciphers or [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
    exts = exts if exts is not None else [
        (0x10, b"\x00\x02h2"), (0x0B, b"\x01\x02"), (43, b"\x02\x03\x04"),
    ]
    body = struct.pack(">H", version) + b"R" * 32 + b"\x00"
    body += struct.pack(">H", len(ciphers) * 2)
    for c in ciphers:
        body += struct.pack(">H", c)
    body += b"\x01\x00"
    blob = b"".join(struct.pack(">HH", t, len(d)) + d for t, d in exts)
    body += struct.pack(">H", len(blob)) + blob
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def frame_tcp(payload: bytes, sport=50000, dport=443,
              src="203.0.113.50", dst="192.168.1.7") -> bytes:
    """A single Ethernet/IPv4/TCP-PSH packet carrying ``payload``."""
    tcp = dpkt.tcp.TCP(
        sport=sport, dport=dport,
        flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK,
        seq=1, ack=1, win=65535, data=payload,
    )
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(src=b"\xaa" * 6, dst=b"\xbb" * 6,
                                 type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    return bytes(eth)


def make_engine() -> InlineEngine:
    cfg = {
        "inline": {"rate_limiting": {"packets_per_second": 10000, "burst": 100},
                   "dpi": {"max_reassembly_buffers": 1024}, "dos": {}},
        "whitelist": [], "local": {"nfqueue_num": 0}, "bridge": {"nfqueue_num": 0},
    }
    return InlineEngine(cfg, db=None, detector=None)


# ── A minimal agent that uses the REAL response decision path ────────────────
#
# We drive the production code (LIDRACore._handle_detection_event) rather than
# copying its logic, so the test cannot drift from the thing it is pinning.
# Only the collaborators that would touch the network/host are stubbed:
# notifier (no webhooks), firewall (no kernel rules), threat intel (no HTTP).


class _RecordingNotifier:
    def __init__(self):
        self.sent = []

    def notify(self, alert):
        self.sent.append(alert)
        return 1


class _StubThreatIntel:
    def lookup_ip(self, ip):
        return {}


class _StubExplainer:
    def explain(self, detection, context):
        return "stub explanation"


class _StubFirewall:
    dry_run = False

    def __init__(self):
        self.blocked = []

    def block_ip(self, ip, ttl_seconds=3600):
        self.blocked.append(ip)
        return True


@pytest.fixture()
def agent(tmp_path):
    """A LIDRACore whose DB is in tmp_path and whose egress is stubbed.

    Instantiated through a minimal concrete subclass so the REAL
    ``_handle_detection_event`` runs — the production code under test — while
    the four abstract capture hooks are inert.
    """
    from core.agent_base import LIDRACore

    class _TestAgent(LIDRACore):
        def _init_mode_components(self): ...
        def _start_capture(self): ...
        def _block_ip(self, ip, reason=""): ...
        def _teardown_capture(self): ...

    config = {
        "response": {"dry_run": False},
        "database": {"path": str(tmp_path / "t.db")},
        "whitelist": [],
        "allowlist": {"enabled": False},
        "alerts": {},
        "threat_intel": {},
    }

    a = object.__new__(_TestAgent)
    a.config = config
    # record_dedupe_seconds=0: the dedupe throttle must not interfere with what
    # this test measures. (It also makes the test independent of machine uptime;
    # see utils/alert_throttle.py for the sentinel bug that made uptime matter.)
    a.db = LIDRADatabase(str(tmp_path / "t.db"), record_dedupe_seconds=0)
    from detection.attack_detector import AttackDetector
    a.detector = AttackDetector()
    a.notifier = _RecordingNotifier()
    a.firewall = _StubFirewall()
    a.threat_intel = _StubThreatIntel()
    a.explainer = _StubExplainer()
    from utils.alert_throttle import AlertThrottle
    a._alert_throttle = AlertThrottle(cooldown_seconds=0)
    a._detect_queue = None
    a.tracer = None

    # TUI push is a no-op here; the TUI itself is not under test.
    a.push_event = lambda event: None
    a._push_tui_event = a.push_event
    a._log = lambda msg: None

    # The allowlist is global+cached; disable it so a test IP is never
    # suppressed for reasons unrelated to this behaviour.
    import utils.allowlist as _al
    _al.reset_allowlist()

    yield a
    _al.reset_allowlist()


def _counts(agent):
    conn = agent.db._get_connection()
    return (
        conn.execute("SELECT COUNT(*) FROM attackers").fetchone()[0],
        conn.execute("SELECT COUNT(*) FROM attacks").fetchone()[0],
        conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
    )


def _drive_engine_to_agent(agent, payload: bytes, sport: int = 50000):
    """Run one packet through the real engine and deliver detections to the
    real agent handler, exactly as the live capture path does."""
    engine = make_engine()
    engine.register_detection_callback(agent._on_detection_callback)

    # _on_detection_callback enqueues; deliver synchronously by calling the
    # worker function directly (no thread, deterministic in tests).
    events = []
    engine._on_detection_callback = events.append

    packet = engine._parse_packet(frame_tcp(payload, sport=sport))
    assert packet, "test fixture failed to parse as a packet"
    detections = engine._run_detection_pipeline(packet)
    verdict = engine._decide(packet, detections)
    engine._apply_verdict(0, verdict, packet, detections, time.time())

    for ev in events:
        agent._handle_detection_event(ev)
    return detections, verdict


# ── Direction 1: a benign ClientHello is an observation, not an attack ───────


class TestBenignClientHelloCreatesNoAttack:
    def test_normal_clienthello_is_an_info_detection(self):
        """The DPI observation must survive: it is telemetry, not a bug."""
        from detection.dpi_engine import DPIEngine
        result = DPIEngine().inspect_stream(make_client_hello(), "tls")
        assert result is not None
        assert result.attack_type == "tls_fingerprint"
        assert result.severity == "info"

    def test_benign_clienthello_writes_no_rows_and_sends_no_alert(self, agent):
        before = _counts(agent)
        detections, verdict = _drive_engine_to_agent(agent, make_client_hello())
        after = _counts(agent)

        assert detections, "expected the JA4 observation to reach the pipeline"
        assert all(d["severity"] == "info" for d in detections), detections
        assert verdict.value == "pass"

        assert after == before, (
            f"a benign ClientHello changed the database: {before} -> {after}. "
            "severity 'info' must not create attacker/attacks rows."
        )
        assert agent.notifier.sent == [], "a benign ClientHello must not alert"
        assert agent.firewall.blocked == [], "a benign ClientHello must not block"

    def test_no_clienthello_at_all_writes_no_rows(self, agent):
        """Guard the guard: the fixture must be the thing that fires."""
        before = _counts(agent)
        detections, _ = _drive_engine_to_agent(agent, b"\x17\x03\x03\x00\x10" + b"x" * 16)
        after = _counts(agent)
        assert not any(d["attack_type"] == "tls_fingerprint" for d in detections)
        assert after == before

    def test_repeated_https_does_not_grow_the_attacker_table(self, agent):
        """The reported symptom: ordinary browsing inflating 'attackers'."""
        before = _counts(agent)
        for i in range(8):
            _drive_engine_to_agent(
                agent, make_client_hello(), sport=50000 + i)
        after = _counts(agent)
        assert after[0] == before[0], "attackers grew with normal HTTPS"
        assert after[1] == before[1], "attacks grew with normal HTTPS"

    def test_many_distinct_benign_peers_create_no_attackers(self, agent):
        """A JA4 row per *peer* is the real-world shape of the leak."""
        before = _counts(agent)
        for i in range(6):
            engine = make_engine()
            events = []
            engine._on_detection_callback = events.append
            pkt = engine._parse_packet(
                frame_tcp(make_client_hello(), sport=40000 + i,
                          src=f"198.51.100.{i + 1}"))
            dets = engine._run_detection_pipeline(pkt)
            engine._apply_verdict(0, engine._decide(pkt, dets), pkt, dets, time.time())
            for ev in events:
                agent._handle_detection_event(ev)
        after = _counts(agent)
        assert after == before, f"{after} != {before}: benign peers persisted"


# ── Direction 2: the malicious case must still reach the alert gate ──────────


class TestMaliciousJA4StillAlerts:
    """If only direction 1 existed, someone could 'fix' the leak by silencing
    the response path. This is the guard against that."""

    def test_known_bad_ja4_is_high_severity_and_drops(self):
        engine = make_engine()          # build FIRST: __init__ reloads the db
        hello = make_client_hello()
        ja4 = tfp.parse_tls_client_hello(hello)["ja4"]
        tfp._KNOWN_MALICIOUS_JA4 = {ja4}   # patch AFTER construction
        try:
            packet = engine._parse_packet(frame_tcp(hello))
            detections = engine._run_detection_pipeline(packet)
            verdict = engine._decide(packet, detections)
        finally:
            tfp._KNOWN_MALICIOUS_JA4 = set()

        assert [d["attack_type"] for d in detections] == ["malicious_tls_fingerprint"]
        assert detections[0]["severity"] == "high"
        assert verdict.value == "drop", "a malicious JA4 must produce a DROP verdict"

    def test_known_bad_ja4_reaches_alert_and_block(self, agent):
        engine = make_engine()
        hello = make_client_hello()
        ja4 = tfp.parse_tls_client_hello(hello)["ja4"]
        tfp._KNOWN_MALICIOUS_JA4 = {ja4}

        events = []
        engine._on_detection_callback = events.append
        try:
            packet = engine._parse_packet(frame_tcp(hello, src="203.0.113.66"))
            detections = engine._run_detection_pipeline(packet)
            verdict = engine._decide(packet, detections)
            engine._apply_verdict(0, verdict, packet, detections, time.time())
        finally:
            tfp._KNOWN_MALICIOUS_JA4 = set()

        for ev in events:
            agent._handle_detection_event(ev)

        attackers, attacks, alerts = _counts(agent)
        assert attacks >= 1, "the malicious case must persist an attack row"
        assert alerts >= 1, "the malicious case must persist an alert"
        assert agent.notifier.sent, "the malicious case must reach the notifier"
        assert agent.notifier.sent[0].severity == "high"


# ── The capture-driven tests: real pcaps through the real engine ─────────────
#
# These are the T7 fixture. They close the "no TLS capture at all" gap that hid
# the leak, and they run the shipped .pcap files rather than hand-built bytes.

PCAP_DIR = Path(__file__).resolve().parent / "attack_pcap"
BENIGN_TLS_PCAP = PCAP_DIR / "benign" / "https_traffic.pcap"
MALICIOUS_TLS_PCAP = PCAP_DIR / "tls" / "malicious_clienthello.pcap"


def _replay_pcap_into_agent(agent, pcap_path, blocklist=None, temp_patch=None):
    """Replay a capture through the real pipeline into the real handler.

    Returns (packets_seen, detections_seen, verdicts_seen).
    """
    engine = make_engine()                 # engine FIRST — see module docstring
    if temp_patch is not None:
        tfp._KNOWN_MALICIOUS_JA4 = set(temp_patch)   # patch SECOND
    events = []
    engine._on_detection_callback = events.append
    n = 0
    dets_seen = []
    verdicts = []
    with open(pcap_path, "rb") as fh:
        for _ts, buf in dpkt.pcap.Reader(fh):
            packet = engine._parse_packet(buf)
            if not packet:
                continue
            n += 1
            dets = engine._run_detection_pipeline(packet)
            verdict = engine._decide(packet, dets)
            engine._apply_verdict(0, verdict, packet, dets, time.time())
            dets_seen.extend(dets)
            verdicts.append(verdict.value)
    for ev in events:
        agent._handle_detection_event(ev)
    return n, dets_seen, verdicts


@pytest.mark.skipif(not BENIGN_TLS_PCAP.exists(),
                    reason="run tests/attack_pcap/_generate_tls_pcaps.py")
class TestBenignTlsCaptureIsSilent:
    def test_capture_exists_and_is_the_tls_baseline(self):
        """The corpus had no TLS capture; this asserts the gap is closed."""
        assert BENIGN_TLS_PCAP.exists()
        assert MALICIOUS_TLS_PCAP.exists()
        with open(BENIGN_TLS_PCAP, "rb") as fh:
            n = sum(1 for _ in dpkt.pcap.Reader(fh))
        assert n > 0, "benign TLS capture is empty"

    def test_real_https_capture_creates_no_rows_and_no_alerts(self, agent):
        before = _counts(agent)
        n, dets, verdicts = _replay_pcap_into_agent(agent, BENIGN_TLS_PCAP)
        after = _counts(agent)

        assert n > 0
        assert any(d["attack_type"] == "tls_fingerprint" for d in dets), (
            "the JA4 observation should still be reported by the DPI layer"
        )
        info = [d for d in dets if d["severity"] == "info"]
        assert info, "expected info-severity observations from HTTPS"
        assert after == before, (
            f"benign HTTPS capture changed the DB {before} -> {after}; "
            "ordinary browsing must not create attackers/attacks rows"
        )
        assert agent.notifier.sent == [], "benign HTTPS must not alert"
        assert agent.firewall.blocked == [], "benign HTTPS must not block"


@pytest.mark.skipif(not MALICIOUS_TLS_PCAP.exists(),
                    reason="run tests/attack_pcap/_generate_tls_pcaps.py")
class TestMaliciousTlsCaptureAlerts:
    def test_capture_ja4_matches_a_synthetic_blocklist_entry(self):
        """T7, synthetic and explicit: craft the hello, compute its JA4, add
        that hash to the blocklist. Matching a *published* hash is infeasible
        (48-bit truncated-sha256 preimage); see the pcap's meta.yaml."""
        with open(MALICIOUS_TLS_PCAP, "rb") as fh:
            ja4s = []
            for _ts, buf in dpkt.pcap.Reader(fh):
                parsed = tfp.parse_tls_client_hello(buf[54:] if len(buf) > 54 else buf)
                if parsed:
                    ja4s.append(parsed["ja4"])
            assert ja4s, "no parseable ClientHello in the malicious capture"
        self.asserted_ja4 = ja4s[0]
        assert self.asserted_ja4 == "t13i010200_0f2cb44170f4_fdaab033dba4"

    def test_malicious_capture_reaches_drop_and_alerts(self, agent):
        with open(MALICIOUS_TLS_PCAP, "rb") as fh:
            ja4 = None
            for _ts, buf in dpkt.pcap.Reader(fh):
                parsed = tfp.parse_tls_client_hello(buf[54:] if len(buf) > 54 else buf)
                if parsed:
                    ja4 = parsed["ja4"]
                    break
        assert ja4, "no parseable ClientHello in the malicious capture"

        before = _counts(agent)
        try:
            n, dets, verdicts = _replay_pcap_into_agent(
                agent, MALICIOUS_TLS_PCAP, temp_patch={ja4})
        finally:
            tfp._KNOWN_MALICIOUS_JA4 = set()
        after = _counts(agent)

        types = [d["attack_type"] for d in dets]
        assert "malicious_tls_fingerprint" in types, types
        assert "drop" in verdicts, "a malicious JA4 must produce a DROP verdict"
        assert after[1] > before[1], "the malicious capture must persist an attack row"
        assert after[2] > before[2], "the malicious capture must persist an alert"
        assert agent.notifier.sent, "the malicious capture must reach the notifier"


# ── The predicate itself ────────────────────────────────────────────────────


class TestSeverityPredicate:
    @pytest.mark.parametrize("sev", ["info", "INFO", " Info "])
    def test_info_is_not_actionable(self, sev):
        assert is_actionable_severity(sev) is False

    @pytest.mark.parametrize("sev", ["low", "medium", "high", "critical"])
    def test_response_bands_are_actionable(self, sev):
        assert is_actionable_severity(sev) is True

    def test_unknown_severity_stays_actionable(self):
        """An unrecognised severity is more likely a typo than a deliberate
        observation; silently dropping a real detection is the worse error."""
        assert is_actionable_severity("weird") is True
        assert is_actionable_severity(None) is True