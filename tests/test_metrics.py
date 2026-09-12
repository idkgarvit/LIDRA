"""Metrics end-to-end: does the Prometheus endpoint actually carry LIDRA data?

The bug this covers: `metrics/server.py` registered the series (packets, attacks,
blocks, latency) and served them, but nothing in the codebase ever incremented
them. A scrape returned only `python_*` / `process_*` families, so the bundled
Grafana dashboard had nothing to draw. These tests replay a real attack pcap
through the real pipeline and then read the real HTTP endpoint — asserting on
scraped text, not on a mock being called.
"""

import os
import socket
import sys
import time
import urllib.request
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC))

pytest.importorskip("prometheus_client", reason="prometheus-client not installed")

from metrics import collector  # noqa: E402
from metrics import server as metrics_server  # noqa: E402

PCAP = PROJECT_ROOT / "tests" / "attack_pcap" / "sqli" / "test_with_sql.pcap"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _scrape(port: int) -> str:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as r:
        return r.read().decode()


def _start_server(port: int):
    """Start the metrics server and wait until it actually accepts connections.

    `MetricsServer.start()` spawns a thread and returns immediately, so a
    straight scrape races the bind and fails intermittently with ECONNREFUSED.
    Poll instead of sleeping a fixed amount.
    """
    srv = metrics_server.MetricsServer(port=port, host="127.0.0.1")
    srv.start()
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return srv
        except OSError:
            time.sleep(0.02)
    srv.stop()
    pytest.fail(f"metrics server never accepted a connection on port {port}")


def test_collector_records_into_scraped_output():
    """A detection recorded via the collector must appear in a scrape."""
    port = _free_port()
    srv = _start_server(port)
    try:
        collector.record_detection("sql_injection", "high")
        collector.record_block("inline")
        collector.set_gauges(active_connections=7)

        body = _scrape(port)

        assert 'lidra_attacks_total{severity="high",type="sql_injection"}' in body, body
        assert 'lidra_blocks_total{method="inline"}' in body
        assert "lidra_active_connections 7" in body
    finally:
        srv.stop()


def test_verdict_counters_are_labelled_per_verdict():
    port = _free_port()
    srv = _start_server(port)
    try:
        from response.verdict import Verdict
        collector.record_verdict(Verdict.PASS)
        collector.record_verdict(Verdict.DROP)
        collector.record_verdict(Verdict.DROP)

        body = _scrape(port)
        assert 'lidra_packets_total{verdict="pass"} 1.0' in body, body
        assert 'lidra_packets_total{verdict="drop"} 2.0' in body, body
    finally:
        srv.stop()


def test_latency_histogram_observes():
    port = _free_port()
    srv = _start_server(port)
    try:
        collector.record_latency(0.002)
        body = _scrape(port)
        assert "lidra_detection_latency_seconds_count" in body, body
    finally:
        srv.stop()


def test_pcap_replay_feeds_the_endpoint():
    """The real integration path: packets -> pipeline -> verdict -> scrape."""
    dpkt = pytest.importorskip("dpkt")
    from bridge.inline_engine import InlineEngine

    if not PCAP.exists():
        pytest.skip(f"missing fixture {PCAP}")

    port = _free_port()
    srv = _start_server(port)
    try:
        engine = InlineEngine({"whitelist": [], "inline": {}, "local": {}})
        before = _scrape(port)
        packets = detections = 0
        with open(PCAP, "rb") as f:
            for _ts, buf in dpkt.pcap.Reader(f):
                packet = engine._parse_packet(buf)
                if not packet:
                    continue
                packets += 1
                dets = engine._run_detection_pipeline(packet)
                detections += len(dets)
                verdict = engine._decide(packet, dets)
                engine._apply_verdict(0, verdict, packet, dets, 0.0)

        assert packets >= 1, "fixture pcap produced no parsable packets"
        assert detections >= 1, "fixture pcap produced no detections"
        body = _scrape(port)
        assert "lidra_packets_total" in body, body
        assert "lidra_attacks_total" in body, body
        assert "lidra_detection_latency_seconds_count" in body, body
        assert body != before
    finally:
        srv.stop()


def test_collector_never_raises_on_bad_input():
    """These calls sit near the verdict path; they must degrade, not explode."""
    collector.record_verdict(None)
    collector.record_detection(None, None)
    collector.record_detection("x" * 500, "y" * 500)  # label-length guard
    collector.record_latency("not-a-number")
    collector.set_gauges(active_connections=None, rate_pps="bad")
    collector.set_gauges_from_stats(None)
    collector.set_gauges_from_stats({})
