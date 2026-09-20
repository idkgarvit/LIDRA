"""Test harness: replay real attack pcaps through LIDRA's detection pipeline.

This is the proof layer. For each pcap in tests/attack_pcap/, we:
  1. Read the metadata file (.meta.yaml) to learn what the pcap contains.
  2. Open the pcap, iterate packets, and feed each into
     InlineEngine._parse_packet() then _run_detection_pipeline().
  3. Aggregate all detections across the pcap.
  4. Assert that the actual detections match the expectations from metadata.

This bypasses the real packet capture / iptables / NFQUEUE path, so the
tests run as plain unit tests (no root, no real network). What we're
testing is the detection logic itself.

What this proves:
  - LIDRA's existing analyzers (port, dos, fragment, tunnel, covert,
    ipv6, l2, timing, proxy, tcp_fingerprinter, behavioral, session,
    smuggling, DPI) fire on the right kind of traffic.
  - False-positive rate is bounded on benign captures.
  - Coverage matrix is honest — when a pcap isn't caught, that's a
    real finding for the README, not a hidden gap.

Sources for each pcap are documented in the .meta.yaml files.
"""
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import pytest
dpkt = pytest.importorskip("dpkt", reason="dpkt not installed (pip install -r requirements.txt)")
import yaml

# Add src/ to path so we can import LIDRA modules
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC))

from bridge.inline_engine import InlineEngine  # noqa: E402
from utils.severity import is_actionable_severity  # noqa: E402

ATTACK_PCAP_DIR = PROJECT_ROOT / "tests" / "attack_pcap"


def _iter_pcaps():
    """Yield (pcap_path, meta_path) for every .pcap with a .meta.yaml."""
    for root, _, files in os.walk(ATTACK_PCAP_DIR):
        for f in sorted(files):
            if not f.endswith(".pcap"):
                continue
            pcap_path = Path(root) / f
            meta_path = pcap_path.with_suffix("").with_suffix(".pcap.meta.yaml")
            if not meta_path.exists():
                meta_path = pcap_path.parent / (f + ".meta.yaml")
            if meta_path.exists():
                yield pcap_path, meta_path


def _read_packets(pcap_path: Path):
    """Yield raw frame bytes regardless of linktype (Ethernet, raw IP, etc.)."""
    with open(pcap_path, "rb") as f:
        try:
            rdr = dpkt.pcap.Reader(f)
        except Exception as e:
            pytest.skip(f"Cannot open {pcap_path.name}: {e}")
        for ts, buf in rdr:
            yield ts, buf


def _make_engine() -> InlineEngine:
    """Build an InlineEngine with a minimal config; no DB, no callbacks."""
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


def _run_pcap(pcap_path: Path) -> Dict:
    """Replay a pcap through the engine; return aggregate detection stats.

    Two counts, deliberately distinct (see docs/PRODUCTION_READINESS.md §0.1.1):

    * ``packets_with_detection`` — EVERY packet where an analyzer fired. This is
      coverage: did the pipeline see the traffic at all?
    * ``packets_with_actionable_detection`` — packets where a non-``info``
      detection fired. This is what the benign false-positive budget is measured
      against, because severity ``info`` is an observation, not an accusation
      (today: the TLS JA4 passthrough, which reports one for any ClientHello).
      Counting an observation as a false positive would make the benign budget
      unsatisfiable on any TLS traffic and would push someone to silence the
      observation instead of tuning a detector.
    """
    engine = _make_engine()
    detections_by_type: Dict[str, int] = {}
    detections_by_source: Dict[str, int] = {}
    total_packets = 0
    parsed_packets = 0
    packets_with_detection = 0
    packets_with_actionable_detection = 0
    observations_by_type: Dict[str, int] = {}
    start = time.time()

    for _ts, buf in _read_packets(pcap_path):
        total_packets += 1
        packet = engine._parse_packet(buf, capture_ts=_ts)
        if not packet:
            continue
        parsed_packets += 1
        detections = engine._run_detection_pipeline(packet)
        if detections:
            packets_with_detection += 1
            actionable = False
            for d in detections:
                atype = d.get("attack_type", "unknown")
                detections_by_type[atype] = detections_by_type.get(atype, 0) + 1
                src = d.get("source_ip", "")
                if src:
                    detections_by_source[src] = detections_by_source.get(src, 0) + 1
                if is_actionable_severity(d.get("severity", "medium")):
                    actionable = True
                else:
                    observations_by_type[atype] = observations_by_type.get(atype, 0) + 1
            if actionable:
                packets_with_actionable_detection += 1

    elapsed = time.time() - start
    return {
        "pcap": str(pcap_path),
        "total_packets": total_packets,
        "parsed_packets": parsed_packets,
        "packets_with_detection": packets_with_detection,
        "packets_with_actionable_detection": packets_with_actionable_detection,
        "observations_by_type": observations_by_type,
        "detection_types": detections_by_type,
        "top_sources": sorted(
            detections_by_source.items(), key=lambda kv: -kv[1]
        )[:5],
        "elapsed_sec": round(elapsed, 3),
    }


# ---- parametrized test ----------------------------------------------------

def _all_pcap_ids():
    """Parametrize IDs from pcap filenames so test output is readable."""
    return [pcap.name for pcap, _ in _iter_pcaps()]


def _all_pcap_args():
    return [(pcap, meta) for pcap, meta in _iter_pcaps()]


# Pcaps that take >10s to process — skip by default; opt-in via RUN_SLOW_PCAPS=1
SLOW_PCAPS = {"iodine_dns_tunnel.pcap"}


def _should_skip(pcap_path):
    name = pcap_path.name
    if name in SLOW_PCAPS and not os.environ.get("RUN_SLOW_PCAPS"):
        return f"slow pcap ({name}, 30MB). Set RUN_SLOW_PCAPS=1 to run."
    return None


@pytest.mark.parametrize("pcap_path,meta_path", _all_pcap_args(),
                         ids=_all_pcap_ids())
def test_pcap_replay(pcap_path, meta_path, capsys):
    """For each pcap, replay through LIDRA and assert against expectations."""
    skip_reason = _should_skip(pcap_path)
    if skip_reason:
        pytest.skip(skip_reason)

    with open(meta_path) as f:
        meta = yaml.safe_load(f)

    result = _run_pcap(pcap_path)
    captured = "\n".join([
        f"  pcap:           {result['pcap']}",
        f"  packets:        {result['total_packets']} total, "
        f"{result['parsed_packets']} parsed",
        f"  packets w/det:  {result['packets_with_detection']}",
        f"  actionable:     {result['packets_with_actionable_detection']}"
        f"  (observations: {result['observations_by_type']})",
        f"  detection types: {result['detection_types']}",
        f"  top sources:    {result['top_sources']}",
        f"  elapsed:        {result['elapsed_sec']}s",
    ])

    expected_types = meta.get("expected_attack_types") or []
    is_benign = meta.get("attack_category") == "benign"
    min_conf = float(meta.get("expected_min_confidence", 0.0))
    min_packets = int(meta.get("expected_min_packets_with_detection", 0))
    max_fp = int(meta.get("expected_max_false_positives", 0))
    # A packet is a "false positive" if it raised an ACTIONABLE detection.
    # severity "info" is an observation, not an accusation — see _run_pcap
    # and docs/PRODUCTION_READINESS.md §0.1.1.
    fp_count = result["packets_with_actionable_detection"]

    if is_benign:
        with capsys.disabled():
            print(f"\n[BENIGN] {pcap_path.name}")
            print(captured)
        assert fp_count <= max_fp, (
            f"FP rate too high on benign pcap {pcap_path.name}: "
            f"{fp_count} packets flagged (max {max_fp})\n{captured}"
        )
        return

    matched_types = _match_types(result["detection_types"], expected_types)

    with capsys.disabled():
        print(f"\n[ATTACK] {pcap_path.name} ({meta.get('attack_category')})")
        print(captured)
        print(f"  expected:       {expected_types}")
        print(f"  matched:        {matched_types}")

    if min_packets > 0:
        assert result["packets_with_detection"] >= min_packets, (
            f"{pcap_path.name}: only {result['packets_with_detection']} "
            f"packets flagged, expected >= {min_packets}\n{captured}"
        )

    if expected_types and not matched_types:
        pytest.fail(
            f"{pcap_path.name}: NONE of expected attack types detected.\n"
            f"  expected any of: {expected_types}\n"
            f"  got: {list(result['detection_types'].keys())}\n"
            f"{captured}"
        )


def _match_types(detected: Dict[str, int], expected: List[str]) -> List[str]:
    """Loose match: an expected type matches if any detection type shares
    a meaningful token with the expected name. Handles plurals, prefixes,
    suffixes, and short forms.

    Examples that match for "sqli":
      - "sql_injection" (sql overlaps with sqli)
      - "sqli" (exact)
      - "session_correlated_sql_attack" (sql)
    """
    def _tokens(s: str):
        return [t for t in s.lower().replace("_", " ").split() if len(t) > 2]

    def _overlaps(a_tokens, b_tokens):
        for ta in a_tokens:
            for tb in b_tokens:
                if ta in tb or tb in ta:
                    return True
        return False

    matched = []
    for exp in expected:
        exp_tokens = _tokens(exp)
        for d in detected:
            d_tokens = _tokens(d)
            if _overlaps(exp_tokens, d_tokens):
                matched.append(exp)
                break
    return matched


# ---- summary test ---------------------------------------------------------

def test_pcap_summary(capsys):
    """Print a coverage table at the end. Always passes; just informational."""
    rows = []
    for pcap_path, meta_path in _iter_pcaps():
        if _should_skip(pcap_path):
            continue
        with open(meta_path) as f:
            meta = yaml.safe_load(f)
        result = _run_pcap(pcap_path)
        rows.append({
            "category": meta.get("attack_category", "?"),
            "name": pcap_path.name,
            "packets": result["total_packets"],
            "detected": result["packets_with_detection"],
            "types": ",".join(sorted(result["detection_types"].keys())),
        })

    with capsys.disabled():
        print("\n" + "=" * 80)
        print("PCAP COVERAGE REPORT")
        print("=" * 80)
        for r in rows:
            print(f"  [{r['category']:10s}] {r['name']:40s} "
                  f"{r['packets']:>6} pkts -> {r['detected']:>5} flagged: {r['types']}")
        print("=" * 80)
