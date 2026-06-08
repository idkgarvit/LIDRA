#!/usr/bin/env python3
"""Benchmark: pcap replay throughput, latency, and memory.

For each pcap in tests/attack_pcap/, replays through the full
InlineEngine detection pipeline and measures:

  - Wall-clock time (seconds)
  - Packets / second
  - Packets with detection (%)
  - Peak RSS (MB)

Usage:
  python3 bench/run_benchmark.py               # skip slow pcaps
  python3 bench/run_benchmark.py --all         # include iodine (30MB)
  python3 bench/run_benchmark.py --json-only   # compact JSON output
"""
import argparse
import json
import os
import resource
import sys
import time
from pathlib import Path
from typing import Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC))

from bridge.inline_engine import InlineEngine
import dpkt

ATTACK_PCAP_DIR = PROJECT_ROOT / "tests" / "attack_pcap"

SLOW_PCAPS = {"iodine_dns_tunnel.pcap"}


def _iter_pcaps():
    for root, _, files in os.walk(ATTACK_PCAP_DIR):
        for f in sorted(files):
            if not f.endswith(".pcap"):
                continue
            yield Path(root) / f


def _read_packets(pcap_path: Path):
    with open(pcap_path, "rb") as f:
        try:
            rdr = dpkt.pcap.Reader(f)
        except Exception as e:
            raise RuntimeError(f"Cannot open {pcap_path}: {e}") from e
        for ts, buf in rdr:
            yield ts, buf


def _make_engine() -> InlineEngine:
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


def _current_rss_mb() -> float:
    """Return instantaneous RSS in MB from /proc/self/status."""
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return float(line.split()[1]) / 1024.0
    except Exception:
        pass
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def run_single(pcap_path: Path, runs: int = 3) -> Dict:
    """Run a pcap through the detection pipeline *runs* times.

    Returns summary dict with min/avg/max for wall time, pps, RSS.
    """
    # Count packets first (fast, no engine)
    pkt_bufs = list(_read_packets(pcap_path))
    total_packets = len(pkt_bufs)

    times: List[float] = []
    pps_vals: List[float] = []
    mems: List[float] = []
    parsed_vals: List[int] = []
    det_packet_vals: List[int] = []

    for _ in range(runs):
        engine = _make_engine()
        mem_before = _current_rss_mb()
        parsed = 0
        det_packets: set = set()
        start = time.perf_counter()

        for buf in (_b for _ts, _b in pkt_bufs):
            packet = engine._parse_packet(buf)
            if not packet:
                continue
            parsed += 1
            detections = engine._run_detection_pipeline(packet)
            if detections:
                det_packets.add(id(packet))

        elapsed = time.perf_counter() - start
        mem_after = _current_rss_mb()
        mems.append(max(0.0, mem_after - mem_before))
        times.append(elapsed)
        pps_vals.append(parsed / elapsed if elapsed > 0 else 0.0)
        parsed_vals.append(parsed)
        det_packet_vals.append(len(det_packets))
        del engine

    def _agg(vals):
        return {
            "min": round(min(vals), 3),
            "avg": round(sum(vals) / len(vals), 3),
            "max": round(max(vals), 3),
        }

    return {
        "pcap": pcap_path.name,
        "file_size_mb": round(pcap_path.stat().st_size / (1024 * 1024), 2),
        "total_packets": total_packets,
        "parsed": _agg(parsed_vals),
        "packets_with_detection": _agg(det_packet_vals),
        "elapsed_sec": _agg(times),
        "packets_per_second": _agg(pps_vals),
        "peak_rss_mb": _agg(mems),
    }


def print_markdown(results: List[Dict]):
    header = "| Pcap | Size | Packets | Parsed | PPS | Elapsed (s) | FP packets | Peak RSS (MB) |"
    sep = "|------|------|---------|--------|-----|-------------|------------|---------------|"
    print(header)
    print(sep)
    for r in results:
        name = r["pcap"]
        size = f"{r['file_size_mb']}MB"
        pkts = r["total_packets"]
        parsed_avg = r["parsed"]["avg"]
        pps = r["packets_per_second"]["avg"]
        elapsed = r["elapsed_sec"]["avg"]
        fps = r["packets_with_detection"]["avg"]
        rss = r["peak_rss_mb"]["avg"]
        print(
            f"| {name} | {size} | {pkts} | {parsed_avg:.0f} "
            f"| {pps:.0f} | {elapsed:.3f} "
            f"| {fps:.0f} | {rss:.1f} |"
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="Include slow pcaps (iodine)")
    parser.add_argument("--json-only", action="store_true", help="JSON output only")
    parser.add_argument("--runs", type=int, default=3, help="Runs per pcap (default 3)")
    args = parser.parse_args()

    pcaps = list(_iter_pcaps())
    results: List[Dict] = []

    for i, pcap_path in enumerate(pcaps):
        is_slow = pcap_path.name in SLOW_PCAPS
        if is_slow and not args.all:
            print(f"[{i+1}/{len(pcaps)}] {pcap_path.name} — SKIP (slow, use --all)", flush=True)
            continue

        runs = 1 if is_slow else args.runs
        print(f"[{i+1}/{len(pcaps)}] {pcap_path.name} ({runs}x runs)...", end=" ", flush=True)
        try:
            result = run_single(pcap_path, runs=runs)
            results.append(result)
            pps = result["packets_per_second"]["avg"]
            elapsed = result["elapsed_sec"]["avg"]
            print(f"{pps:.0f} pps, {elapsed:.3f}s", flush=True)
        except Exception as e:
            print(f"FAILED: {e}", flush=True)

    print("\n\n## Benchmark Results\n")
    print_markdown(results)

    # Write JSON for CI/automation
    json_path = Path(__file__).parent / "RESULTS.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nJSON written to {json_path}")

    # Summary
    if results:
        all_pps = [r["packets_per_second"]["avg"] for r in results]
        avg_pps = sum(all_pps) / len(all_pps)
        print(f"\nAverage PPS across all pcaps: {avg_pps:.0f}")
        print(f"Min PPS: {min(all_pps):.0f} ({results[all_pps.index(min(all_pps))]['pcap']})")
        print(f"Max PPS: {max(all_pps):.0f} ({results[all_pps.index(max(all_pps))]['pcap']})")


if __name__ == "__main__":
    main()
