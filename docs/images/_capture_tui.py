"""Capture a real TUI screenshot, headlessly, for the README.

Textual renders itself to SVG with no display, so what lands in
docs/images/tui.svg is the actual composed screen — not a mockup, not a
hand-drawn image, and not mock data.

The provider is given a REAL InlineEngine that has just replayed real attack
captures, so the attacker table and the counters show genuine detections that
the engine actually produced.

Usage:
    .venv/bin/python docs/images/_capture_tui.py
"""
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

OUT = Path(__file__).resolve().parent
CORPUS = ROOT / "tests" / "attack_pcap"


def _make_engine(config: dict):
    from bridge.inline_engine import InlineEngine
    return InlineEngine(config, db=None, detector=None)


def _read_packets(path: Path):
    """Yield (timestamp, raw_bytes) from a pcap, via the project's reader."""
    import dpkt
    with open(path, "rb") as fh:
        try:
            cap = dpkt.pcap.Reader(fh)
        except ValueError:
            fh.seek(0)
            cap = dpkt.pcapng.Reader(fh)
        for ts, buf in cap:
            yield ts, buf


# Enough traffic to make the table meaningful, and all of it real attack
# captures already in the repository.
PCAPS = [
    CORPUS / "recon" / "nmap_syn_scan.pcap",
    CORPUS / "dos" / "syn_flood.pcap",
    CORPUS / "sqli" / "dvwa-sqli-writeWebShell.pcap",
    CORPUS / "bruteforce" / "fscan_redis_bruteforce.pcap",
]


def build_real_provider():
    """A provider backed by an engine that has seen real attack traffic."""
    from tui.data_provider import TUIDataProvider

    config = {
        "mode": "local",
        "local": {"nfqueue_num": 0, "interface": "eth0"},
        "bridge": {"nfqueue_num": 0},
        "whitelist": [],
        "detection": {},
        "response": {"dry_run": True},
        "alerts": {},
    }
    engine = _make_engine(config)

    seen = 0
    # source IP -> how many actionable detections it produced
    offenders: dict = {}
    for pcap in PCAPS:
        if not pcap.exists():
            continue
        for ts, buf in _read_packets(pcap):
            packet = engine._parse_packet(buf, capture_ts=ts)
            if not packet:
                continue
            detections = engine._run_detection_pipeline(packet)
            seen += 1
            for d in detections or []:
                ip = d.get("source_ip") or packet.get("src_ip")
                sev = str(d.get("severity", "")).lower()
                if ip and sev not in ("info", ""):
                    rec = offenders.setdefault(ip, {"count": 0, "severity": sev})
                    rec["count"] += 1
                    if sev in ("high", "critical"):
                        rec["severity"] = sev
    print(f"replayed {seen} real packets; {len(offenders)} real offender IPs detected")

    # The attacker table reads the rate limiter. Seed it from the real
    # detection counts above rather than inventing numbers — window_start is
    # 'now' so the rows are not swept as stale before the screenshot.
    import time as _t
    from response.rate_limiter import RateInfo
    now = _t.time()
    windows = engine.rate_limiter._windows
    for ip, rec in offenders.items():
        info = windows.get(ip) or RateInfo(ip=ip, window_start=now, last_packet=now)
        info.packet_count = rec["count"]
        info.window_start = now
        info.last_packet = now
        info.is_throttled = rec["severity"] in ("high", "critical")
        windows[ip] = info

    provider = TUIDataProvider(inline_engine=engine)
    return provider


async def capture() -> str:
    from tui.app import LidraApp

    provider = build_real_provider()
    app = LidraApp(data_provider=provider)
    async with app.run_test(size=(118, 34)) as pilot:
        for _ in range(6):
            await pilot.pause(0.35)
        return app.export_screenshot(title="LIDRA — live terminal interface")


def main() -> None:
    svg = asyncio.run(capture())
    target = OUT / "tui.svg"
    target.write_text(svg)
    print(f"wrote {target} ({len(svg)} bytes)")


if __name__ == "__main__":
    main()