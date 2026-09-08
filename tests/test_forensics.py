"""ForensicRecorder: pcap backtrack for high/critical detections."""
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import dpkt  # noqa: E402
from bridge.forensics import ForensicRecorder  # noqa: E402

ETH_IP = b"\x00" * 12 + b"\x08\x00" + b"E\x00\x00\x14" + b"\x00" * 16


def _rec(tmp_path, **kw):
    kw.setdefault("cooldown_s", 0)
    return ForensicRecorder(config={}, base_dir=tmp_path, **kw)


def test_high_severity_dumps_window(tmp_path):
    r = _rec(tmp_path)
    for _ in range(3):
        r.note_packet(time.time(), ETH_IP, True)
    path = r.maybe_dump({"severity": "high", "source_ip": "1.2.3.4", "attack_type": "syn_burst"})
    assert path and Path(path).exists()
    with open(path, "rb") as f:
        pkts = list(dpkt.pcap.Reader(f))
    assert len(pkts) == 3
    assert pkts[0][1] == ETH_IP


def test_medium_severity_skipped(tmp_path):
    r = _rec(tmp_path)
    r.note_packet(time.time(), ETH_IP, True)
    assert r.maybe_dump({"severity": "medium", "source_ip": "1.2.3.4"}) is None


def test_per_ip_cooldown(tmp_path):
    r = ForensicRecorder(config={}, base_dir=tmp_path, cooldown_s=300)
    r.note_packet(time.time(), ETH_IP, True)
    d = {"severity": "critical", "source_ip": "1.2.3.4"}
    assert r.maybe_dump(d) is not None
    assert r.maybe_dump(d) is None  # same IP still cooling down
    d2 = {"severity": "critical", "source_ip": "5.6.7.8"}
    assert r.maybe_dump(d2) is not None  # other IP unaffected


def test_prune_caps_files(tmp_path):
    r = _rec(tmp_path, max_files=2)
    for i, ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3"]):
        r.note_packet(time.time(), ETH_IP, True)
        assert r.maybe_dump({"severity": "high", "source_ip": ip})
    assert len(list(tmp_path.rglob("*.pcap"))) == 2
