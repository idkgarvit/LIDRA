"""Per-incident packet forensics — the backtrack gap.

Alerts used to carry metadata only. The engine keeps a rolling window of
recent raw wire bytes; on a high/critical detection it dumps the window to
a pcap next to the alert, so an analyst can open the actual packets.
"""
import logging
import re
import time
from collections import deque
from pathlib import Path
from typing import Deque, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import dpkt
    HAS_DPKT = True
except ImportError:  # pragma: no cover
    dpkt = None  # type: ignore
    HAS_DPKT = False


class ForensicRecorder:
    """Rolling raw-packet window + throttled pcap dumps on detection."""

    def __init__(self, config: dict = None, base_dir: Path = None,
                 max_packets: int = 64, cooldown_s: float = 300,
                 max_files: int = 500):
        cfg = config or {}
        if base_dir is None:
            from utils.paths import get_lidra_root
            base_dir = get_lidra_root() / cfg.get("state_dir", "state")
        self._dir = Path(base_dir) / "forensics"
        self._window: Deque[Tuple[float, bytes, bool]] = deque(maxlen=max_packets)
        self._last_dump: Dict[str, float] = {}
        self._cooldown = cooldown_s
        self._max_files = max_files

    def note_packet(self, ts: float, raw: bytes, is_eth: bool):
        """Record one raw packet. Called on the capture hot path — O(1)."""
        if raw:
            self._window.append((ts, bytes(raw), is_eth))

    def maybe_dump(self, detection: dict) -> Optional[str]:
        """Dump the window to pcap for a qualifying detection. Returns path."""
        if not HAS_DPKT or not self._window:
            return None
        if detection.get("severity") not in ("high", "critical"):
            return None
        ip = detection.get("source_ip", "unknown") or "unknown"
        now = time.time()
        if now - self._last_dump.get(ip, 0) < self._cooldown:
            return None
        self._last_dump[ip] = now
        try:
            day = self._dir / time.strftime("%Y%m%d")
            day.mkdir(parents=True, exist_ok=True)
            # ponytail: one linktype per pcap — the engine runs a single
            # capture source per process, so the trigger packet's framing
            # holds for the whole window.
            linktype = dpkt.pcap.DLT_EN10MB if self._window[-1][2] else dpkt.pcap.DLT_RAW
            safe_ip = re.sub(r"[^0-9a-zA-Z.:]", "_", ip)
            attack = re.sub(r"[^0-9a-zA-Z_.-]", "_", str(detection.get("attack_type", "unknown")))
            path = day / f"{safe_ip}_{attack}_{int(now)}.pcap"
            with open(path, "wb") as f:
                writer = dpkt.pcap.Writer(f, linktype=linktype)
                for ts, raw, _ in list(self._window):
                    writer.writepkt(raw, ts=ts)
            self._prune()
            logger.info(f"[Forensics] dumped {len(self._window)} pkts -> {path}")
            return str(path)
        except Exception as e:
            logger.warning(f"[Forensics] dump failed: {e}")
            return None

    def _prune(self):
        """Cap total pcap files so a long incident can't fill the disk."""
        try:
            files = sorted(self._dir.rglob("*.pcap"), key=lambda p: p.stat().st_mtime)
            for stale in files[:max(0, len(files) - self._max_files)]:
                try:
                    stale.unlink()
                except OSError:
                    pass
        except OSError:
            pass
