import logging
import os
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

_XDP_AVAILABLE = False
try:
    from bcc import BPF
    _XDP_AVAILABLE = True
except ImportError:
    logger.info("[XDP] BCC not available; XDP acceleration disabled")

_XDP_FLAGS_SKB = 1
_XDP_FLAGS_DRV = 2
_XDP_FLAGS_HW = 4


class XDPLoader:
    def __init__(self, interface: str = "", blocklist: Optional[Set[str]] = None):
        self._interface = interface or self._detect_iface()
        self._blocklist = set(blocklist or [])
        self._bpf = None
        self._running = False
        self._stats = {"dropped": 0, "passed": 0}
        self._lock = threading.Lock()

    def _detect_iface(self) -> str:
        try:
            import subprocess
            r = subprocess.run(
                ["ip", "-o", "link", "show", "up"],
                capture_output=True, text=True, timeout=5
            )
            for line in r.stdout.strip().split("\n"):
                parts = line.split(": ")
                if len(parts) >= 2:
                    iface = parts[1].split("@")[0]
                    if iface != "lo":
                        return iface
        except Exception:
            pass
        return "eth0"

    def load(self) -> bool:
        if not _XDP_AVAILABLE:
            logger.warning("[XDP] Cannot load: BCC not available")
            return False

        xdp_path = Path(__file__).parent / "xdp_drop.c"
        if not xdp_path.exists():
            logger.error(f"[XDP] Program not found: {xdp_path}")
            return False

        try:
            self._bpf = BPF(src_file=str(xdp_path))
            fn = self._bpf.load_func("xdp_drop", BPF.XDP)
            self._bpf.attach_xdp(self._interface, fn, _XDP_FLAGS_DRV)
            self._running = True
            logger.info(f"[XDP] Loaded on {self._interface}")
            self._populate_blocklist()
            self._start_stats_poll()
            return True
        except Exception as e:
            logger.warning(f"[XDP] Load failed (fallback to AF_PACKET): {e}")
            return False

    def _populate_blocklist(self):
        blocklist_map = self._bpf.get_table("blocklist")
        for ip_str in self._blocklist:
            try:
                ip_int = struct.unpack(">I", socket.inet_aton(ip_str))[0]
                key = blocklist_map.Key(ip=ip_int, prefix=32)
                val = blocklist_map.Leaf()
                blocklist_map[key] = val
            except Exception:
                continue
        if self._blocklist:
            logger.info(f"[XDP] Loaded {len(self._blocklist)} blocklist entries")

    def _start_stats_poll(self):
        def _poll():
            stats_map = self._bpf.get_table("stats")
            while self._running:
                try:
                    for k, v in stats_map.items():
                        with self._lock:
                            self._stats["dropped"] = v.value
                except Exception:
                    pass
                time.sleep(5)
        t = threading.Thread(target=_poll, daemon=True)
        t.start()

    def update_blocklist(self, ips: Set[str]):
        self._blocklist = set(ips)
        if self._running:
            self._populate_blocklist()

    def unload(self):
        self._running = False
        if self._bpf:
            try:
                self._bpf.remove_xdp(self._interface, _XDP_FLAGS_DRV)
            except Exception:
                pass
            logger.info("[XDP] Unloaded")

    def get_stats(self) -> Dict:
        with self._lock:
            return dict(self._stats)

    def is_loaded(self) -> bool:
        return self._running
