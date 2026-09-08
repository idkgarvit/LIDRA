"""Live activity panel: sparkline + protocol split + totals.

Replaces the old separate Sparkline + ProtocolBar pair with a single
panel that answers "what's the network doing right now" in one glance.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Deque, Dict, List

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Static

from ..style_utils import resolve

logger = logging.getLogger(__name__)

SPARK_CHARS = "▁▂▃▄▅▆▇█"

PROTOCOL_ORDER = ("tcp", "udp", "icmp", "http", "tls", "dns", "ssh", "other")
PROTOCOL_LABEL = {
    "tcp": "TCP", "udp": "UDP", "icmp": "ICMP",
    "http": "HTTP", "tls": "TLS", "dns": "DNS", "ssh": "SSH",
    "other": "Other",
}
PROTOCOL_COLOR = {
    "tcp": "primary", "udp": "secondary", "icmp": "warning",
    "http": "success", "tls": "primary", "dns": "secondary",
    "ssh": "error", "other": "muted",
}


def _bar(value: float, max_value: float) -> str:
    if max_value <= 0:
        return " "
    idx = int((value / max_value) * (len(SPARK_CHARS) - 1))
    idx = max(0, min(len(SPARK_CHARS) - 1, idx))
    return SPARK_CHARS[idx]


class PacketGauge(Static):
    """A self-contained live-traffic panel: sparkline + protocol split + total."""

    DEFAULT_CSS: str = """
    PacketGauge {
        height: auto;
    }
    .activity-title {
        background: $secondary;
        color: $background;
        text-style: bold;
        padding: 0 1;
        height: 1;
    }
    .activity-row {
        height: 3;
        padding: 0 1;
    }
    .activity-value {
        width: 22;
        content-align: right middle;
        padding: 0 1;
        color: $primary;
        text-style: bold;
    }
    .activity-meta {
        height: 1;
        color: $text-muted;
        padding: 0 1;
    }
    .activity-protocols {
        height: 1;
        padding: 0 1;
    }
    """

    pps: reactive[int] = reactive(0)

    def __init__(self, window: int = 60, **kwargs) -> None:
        super().__init__(**kwargs)
        self._window = window
        self._samples: Deque[int] = deque(maxlen=window)
        self._peak: int = 0
        self._total: int = 0
        self._protocols: Dict[str, int] = {}

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("LIVE TRAFFIC", classes="activity-title")
            with Horizontal(classes="activity-row"):
                yield Static("", id="activity-spark", classes="activity-spark")
                yield Static("0 pkts/s", id="activity-value", classes="activity-value")
            yield Static("peak: 0   avg: 0   min: 0", id="activity-meta", classes="activity-meta")
            yield Static("", id="activity-protocols", classes="activity-protocols")

    def update_flow(self, value: int, history: List[int]) -> None:
        """Back-compat with the old (value, history) signature."""
        self.pps = int(value)
        if history:
            self._samples = deque(history[-self._window:], maxlen=self._window)
            self._peak = max(self._samples) if self._samples else 0
            self._total = sum(self._samples)
        else:
            self._samples.append(int(value))
            if int(value) > self._peak:
                self._peak = int(value)
        self._refresh_spark()

    def update_protocols(self, protocols: Dict[str, int]) -> None:
        self._protocols = {k: int(v) for k, v in protocols.items() if v}
        self._refresh_protocols()

    def _refresh_spark(self) -> None:
        try:
            spark = self.query_one("#activity-spark", Static)
        except Exception:
            return
        if not self._samples:
            return
        max_v = max(self._samples) or 1
        bars = "".join(_bar(v, max_v) for v in self._samples)
        current = self._samples[-1]
        avg = sum(self._samples) // len(self._samples)
        lo = min(self._samples)
        cls = "success" if current < 500 else "warning" if current < 2000 else "error"
        spark.update(Text.assemble(
            (f"{current:>5,} pps  ", f"bold {resolve(cls)}"),
            (f"peak {self._peak:>5,}  avg {avg:>5,}  min {lo:>5,}\n", resolve("muted")),
            (bars, resolve("primary")),
        ))
        try:
            self.query_one("#activity-value", Static).update(
                Text(f"{current:,} pkts/s", style=f"bold {resolve('primary')}")
            )
        except Exception:
            pass
        try:
            self.query_one("#activity-meta", Static).update(
                f"window: {len(self._samples)}s   total: {self._total:,} pkts"
            )
        except Exception:
            pass

    def _refresh_protocols(self) -> None:
        try:
            slot = self.query_one("#activity-protocols", Static)
        except Exception:
            return
        if not self._protocols:
            slot.update(Text("protocols: —", style=resolve("muted")))
            return
        ordered = sorted(
            self._protocols.items(),
            key=lambda kv: PROTOCOL_ORDER.index(kv[0]) if kv[0] in PROTOCOL_ORDER else 99,
        )
        total = sum(self._protocols.values()) or 1
        parts: list = [("protocols: ", resolve("muted"))]
        for name, count in ordered:
            label = PROTOCOL_LABEL.get(name, name.upper())
            color = PROTOCOL_COLOR.get(name, "foreground")
            pct = count * 100 // total
            parts.append((f"{label} ", resolve(color)))
            parts.append((f"{pct:>2}%  ", resolve("muted")))
        slot.update(Text.assemble(*parts))
