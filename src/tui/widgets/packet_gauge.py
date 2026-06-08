"""Packet flow gauge widget."""

from __future__ import annotations

import logging
from typing import List

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Sparkline, Static

from ..style_utils import resolve

logger = logging.getLogger(__name__)


class PacketGauge(Static):
    """A horizontal packet rate gauge with a sparkline."""

    DEFAULT_CSS: str = """
    PacketGauge {
        height: 1fr;
    }
    .packet-title {
        background: $secondary;
        color: $background;
        text-style: bold;
        padding: 0 1;
        height: 1;
    }
    .packet-row {
        height: 3;
    }
    Sparkline {
        width: 1fr;
        background: $panel;
    }
    .packet-value {
        width: 18;
        content-align: right middle;
        padding: 0 1;
        color: $primary;
        text-style: bold;
    }
    .packet-meta {
        height: 1;
        color: $text-muted;
        padding: 0 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("PACKET FLOW (pkts/sec)", classes="packet-title")
            with Horizontal(classes="packet-row"):
                yield Sparkline([0] * 20, id="flow-sparkline")
                yield Static("0 pkts/s", id="flow-value", classes="packet-value")
            yield Static("peak: 0   avg: 0   min: 0", id="flow-meta", classes="packet-meta")

    def update_flow(self, value: int, history: List[int]) -> None:
        try:
            spark = self.query_one("#flow-sparkline", Sparkline)
            spark.data = history[-120:] if history else [0]
        except Exception:
            logger.debug("Sparkline widget not yet mounted")
        try:
            label = self.query_one("#flow-value", Static)
            label.update(Text.assemble(
                (f"{int(value):,}", f"bold {resolve('primary')}"),
                (" pkts/s", resolve("muted")),
            ))
        except Exception:
            logger.debug("flow-value not yet mounted")
        try:
            meta = self.query_one("#flow-meta", Static)
            if history:
                peak = max(history)
                avg = sum(history) // len(history)
                lo = min(history)
                meta.update(f"peak: {peak:,}   avg: {avg:,}   min: {lo:,}")
        except Exception:
            logger.debug("flow-meta not yet mounted")
