"""Protocol distribution bar widget."""

from __future__ import annotations

import logging
from typing import Dict

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import ProgressBar, Static

logger = logging.getLogger(__name__)


PROTO_COLORS = {
    "http": "$primary",
    "https": "$primary",
    "dns": "$secondary",
    "tls": "$accent",
    "ssh": "$warning",
    "ftp": "$error",
    "smtp": "$success",
}


class ProtocolBar(Static):
    """A compact bar chart of protocol packet shares."""

    DEFAULT_CSS: str = """
    ProtocolBar {
        height: 1fr;
    }
    .protocol-title {
        background: $primary;
        color: $background;
        text-style: bold;
        padding: 0 1;
        height: 1;
    }
    .proto-row {
        height: 1;
    }
    .proto-label {
        width: 8;
        color: $text-muted;
        padding: 0 1;
    }
    ProgressBar {
        width: 1fr;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("PROTOCOLS", classes="protocol-title")
            for proto in ("http", "dns", "tls", "ssh", "smtp"):
                with Horizontal(classes="proto-row"):
                    yield Static(f"{proto.upper():<5}", classes="proto-label")
                    yield ProgressBar(total=100, id=f"bar-{proto}", show_percentage=False, show_eta=False)

    def update_protocols(self, counts: Dict[str, int]) -> None:
        total = sum(counts.values()) or 1
        for proto in ("http", "dns", "tls", "ssh", "smtp"):
            try:
                bar = self.query_one(f"#bar-{proto}", ProgressBar)
            except Exception:
                continue
            share = (counts.get(proto, 0) / total) * 100
            bar.progress = share
