"""Sparkline widget for packet rate (last 60 seconds)."""

from __future__ import annotations

import logging
from collections import deque
from typing import Deque, List, Optional

from textual.app import ComposeResult
from textual.widgets import Static

logger = logging.getLogger(__name__)


SPARK_CHARS = "▁▂▃▄▅▆▇█"


def _bar_char(value: float, max_value: float) -> str:
    if max_value <= 0:
        return " "
    idx = int((value / max_value) * (len(SPARK_CHARS) - 1))
    idx = max(0, min(len(SPARK_CHARS) - 1, idx))
    return SPARK_CHARS[idx]


class Sparkline(Static):
    """Live sparkline of packets/sec."""

    DEFAULT_CSS = """
    Sparkline {
        height: 3;
        padding: 0 1;
    }
    Sparkline .sparkline-title {
        color: $primary;
        text-style: bold;
    }
    Sparkline .sparkline-value {
        color: $foreground;
    }
    Sparkline .sparkline-warn {
        color: $warning;
    }
    Sparkline .sparkline-error {
        color: $error;
    }
    """

    def __init__(self, window: int = 60, **kwargs) -> None:
        super().__init__("", **kwargs)
        self._window = window
        self._samples: Deque[int] = deque(maxlen=window)
        self._peak: int = 0
        self._total: int = 0

    def compose(self) -> ComposeResult:
        yield Static("", id="sparkline-content")

    def push_sample(self, value: int) -> None:
        self._samples.append(value)
        if value > self._peak:
            self._peak = value
        self._total += value
        self._refresh()

    def _refresh(self) -> None:
        if not self._samples:
            return
        max_v = max(self._samples)
        bars = "".join(_bar_char(v, max_v) for v in self._samples)
        current = self._samples[-1]
        avg = sum(self._samples) // len(self._samples)

        cls = "sparkline-value"
        if current >= 2000:
            cls = "sparkline-error"
        elif current >= 500:
            cls = "sparkline-warn"

        text = f"[{cls}]{current:,}[/] pkts/s  [dim]peak: {self._peak:,}  avg: {avg:,}[/]\n{bars}"
        try:
            self.query_one("#sparkline-content", Static).update(text)
        except Exception:
            pass

    def reset(self) -> None:
        self._samples.clear()
        self._peak = 0
        self._total = 0
