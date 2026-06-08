"""Live event log widget."""

from __future__ import annotations

import logging
from typing import Dict, Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.widgets import RichLog, Static

from ..style_utils import resolve
from ..themes import severity_style

logger = logging.getLogger(__name__)


class EventLog(Static):
    """A live, severity-coloured event log."""

    DEFAULT_CSS: str = """
    EventLog {
        height: 1fr;
    }
    .event-title {
        background: $secondary;
        color: $background;
        text-style: bold;
        padding: 0 1;
        height: 1;
    }
    RichLog {
        background: $panel;
        height: 1fr;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("LIVE EVENTS", classes="event-title")
        yield RichLog(id="log-view", max_lines=200, wrap=False, markup=True)

    def add_event(self, event_type: str, data: Dict) -> None:
        try:
            log = self.query_one(RichLog)
        except Exception:
            logger.debug("RichLog not yet mounted")
            return
        severity = (data.get("severity") or "info").lower()
        style = severity_style(severity)
        ts = data.get("timestamp", "")
        ip = data.get("ip", "N/A")
        etype = data.get("type", data.get("reason", event_type))
        msg = Text()
        msg.append(f"[{ts}] ", style=resolve("muted"))
        msg.append(f"{event_type.upper():<8} ", style=f"bold {style}")
        msg.append(f"{ip:<18} ", style=f"bold {resolve('primary')}")
        msg.append(str(etype), style=style)
        log.write(msg)
