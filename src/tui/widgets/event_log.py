"""Live event log widget."""

from __future__ import annotations

import logging
from typing import Dict

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

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._filter: str = ""
        self._all_events: list[tuple[str, dict]] = []

    def compose(self) -> ComposeResult:
        yield Static("LIVE EVENTS", classes="event-title")
        yield RichLog(id="log-view", max_lines=200, wrap=False, markup=True)

    def add_event(self, event_type: str, data: Dict) -> None:
        self._all_events.append((event_type, data))
        if self._filter and self._filter.lower() not in str(data).lower():
            return
        self._write_event(event_type, data)

    def clear_log(self) -> None:
        """Clear all events from the log."""
        self._all_events.clear()
        try:
            log = self.query_one(RichLog)
            log.clear()
        except Exception:
            logger.debug("RichLog not yet mounted")

    def set_max_lines(self, n: int) -> None:
        """Set the maximum number of visible lines."""
        try:
            log = self.query_one(RichLog)
            log.max_lines = max(n, 10)
        except Exception:
            logger.debug("RichLog not yet mounted")

    def set_filter(self, term: str) -> None:
        """Set a filter term. Events not matching are hidden. Empty string clears filter."""
        self._filter = term
        try:
            log = self.query_one(RichLog)
            log.clear()
            if not term:
                # Replay all events
                for etype, data in self._all_events:
                    self._write_event(etype, data)
            else:
                # Show only matching
                for etype, data in self._all_events:
                    if term.lower() in str(data).lower():
                        self._write_event(etype, data)
        except Exception:
            logger.debug("RichLog filter failed")

    def _write_event(self, event_type: str, data: Dict) -> None:
        try:
            log = self.query_one(RichLog)
        except Exception:
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
