"""Reusable severity badge widget.

Renders a compact, color-coded severity indicator suitable for use in
table rows. The badge uses a block character followed by the
upper-cased severity label and is colored according to ``themes``.
"""

from __future__ import annotations

import logging
from typing import ClassVar, Dict

from rich.text import Text
from textual.widgets import Static

from ..themes import SEVERITY_COLORS, severity_style

logger = logging.getLogger(__name__)


_BADGE_FILLS: Dict[str, str] = {
    "critical": "\u2588",
    "high": "\u2588",
    "medium": "\u2588",
    "low": "\u2588",
    "info": "\u2588",
}


class SeverityBadge(Static):
    """A compact severity indicator."""

    SEVERITY_ORDER: ClassVar[tuple[str, ...]] = (
        "critical",
        "high",
        "medium",
        "low",
        "info",
    )

    def __init__(self, severity: str = "info", show_label: bool = True, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._severity = (severity or "info").lower()
        self._show_label = show_label

    @property
    def severity(self) -> str:
        return self._severity

    def watch_severity(self, new: str) -> None:
        self._severity = (new or "info").lower()
        self.refresh()

    def render(self) -> Text:
        sev = (self._severity or "info").lower()
        if sev not in self.SEVERITY_ORDER:
            sev = "info"
        style = severity_style(sev)
        text = Text()
        fill = _BADGE_FILLS.get(sev, "\u2588")
        text.append(f"{fill} ", style=style)
        if self._show_label:
            text.append(sev.upper(), style=style)
        return text


def severity_marker(severity: str) -> Text:
    """Build a single-glyph severity marker, suitable for table cells."""
    sev = (severity or "info").lower()
    if sev not in SeverityBadge.SEVERITY_ORDER:
        sev = "info"
    style = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
    return Text(_BADGE_FILLS.get(sev, "\u2588"), style=style)


def severity_label(severity: str) -> Text:
    """Build a colored text label for a severity string."""
    sev = (severity or "info").lower()
    if sev not in SeverityBadge.SEVERITY_ORDER:
        sev = "info"
    style = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
    return Text(sev.upper(), style=style)


def severity_cell(severity: str) -> Text:
    """Build a combined marker + label suitable for a single table cell."""
    sev = (severity or "info").lower()
    if sev not in SeverityBadge.SEVERITY_ORDER:
        sev = "info"
    style = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
    text = Text()
    text.append(_BADGE_FILLS.get(sev, "\u2588"), style=style)
    text.append(" ")
    text.append(sev.upper(), style=style)
    return text
