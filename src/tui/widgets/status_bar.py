"""Top status bar shown above the dashboard.

Shows version, environment, mode, packet rate, attack count, blocked
count and a live clock. The bar updates every 500 ms and reflects the
worst current state (green \u2192 yellow \u2192 red) via the ``health`` reactive.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import Static

from ..style_utils import resolve
from ..themes import THEMES, current_tokens, severity_style

logger = logging.getLogger(__name__)


VERSION: str = "v3.0.0"


@dataclass
class StatusSnapshot:
    version: str = VERSION
    environment: str = "local"
    interface: str = "eth0"
    mode: str = "dry-run"
    packets_per_sec: int = 0
    attack_count: int = 0
    blocked_count: int = 0
    critical_count: int = 0
    top_ip: str = "—"
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))

    @property
    def health(self) -> str:
        if self.attack_count >= 50 or self.blocked_count >= 20:
            return "error"
        if self.attack_count >= 10 or self.blocked_count >= 5:
            return "warning"
        return "ok"

    @property
    def health_color(self) -> str:
        tokens = current_tokens_for_health()
        return {
            "ok": tokens.get("success", "green"),
            "warning": tokens.get("warning", "yellow"),
            "error": tokens.get("error", "red"),
        }[self.health]


def current_tokens_for_health() -> dict:
    """Return the current theme tokens via a Textual App fallback.

    The status bar is a child of an App, so this is overridden at runtime
    via :func:`bind_tokens_provider`. We keep this default safe for any
    headless import-time usage.
    """
    return THEMES["dark"].tokens


_tokens_provider = current_tokens_for_health


def bind_tokens_provider(fn) -> None:
    """Allow the app to inject a token provider that reads the live theme."""
    global _tokens_provider
    _tokens_provider = fn


def _arrow(value: int) -> str:
    return "\u2191" if value >= 0 else "\u2193"


class StatusBar(Static):
    """A single-line top-of-screen status bar."""

    DEFAULT_CSS: str = """
    StatusBar {
        height: 1;
        background: $panel;
        color: $foreground;
        padding: 0 1;
        border-bottom: solid $border;
    }
    StatusBar > Horizontal {
        height: 1;
    }
    .status-cell {
        height: 1;
        padding: 0 1;
    }
    .status-cell:hover {
        background: $boost;
    }
    .status-spacer {
        width: 1fr;
    }
    .status-version { color: $primary; text-style: bold; }
    .status-ok { color: $success; }
    .status-warn { color: $warning; }
    .status-error { color: $error; text-style: bold; }
    StatusBar.critical-flash {
        background: $error;
        color: $background;
        text-style: bold;
    }
    StatusBar.critical-flash > Horizontal > .status-cell {
        color: $background;
    }
    """

    snapshot: reactive[StatusSnapshot] = reactive(
        StatusSnapshot, init=False, always_update=True
    )

    class Clicked(Message):
        def __init__(self, area: str) -> None:
            super().__init__()
            self.area = area

    def compose(self) -> ComposeResult:
        with Horizontal(id="status-row"):
            yield Static(self._render_initial("version"), id="status-version", classes="status-cell status-version")
            yield Static(self._render_initial("env"), id="status-env", classes="status-cell")
            yield Static(self._render_initial("iface"), id="status-iface", classes="status-cell")
            yield Static(self._render_initial("mode"), id="status-mode", classes="status-cell")
            yield Static(self._render_initial("rate"), id="status-rate", classes="status-cell")
            yield Static(self._render_initial("attacks"), id="status-attacks", classes="status-cell")
            yield Static(self._render_initial("critical"), id="status-critical", classes="status-cell")
            yield Static(self._render_initial("blocked"), id="status-blocked", classes="status-cell")
            yield Static(self._render_initial("top"), id="status-top", classes="status-cell")
            yield Static(self._render_initial("clock"), id="status-clock", classes="status-cell")

    def _render_initial(self, area: str) -> str:
        snap = StatusSnapshot()
        return self._format_cell(area, snap)

    def _format_cell(self, area: str, snap: StatusSnapshot) -> Text:
        tokens = _tokens_provider()
        if area == "version":
            return Text(f" LIDRA {snap.version} ", style=f"bold {tokens.get('primary', '#3DD2C0')}")
        if area == "env":
            return Text(f" {snap.environment} ", style=tokens.get("muted", "#5A6472"))
        if area == "iface":
            return Text(f" {snap.interface} ", style=tokens.get("foreground", "#E6E6E6"))
        if area == "mode":
            color = tokens.get("warning", "#E0A33A") if snap.mode.lower() in ("dry-run",) else tokens.get("success", "#4EBF71")
            return Text(f" {snap.mode} ", style=color)
        if area == "rate":
            return Text(f" {_arrow(snap.packets_per_sec)} {snap.packets_per_sec:,} pps ", style=tokens.get("foreground", "#E6E6E6"))
        if area == "attacks":
            if snap.attack_count >= 50:
                style = f"bold {tokens.get('error', '#E84B4B')}"
                glyph = "\u26a0"
            elif snap.attack_count >= 10:
                style = tokens.get("warning", "#E0A33A")
                glyph = "\u26a0"
            else:
                style = tokens.get("foreground", "#E6E6E6")
                glyph = "\u2713"
            return Text(f" {glyph} {snap.attack_count} attacks ", style=style)
        if area == "blocked":
            if snap.blocked_count >= 20:
                style = f"bold {tokens.get('error', '#E84B4B')}"
            elif snap.blocked_count >= 5:
                style = tokens.get("warning", "#E0A33A")
            else:
                style = tokens.get("success", "#4EBF71")
            return Text(f" \u2713 {snap.blocked_count} blocked ", style=style)
        if area == "critical":
            if snap.critical_count >= 5:
                style = f"bold {tokens.get('error', '#E84B4B')}"
                glyph = "\u2620"
            elif snap.critical_count >= 1:
                style = f"bold {tokens.get('error', '#E84B4B')}"
                glyph = "\u2620"
            else:
                style = tokens.get("muted", "#5A6472")
                glyph = "\u2620"
            return Text(f" {glyph} {snap.critical_count} crit ", style=style)
        if area == "top":
            return Text(f" \u2192 {snap.top_ip} ", style=tokens.get("foreground", "#E6E6E6"))
        if area == "clock":
            return Text(f" {snap.timestamp} ", style=tokens.get("muted", "#5A6472"))
        return Text("")

    def update_snapshot(self, snapshot: StatusSnapshot) -> None:
        snap = StatusSnapshot(
            version=snapshot.version or VERSION,
            environment=snapshot.environment or "local",
            interface=snapshot.interface or "eth0",
            mode=snapshot.mode or "dry-run",
            packets_per_sec=int(snapshot.packets_per_sec or 0),
            attack_count=int(snapshot.attack_count or 0),
            blocked_count=int(snapshot.blocked_count or 0),
            critical_count=int(getattr(snapshot, "critical_count", 0) or 0),
            top_ip=str(getattr(snapshot, "top_ip", "—") or "—"),
            timestamp=datetime.now().strftime("%H:%M:%S"),
        )
        self.snapshot = snap

    def flash_critical(self, duration: float = 3.0) -> None:
        """Briefly tint the bar red to draw attention to a critical event."""
        self.add_class("critical-flash")

        def _clear():
            try:
                self.remove_class("critical-flash")
            except Exception:
                pass

        self.set_timer(duration, _clear)

    def watch_snapshot(self, snap: StatusSnapshot) -> None:
        cells = {
            "status-version": "version",
            "status-env": "env",
            "status-iface": "iface",
            "status-mode": "mode",
            "status-rate": "rate",
            "status-attacks": "attacks",
            "status-critical": "critical",
            "status-blocked": "blocked",
            "status-top": "top",
            "status-clock": "clock",
        }
        for widget_id, area in cells.items():
            try:
                self.query_one(f"#{widget_id}", Static).update(self._format_cell(area, snap))
            except Exception:
                logger.debug("Missing status cell %s", widget_id)

    def on_static_click(self, event: Static.Click) -> None:
        widget = event.widget
        widget_id = getattr(widget, "id", "") or ""
        area_map = {
            "status-version": "version",
            "status-env": "environment",
            "status-iface": "interface",
            "status-mode": "mode",
            "status-rate": "rate",
            "status-attacks": "attacks",
            "status-blocked": "blocked",
            "status-clock": "clock",
        }
        area = area_map.get(widget_id)
        if area:
            self.post_message(self.Clicked(area))
