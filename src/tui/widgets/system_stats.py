"""System stats panel widget."""

from __future__ import annotations

import logging
from typing import Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Static

from ..themes import current_tokens

logger = logging.getLogger(__name__)


BRIDGE_COLOR_KEY = {
    "UP": "success",
    "DOWN": "error",
    "UNKNOWN": "muted",
    "DEGRADED": "warning",
}


def _resolve(token: str) -> str:
    """Resolve a theme token name to its hex value, falling back to the input."""
    return current_tokens_for_widget().get(token, token)


def current_tokens_for_widget():
    try:
        from textual.app import App
        from textual._context import active_app
        app = active_app.get()
        if app is not None:
            from ..themes import current_tokens
            return current_tokens(app)
    except Exception:
        pass
    from ..themes import DARK_THEME
    return DARK_THEME


class SystemStats(Static):
    """A small system panel showing CPU, memory and bridge status."""

    DEFAULT_CSS: str = """
    SystemStats {
        height: 1fr;
    }
    .system-title {
        background: $secondary;
        color: $background;
        text-style: bold;
        padding: 0 1;
        height: 1;
    }
    .stat-row {
        height: 1;
        padding: 0 1;
    }
    .stat-label {
        color: $text-muted;
    }
    .stat-value {
        color: $foreground;
        text-style: bold;
    }
    .stat-ok { color: $success; }
    .stat-warn { color: $warning; }
    .stat-error { color: $error; }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("SYSTEM", classes="system-title")
            yield Static(self._fmt_row("CPU", "0.0%"), id="stat-cpu", classes="stat-row")
            yield Static(self._fmt_row("MEM", "0.0%"), id="stat-mem", classes="stat-row")
            yield Static(self._fmt_row("BRIDGE", "UNKNOWN"), id="stat-bridge", classes="stat-row")
            yield Static(self._fmt_row("UPTIME", "00:00:00"), id="stat-uptime", classes="stat-row")
            yield Static(self._fmt_row("DEMO", "off"), id="stat-demo", classes="stat-row")

    def _fmt_row(self, label: str, value: str) -> Text:
        text = Text()
        muted = _resolve("muted")
        text.append(f"{label:<7} ", style=muted)
        text.append(value, style=f"bold {_resolve('foreground')}")
        return text

    def update_stats(self, cpu: float, mem: float, bridge: str) -> None:
        bridge_status = (bridge or "UNKNOWN").upper()
        bridge_key = BRIDGE_COLOR_KEY.get(bridge_status, "muted")
        bridge_color = _resolve(bridge_key)
        try:
            self.query_one("#stat-cpu", Static).update(self._fmt_colored("CPU", f"{cpu:.1f}%", cpu))
            self.query_one("#stat-mem", Static).update(self._fmt_colored("MEM", f"{mem:.1f}%", mem))
            self.query_one("#stat-bridge", Static).update(
                Text.assemble(
                    ("BRIDGE  ", _resolve("muted")),
                    (bridge_status, f"bold {bridge_color}"),
                )
            )
        except Exception:
            logger.debug("System stats widgets not yet mounted")

    def _fmt_colored(self, label: str, value: str, percent: float) -> Text:
        text = Text()
        text.append(f"{label:<7} ", style=_resolve("muted"))
        if percent >= 85:
            style = f"bold {_resolve('error')}"
        elif percent >= 65:
            style = f"bold {_resolve('warning')}"
        else:
            style = f"bold {_resolve('success')}"
        text.append(value, style=style)
        return text

    def update_uptime(self, uptime: str) -> None:
        try:
            self.query_one("#stat-uptime", Static).update(self._fmt_row("UPTIME", uptime))
        except Exception:
            logger.debug("Uptime widget not yet mounted")

    def update_demo(self, enabled: bool) -> None:
        try:
            self.query_one("#stat-demo", Static).update(
                Text.assemble(
                    ("DEMO    ", _resolve("muted")),
                    ("on" if enabled else "off",
                     f"bold {_resolve('warning')}" if enabled else _resolve("muted")),
                )
            )
        except Exception:
            logger.debug("Demo widget not yet mounted")
