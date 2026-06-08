"""Context menu shown on right-click of an attacker row.

Implements a small modal with Block / Whois / View Details / Copy IP
options. The menu is shown relative to the click coordinates.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import ClassVar, List, Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

from ..style_utils import resolve

logger = logging.getLogger(__name__)


@dataclass
class ContextMenuAction:
    label: str
    action_id: str


class ContextMenuScreen(ModalScreen):
    """A right-click context menu for attacker rows."""

    BINDINGS: ClassVar[List[Binding]] = [
        Binding("escape", "dismiss_menu", "Cancel", show=False),
        Binding("q", "dismiss_menu", "Cancel", show=False),
    ]

    DEFAULT_CSS: str = """
    ContextMenuScreen {
        align: center top;
    }
    #context-menu {
        width: 28;
        height: auto;
        background: $panel;
        border: round $primary;
        padding: 0 1;
    }
    .ctx-title {
        background: $primary;
        color: $background;
        text-style: bold;
        padding: 0 1;
        height: 1;
    }
    .ctx-item {
        height: 1;
        padding: 0 1;
    }
    .ctx-item:hover {
        background: $boost;
    }
    .ctx-item:focus {
        background: $primary;
        color: $background;
    }
    .ctx-divider {
        height: 1;
        color: $border;
    }
    """

    ACTIONS: ClassVar[tuple[ContextMenuAction, ...]] = (
        ContextMenuAction("Block IP", "block"),
        ContextMenuAction("Unblock IP", "unblock"),
        ContextMenuAction("Whois lookup", "whois"),
        ContextMenuAction("View details", "details"),
        ContextMenuAction("Copy IP", "copy"),
    )

    def __init__(self, ip: str, x: int = 0, y: int = 0) -> None:
        super().__init__()
        self.ip = ip
        self.x = x
        self.y = y

    def compose(self) -> ComposeResult:
        with Container(id="context-menu"):
            yield Static(f" {self.ip} ", classes="ctx-title")
            for action in self.ACTIONS:
                yield Static(self._render_item(action), classes="ctx-item", id=f"ctx-{action.action_id}")
            yield Static("\u2500" * 24, classes="ctx-divider")
            yield Static("esc / q to close", classes="ctx-item")

    def _render_item(self, action: ContextMenuAction) -> Text:
        text = Text()
        text.append(" \u25b8 ", style=f"bold {resolve('accent')}")
        text.append(action.label, style=resolve("foreground"))
        return text

    def on_static_click(self, event: Static.Click) -> None:
        widget_id = getattr(event.widget, "id", "") or ""
        for action in self.ACTIONS:
            if widget_id == f"ctx-{action.action_id}":
                self.dismiss({"ip": self.ip, "action": action.action_id})
                return

    def action_dismiss_menu(self) -> None:
        self.dismiss(None)
