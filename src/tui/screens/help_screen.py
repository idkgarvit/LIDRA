"""Help screen showing all keybindings and commands.

Opened with ``?`` or ``F1``, dismissed with ``q``, ``escape`` or
``enter``. Renders keybindings grouped into sections using a
Textual ``DataTable``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import ClassVar, List, Tuple

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Static

from ..style_utils import resolve

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class HelpEntry:
    keys: str
    action: str
    description: str


@dataclass(frozen=True)
class HelpSection:
    title: str
    entries: Tuple[HelpEntry, ...]


SECTIONS: Tuple[HelpSection, ...] = (
    HelpSection(
        title="Navigation",
        entries=(
            HelpEntry("1", "Dashboard", "Open the main dashboard view."),
            HelpEntry("2", "Connections", "Open the live connections table."),
            HelpEntry("3", "Config", "Open engine and bridge configuration."),
            HelpEntry("Tab", "Cycle focus", "Move focus to the next widget."),
            HelpEntry("Shift+Tab", "Cycle focus back", "Move focus to the previous widget."),
            HelpEntry("g", "Top", "Jump to the first row in any table."),
            HelpEntry("G", "Bottom", "Jump to the last row in any table."),
        ),
    ),
    HelpSection(
        title="Actions",
        entries=(
            HelpEntry("b", "Block", "Block the selected attacker (1h default)."),
            HelpEntry("u", "Unblock", "Release the selected IP from the blocklist."),
            HelpEntry("r", "Refresh", "Force-refresh the current snapshot."),
            HelpEntry("w", "Whois", "Run a whois lookup for the selected IP."),
            HelpEntry("c", "Copy IP", "Copy the selected IP to the clipboard."),
            HelpEntry("Enter", "Details", "Open the detail panel for the selected row."),
        ),
    ),
    HelpSection(
        title="Filtering",
        entries=(
            HelpEntry("/", "Search", "Filter rows by IP, country or attack type."),
            HelpEntry("f", "Cycle severity", "Cycle severity filter: all \u2192 critical+ \u2192 high+."),
            HelpEntry("p", "Cycle protocol", "Cycle protocol filter: all \u2192 http \u2192 dns \u2192 tls."),
            HelpEntry("Esc", "Clear filter", "Reset active filters and search."),
        ),
    ),
    HelpSection(
        title="Block Management",
        entries=(
            HelpEntry("B", "Bulk block", "Block every visible row in the current table."),
            HelpEntry("U", "Bulk unblock", "Unblock every IP shown in the table."),
            HelpEntry("x", "Extend block", "Extend the selected block by 24h."),
        ),
    ),
    HelpSection(
        title="Theme",
        entries=(
            HelpEntry("Ctrl+t", "Toggle theme", "Switch between dark and light themes."),
            HelpEntry("d", "Demo data", "Toggle demo data mode (screenshot-friendly)."),
        ),
    ),
    HelpSection(
        title="Quit",
        entries=(
            HelpEntry("?", "Help", "Open this help screen."),
            HelpEntry("F1", "Help", "Open this help screen."),
            HelpEntry("q", "Quit", "Exit LIDRA TUI."),
            HelpEntry("Ctrl+c", "Force quit", "Force exit at any time."),
        ),
    ),
)


class HelpScreen(ModalScreen):
    """Modal screen listing every keybinding and command."""

    BINDINGS: ClassVar[List[Binding]] = [
        Binding("q", "dismiss_help", "Close", show=True),
        Binding("escape", "dismiss_help", "Close", show=False),
        Binding("f1", "dismiss_help", "Close", show=False),
        Binding("question_mark", "dismiss_help", "Close", show=False),
        Binding("enter", "dismiss_help", "Close", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    HelpScreen {
        align: center middle;
    }
    #help-container {
        width: 90%;
        max-width: 110;
        height: 90%;
        max-height: 40;
        background: $panel;
        border: round $primary;
        padding: 1 2;
    }
    #help-title {
        content-align: center middle;
        text-style: bold;
        color: $primary;
        padding: 0 1;
        height: 1;
    }
    #help-subtitle {
        content-align: center middle;
        color: $text-muted;
        padding: 0 1;
        height: 1;
        margin-bottom: 1;
    }
    #help-scroll {
        height: 1fr;
        border: round $border;
    }
    .help-section-title {
        text-style: bold;
        color: $secondary;
        padding: 0 1;
        margin-top: 1;
    }
    DataTable {
        height: auto;
        margin: 0 1 1 1;
    }
    DataTable > .datatable--header {
        text-style: bold;
        color: $accent;
    }
    #help-footer-hint {
        dock: bottom;
        content-align: center middle;
        color: $text-muted;
        padding: 1 0 0 0;
    }
    """

    def compose(self) -> ComposeResult:
        with Container(id="help-container"):
            yield Static("LIDRA TUI \u2014 Keybindings", id="help-title")
            yield Static("Press q, Esc, F1 or Enter to close", id="help-subtitle")
            with VerticalScroll(id="help-scroll"):
                yield from self._compose_sections()
            yield Static("tip: click any row for details \u00b7 Tab to focus", id="help-footer-hint")

    def _compose_sections(self):
        for section in SECTIONS:
            yield Static(section.title, classes="help-section-title")
            table = DataTable(classes="help-table", cursor_type="row", zebra_stripes=True, id=f"help-{section.title.lower().replace(' ', '-')}")
            table.add_columns("Key", "Action", "Description")
            for entry in section.entries:
                key_cell = Text(entry.keys, style=f"bold {resolve('accent')}")
                action_cell = Text(entry.action, style=f"bold {resolve('primary')}")
                desc_cell = Text(entry.description, style=resolve("foreground"))
                table.add_row(key_cell, action_cell, desc_cell)
            yield table

    def on_mount(self) -> None:
        try:
            first_table = self.query(DataTable).first()
            if first_table is not None:
                first_table.focus()
        except Exception:
            logger.debug("No DataTable to focus in help screen")

    def action_dismiss_help(self) -> None:
        self.dismiss()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.dismiss()
