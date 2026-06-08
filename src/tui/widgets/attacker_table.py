"""Attacker table widget.

Renders a Textual ``DataTable`` with clickable rows. A right-click
posts a ``ContextMenuRequested`` message so the dashboard can show a
floating menu with Block / Whois / View Details / Copy IP entries.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import ClassVar, Dict, List, Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.message import Message
from textual.widgets import DataTable, Static

from ..style_utils import resolve
from .severity_badge import severity_cell

logger = logging.getLogger(__name__)


@dataclass
class AttackerRow:
    ip: str
    attacks: int
    severity: str
    country: str

    @classmethod
    def from_dict(cls, data: Dict) -> "AttackerRow":
        return cls(
            ip=str(data.get("ip", "")),
            attacks=int(data.get("attacks", 0)),
            severity=str(data.get("severity", "info")),
            country=str(data.get("country", "??")),
        )


class AttackerTable(Static):
    """Top attackers table with click and right-click support."""

    DEFAULT_CSS: str = """
    AttackerTable {
        height: 1fr;
    }
    AttackerTable > Vertical {
        height: 1fr;
    }
    .attacker-title {
        background: $primary;
        color: $background;
        text-style: bold;
        padding: 0 1;
        height: 1;
    }
    DataTable {
        height: 1fr;
    }
    DataTable > .datatable--cursor {
        background: $primary;
        color: $background;
    }
    DataTable > .datatable--hover {
        background: $boost;
    }
    """

    BINDINGS: ClassVar[List] = []

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("TOP ATTACKERS", classes="attacker-title")
            yield DataTable(id="attacker-data", cursor_type="row", zebra_stripes=True)

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("IP", "Attacks", "Severity", "Country")
        self._row_data: Dict[str, AttackerRow] = {}

    def update_data(self, attackers: List[Dict]) -> None:
        table = self.query_one(DataTable)
        table.clear()
        self._row_data = {}
        for raw in attackers:
            row = AttackerRow.from_dict(raw)
            key = table.add_row(
                Text(row.ip, style=f"bold {resolve('foreground')}"),
                Text(f"{row.attacks:,}", style=resolve("foreground")),
                severity_cell(row.severity),
                Text(row.country, style=resolve("muted")),
            )
            try:
                self._row_data[str(key.value)] = row
            except Exception:
                logger.debug("row key not string-coercible")

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        row = self._lookup_row(event.row_key)
        if row is not None:
            self.post_message(self.RowFocused(row))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row = self._lookup_row(event.row_key)
        if row is not None:
            self.post_message(self.RowActivated(row))

    def _lookup_row(self, row_key) -> Optional[AttackerRow]:
        try:
            key = str(row_key.value)
        except Exception:
            return None
        return self._row_data.get(key)

    class RowFocused(Message):
        def __init__(self, row: AttackerRow) -> None:
            super().__init__()
            self.row = row

    class RowActivated(Message):
        def __init__(self, row: AttackerRow) -> None:
            super().__init__()
            self.row = row

    class ContextMenuRequested(Message):
        def __init__(self, row: AttackerRow, x: int, y: int) -> None:
            super().__init__()
            self.row = row
            self.x = x
            self.y = y
