from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, DataTable
from rich.text import Text

from ..footer import CompactFooter

STATE_COLORS = {
    "ESTABLISHED": "green",
    "SYN_SENT": "yellow",
    "SYN_RECV": "cyan",
    "NEW": "white",
    "CLOSED": "gray",
    "BLOCKED": "red",
}


class ConnectionsScreen(Screen):
    def compose(self) -> ComposeResult:
        yield DataTable(id="connections-table")
        yield CompactFooter()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Src IP", "Port", "Dst IP", "Port", "Proto", "State", "Bytes", "Duration")
        table.cursor_type = "row"
        self.set_interval(2.0, self.refresh_connections)
        self.refresh_connections()

    def refresh_connections(self) -> None:
        snapshot = self.app.data_provider.get_snapshot()
        table = self.query_one(DataTable)
        table.clear()
        for conn in snapshot["connections"]:
            state = conn.get("state", "")
            state_color = STATE_COLORS.get(state, "white")
            table.add_row(
                conn["src_ip"], str(conn.get("src_port", 0)),
                conn["dst_ip"], str(conn.get("dst_port", 0)),
                conn.get("protocol", ""),
                Text(state, style=f"bold {state_color}"),
                f"{conn.get('bytes', 0)/1024:.1f} KB",
                conn.get("duration", ""),
            )
