from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer
from textual.containers import Container, Horizontal
from ..widgets.packet_gauge import PacketGauge
from ..widgets.attacker_table import AttackerTable
from ..widgets.event_log import EventLog
from ..widgets.protocol_bar import ProtocolBar
from ..widgets.system_stats import SystemStats

class DashboardScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Container(
            PacketGauge(id="packet-flow"),
            Horizontal(
                AttackerTable(id="top-attackers"),
                EventLog(id="main-log"),
                id="main-row"
            ),
            Horizontal(
                ProtocolBar(id="protocols"),
                SystemStats(id="sys-stats"),
                id="bottom-row"
            ),
            id="dashboard-container"
        )
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(1.0, self.refresh_snapshot)
        self.refresh_snapshot()

    def refresh_snapshot(self) -> None:
        snapshot = self.app.data_provider.get_snapshot()
        self.query_one("#top-attackers", AttackerTable).update_data(snapshot["top_attackers"])
        self.query_one("#sys-stats", SystemStats).update_stats(
            snapshot["system"]["cpu_percent"],
            snapshot["system"]["memory_percent"],
            snapshot["system"]["bridge_status"]
        )
        # Mock protocol counts for the bar
        self.query_one("#protocols", ProtocolBar).update_protocols({"http": 40, "dns": 30, "tls": 30})

    def handle_event(self, etype: str, data: dict) -> None:
        if etype == "packet":
            self.query_one("#packet-flow", PacketGauge).update_flow(
                data["pkts_per_sec"], self.app.packet_history
            )
        elif etype == "attack" or etype == "block":
            self.query_one("#main-log", EventLog).add_event(etype, data)
        elif etype == "stats":
            self.query_one("#sys-stats", SystemStats).update_stats(
                data["cpu_usage"], data["memory_usage"], "UP"
            )
