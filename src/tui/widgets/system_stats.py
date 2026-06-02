from textual.app import ComposeResult
from textual.widgets import Static
from textual.containers import Vertical

class SystemStats(Static):
    def compose(self) -> ComposeResult:
        yield Static("SYSTEM", classes="panel-title")
        with Vertical():
            yield Static("CPU: 0.0%", id="stat-cpu")
            yield Static("MEM: 0.0%", id="stat-mem")
            yield Static("BRIDGE: UNKNOWN", id="stat-bridge")

    def update_stats(self, cpu: float, mem: float, bridge: str):
        self.query_one("#stat-cpu").update(f"CPU: {cpu:.1f}%")
        self.query_one("#stat-mem").update(f"MEM: {mem:.1f}%")
        self.query_one("#stat-bridge").update(f"BRIDGE: {bridge}")
