from textual.app import ComposeResult
from textual.widgets import Static, Sparkline
from textual.containers import Vertical, Horizontal

class PacketGauge(Static):
    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("PACKET FLOW (pkts/sec)", classes="label")
            with Horizontal():
                yield Sparkline([0] * 20, id="flow-sparkline")
                yield Static("0 pkts/s", id="flow-value")

    def update_flow(self, value: int, history: list[int]):
        self.query_one("#flow-sparkline", Sparkline).data = history
        self.query_one("#flow-value", Static).update(f"{value} pkts/s")
