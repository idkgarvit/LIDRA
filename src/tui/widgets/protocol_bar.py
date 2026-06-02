from textual.app import ComposeResult
from textual.widgets import Static, ProgressBar
from textual.containers import Vertical, Horizontal

class ProtocolBar(Static):
    def compose(self) -> ComposeResult:
        yield Static("PROTOCOLS", classes="panel-title")
        with Vertical():
            with Horizontal():
                yield Static("HTTP ", classes="proto-label")
                yield ProgressBar(total=100, id="bar-http", show_percentage=False, show_eta=False)
            with Horizontal():
                yield Static("DNS  ", classes="proto-label")
                yield ProgressBar(total=100, id="bar-dns", show_percentage=False, show_eta=False)
            with Horizontal():
                yield Static("TLS  ", classes="proto-label")
                yield ProgressBar(total=100, id="bar-tls", show_percentage=False, show_eta=False)

    def update_protocols(self, counts: dict):
        # Update bars based on relative counts
        total = sum(counts.values()) or 1
        self.query_one("#bar-http", ProgressBar).progress = (counts.get("http", 0) / total) * 100
        self.query_one("#bar-dns", ProgressBar).progress = (counts.get("dns", 0) / total) * 100
        self.query_one("#bar-tls", ProgressBar).progress = (counts.get("tls", 0) / total) * 100
