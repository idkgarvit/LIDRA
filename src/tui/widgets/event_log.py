from textual.app import ComposeResult
from textual.widgets import Static, RichLog
from rich.text import Text

class EventLog(Static):
    def compose(self) -> ComposeResult:
        yield Static("LIVE EVENTS", classes="panel-title")
        yield RichLog(id="log-view", max_lines=100)

    def add_event(self, event_type: str, data: dict):
        log = self.query_one(RichLog)
        severity = data.get("severity", "info")
        color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green", "info": "white"}.get(severity, "white")
        
        msg = Text.assemble(
            (f"[{data.get('timestamp', '')}] ", "cyan"),
            (f"{event_type.upper()}: ", f"bold {color}"),
            f"{data.get('ip', 'N/A')} - {data.get('type', data.get('reason', 'event'))}"
        )
        log.write(msg)
