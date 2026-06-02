from textual.app import ComposeResult
from textual.widgets import Static, DataTable

class AttackerTable(Static):
    def compose(self) -> ComposeResult:
        yield Static("TOP ATTACKERS", classes="panel-title")
        yield DataTable(id="attacker-data")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("IP", "Attacks", "Severity", "Country")
        table.cursor_type = "row"

    def update_data(self, attackers: list[dict]):
        table = self.query_one(DataTable)
        table.clear()
        for a in attackers:
            table.add_row(a["ip"], str(a["attacks"]), a["severity"], a["country"])
