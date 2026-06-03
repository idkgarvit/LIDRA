from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, Static
from textual.containers import Vertical

BRIDGE_STYLE = {"UP": "bold green", "DOWN": "bold red", "UNKNOWN": "gray"}


class ConfigScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Configuration & Status", id="config-title")
        with Vertical(id="config-body"):
            yield Static("Bridge Interfaces: configured in config.yaml", classes="config-item", id="cfg-interfaces")
            yield Static("Detection Mode: INLINE", classes="config-item", id="cfg-mode")
            yield Static("Bridge Status: checking...", classes="config-item", id="cfg-bridge")
            yield Static("Active Blocks: 0", classes="config-item", id="cfg-blocks")
            yield Static("Total Packets: 0", classes="config-item", id="cfg-packets")
            yield Static("Total Attacks: 0", classes="config-item", id="cfg-attacks")
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(3.0, self.refresh_status)
        self.refresh_status()

    def refresh_status(self) -> None:
        snapshot = self.app.data_provider.get_snapshot()
        system = snapshot.get("system", {})
        stats = snapshot.get("stats", {})
        blocks = snapshot.get("blocks", [])

        bridge_status = system.get("bridge_status", "UNKNOWN")
        bridge_style = BRIDGE_STYLE.get(bridge_status, "gray")
        self.query_one("#cfg-bridge", Static).update(
            f"Bridge Status: [{bridge_style}]{bridge_status}[/]"
        )
        self.query_one("#cfg-blocks", Static).update(
            f"Active Blocks: {len(blocks)}"
        )
        self.query_one("#cfg-packets", Static).update(
            f"Total Packets: {stats.get('total_packets', 0):,}"
        )
        self.query_one("#cfg-attacks", Static).update(
            f"Total Attacks: {stats.get('total_attacks', 0):,}"
        )
