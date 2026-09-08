from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Static

from ..footer import CompactFooter

BRIDGE_STYLE = {"UP": "bold green", "DOWN": "bold red", "UNKNOWN": "gray"}


class ConfigScreen(Screen):
    DEFAULT_CSS = """
    ConfigScreen {
        background: $background;
    }
    #config-title {
        background: $primary;
        color: $background;
        text-style: bold;
        padding: 0 1;
        height: 1;
    }
    #config-body {
        margin: 1 2;
    }
    .cfg-section {
        text-style: bold;
        color: $secondary;
        margin: 0 0;
    }
    .cfg-item {
        height: 1;
        color: $foreground;
        padding: 0 1;
    }
    .cfg-value {
        color: $text-muted;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("CONFIGURATION & STATUS", id="config-title")
        with VerticalScroll(id="config-body"):
            yield Static("Bridge Interfaces: configured in config.yaml", classes="cfg-item", id="cfg-interfaces")
            yield Static("Detection Mode: INLINE", classes="cfg-item", id="cfg-mode")
            yield Static("Bridge Status: checking...", classes="cfg-item", id="cfg-bridge")
            yield Static("Active Blocks: 0", classes="cfg-item", id="cfg-blocks")
            yield Static("Total Packets: 0", classes="cfg-item", id="cfg-packets")
            yield Static("Total Attacks: 0", classes="cfg-item", id="cfg-attacks")
            yield Static("Total Blocked: 0", classes="cfg-item", id="cfg-blocked")
            yield Static("Uptime: —", classes="cfg-item", id="cfg-uptime")
            yield Static("", classes="cfg-item")  # spacer
            yield Static("ATTACK TYPES (last 24h)", classes="cfg-section", id="cfg-by-type-title")
            yield Static("(no attack data yet)", classes="cfg-item", id="cfg-by-type")
        yield CompactFooter()

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

        # Show total blocked count if available
        blocked_count = len(blocks)
        if hasattr(self.app.data_provider, "get_threat_stats"):
            try:
                ts = self.app.data_provider.get_threat_stats()
                blocked_count = int(ts.get("total_blocked", blocked_count))
            except Exception:
                pass
        self.query_one("#cfg-blocked", Static).update(f"Total Blocked: {blocked_count:,}")
        self.query_one("#cfg-uptime", Static).update(
            f"Uptime: {stats.get('uptime', '—')}"
        )

        # Attack type breakdown
        if hasattr(self.app.data_provider, "get_threat_stats"):
            try:
                ts = self.app.data_provider.get_threat_stats()
                by_type = ts.get("by_type", {})
                if by_type:
                    sorted_types = sorted(by_type.items(), key=lambda x: -x[1])[:10]
                    lines = []
                    for atype, count in sorted_types:
                        lines.append(f"  {atype}: {count}")
                    self.query_one("#cfg-by-type", Static).update("\n".join(lines))
                else:
                    self.query_one("#cfg-by-type", Static).update("(no attack data yet)")
            except Exception:
                self.query_one("#cfg-by-type", Static).update("(error loading attack types)")
