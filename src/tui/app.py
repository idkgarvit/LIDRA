"""Top-level Textual App for the LIDRA TUI."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Footer

from .data_provider import TUIDataProvider
from .footer import CompactFooter
from .screens.config import ConfigScreen
from .screens.connections import ConnectionsScreen
from .screens.dashboard import DashboardScreen
from .screens.help_screen import HelpScreen
from .themes import apply_theme, toggle_theme
from .widgets.status_bar import bind_tokens_provider, current_tokens_for_health

logger = logging.getLogger(__name__)


class LidraApp(App):
    """Polished Textual application for the LIDRA IDS dashboard."""

    CSS: str = """
    Screen {
        background: $background;
    }
    .panel-title {
        background: $primary;
        color: $background;
        text-style: bold;
        padding: 0 1;
        height: 1;
    }
    .dashboard-cell {
        padding: 0 1;
    }
    DataTable {
        background: $panel;
    }
    DataTable > .datatable--header {
        background: $boost;
        color: $primary;
        text-style: bold;
    }
    DataTable > .datatable--cursor {
        background: $primary;
        color: $background;
    }
    DataTable > .datatable--hover {
        background: $boost;
    }
    DataTable > .datatable--highlight {
        background: $boost;
    }
    .clickable {
        background: $panel;
    }
    .clickable:hover {
        background: $boost;
    }
    .clickable:focus {
        background: $boost;
    }
    LoadingIndicator {
        background: $panel;
        color: $primary;
    }
    """

    BINDINGS = [
        Binding("1", "switch_screen('dashboard')", "Dashboard", show=True),
        Binding("2", "switch_screen('connections')", "Connections", show=True),
        Binding("3", "switch_screen('config')", "Config", show=True),
        Binding("question_mark", "show_help", "Help", show=True),
        Binding("f1", "show_help", "Help", show=False),
        Binding("ctrl+t", "toggle_theme", "Theme", show=False),
        Binding("b", "block_selected", "Block", show=True),
        Binding("u", "unblock_selected", "Unblock", show=False),
        Binding("slash", "search", "Search", show=False),
        Binding("ctrl+l", "clear_filters", "Clear", show=False),
        Binding("d", "toggle_demo", "Demo", show=False),
        Binding("q", "quit", "Quit", show=True),
        Binding("escape", "app.pop_screen", "Back", show=False),
    ]

    def __init__(self, data_provider: Optional[TUIDataProvider] = None, demo: bool = False) -> None:
        super().__init__()
        self.data_provider = data_provider or TUIDataProvider()
        self.packet_history = [0] * 20
        self.demo = demo
        self._theme_active = "dark"

    def on_mount(self) -> None:
        bind_tokens_provider(self._live_tokens)
        apply_theme(self, self._theme_active)
        self.install_screen(DashboardScreen(), name="dashboard")
        self.install_screen(ConnectionsScreen(), name="connections")
        self.install_screen(ConfigScreen(), name="config")
        self.install_screen(HelpScreen(), name="help")
        self.push_screen("dashboard")
        self.run_worker(self.listen_to_events())

    def _live_tokens(self):
        from .themes import current_tokens
        try:
            return current_tokens(self)
        except Exception:
            return current_tokens_for_health()

    async def listen_to_events(self) -> None:
        try:
            async for event in self.data_provider.subscribe():
                etype = event.get("type")
                data = event.get("data", {})
                if etype == "packet":
                    pps = data.get("pkts_per_sec", 0)
                    self.packet_history.append(pps)
                    self.packet_history = self.packet_history[-120:]
                if self.screen is not None and getattr(self.screen, "name", "") == "dashboard":
                    self.screen.handle_event(etype, data)
        except Exception as exc:
            logger.warning("event loop error: %s", exc)

    def action_show_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_toggle_theme(self) -> None:
        new = toggle_theme(self)
        self._theme_active = new
        self.notify(f"Theme: {new}", title="LIDRA")

    def action_block_selected(self) -> None:
        screen = self.screen
        if screen is not None and hasattr(screen, "block_selected_attacker"):
            screen.block_selected_attacker()

    def action_unblock_selected(self) -> None:
        screen = self.screen
        if screen is not None and hasattr(screen, "unblock_selected_attacker"):
            screen.unblock_selected_attacker()

    def action_search(self) -> None:
        screen = self.screen
        if screen is not None and hasattr(screen, "focus_search"):
            screen.focus_search()

    def action_clear_filters(self) -> None:
        screen = self.screen
        if screen is not None and hasattr(screen, "clear_filters"):
            screen.clear_filters()

    def action_toggle_demo(self) -> None:
        self.demo = not self.demo
        self.notify(f"Demo mode: {'on' if self.demo else 'off'}", title="LIDRA")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(prog="lidra tui", description="LIDRA Textual TUI")
    parser.add_argument("--demo", action="store_true", help="Run with synthetic demo data (no DB needed)")
    parser.add_argument("--standalone", action="store_true", help="Run as agent subprocess (reads LIDRA_TUI_SOCKET)")
    args = parser.parse_args()

    provider = None
    if args.demo:
        from .demo_mode import generate_demo_data

        class DemoProvider:
            def __init__(self) -> None:
                self._snapshot = generate_demo_data()
                self._attackers = list(self._snapshot["top_attackers"])
                self._seq = 0

            def get_snapshot(self) -> dict:
                import random
                snap = dict(self._snapshot)
                snap["top_attackers"] = self._attackers
                snap["connections"] = []
                snap["system"] = {
                    "cpu_percent": random.uniform(8, 35),
                    "memory_percent": random.uniform(25, 55),
                    "bridge_status": "UP",
                }
                snap["stats"] = {
                    "total_packets": int(snap["stats"].get("total_packets", 0)) + random.randint(0, 5000),
                    "total_attacks": int(snap["stats"].get("total_attacks", 0)) + random.randint(0, 5),
                    "uptime": "00:00:00",
                }
                snap["protocols"] = {
                    "http": random.randint(30, 55),
                    "dns": random.randint(15, 35),
                    "tls": random.randint(15, 35),
                    "ssh": random.randint(2, 10),
                    "smtp": random.randint(1, 8),
                }
                return snap

            def subscribe(self):
                return self._events()

            async def _events(self):
                import random
                while True:
                    await asyncio.sleep(0.3)
                    self._seq += 1
                    yield {
                        "type": "packet",
                        "data": {"pkts_per_sec": random.randint(800, 1500)},
                    }

            def on_block(self, ip: str) -> None:
                pass

            def on_unblock(self, ip: str) -> None:
                pass

        provider = DemoProvider()
    elif args.standalone:
        from .data_provider import TUIDataProvider
        provider = TUIDataProvider()

    app = LidraApp(data_provider=provider, demo=bool(args.demo))
    app.title = "LIDRA " + ("[Demo]" if args.demo else "[IPC]" if args.standalone else "")
    app.run()


if __name__ == "__main__":
    import asyncio
    main()
