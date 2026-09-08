"""Top-level Textual App for the LIDRA TUI."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

from textual.app import App
from textual.binding import Binding

from .data_provider import TUIDataProvider
from .screens.config import ConfigScreen
from .screens.dashboard import DashboardScreen
from .screens.help_screen import HelpScreen
from .themes import apply_theme, toggle_theme
from .widgets.status_bar import bind_tokens_provider, current_tokens_for_health

logger = logging.getLogger(__name__)


class LocalProvider:
    """In-process LIDRA engine provider for local/laptop mode.

    Runs LIDRAPersonal in a daemon thread inside the TUI process,
    bypassing the IPC server + subprocess chain entirely.
    Events flow directly via asyncio.Queue (thread-safe).
    """

    def __init__(self) -> None:
        if os.geteuid() != 0:
            print("LIDRA requires root privileges for packet capture. Re-run with sudo.")
            sys.exit(1)

        src = str(Path(__file__).resolve().parent.parent)
        if src not in sys.path:
            sys.path.insert(0, src)

        from utils.config_loader import load_config

        config = load_config()
        config.setdefault("tui", {})["embedded"] = True

        from core.personal_agent import LIDRAPersonal

        self.agent = LIDRAPersonal(config)
        self._data_provider = self.agent.tui_data_provider
        self._error: Optional[str] = None

        self._thread = threading.Thread(target=self._run_agent, daemon=True)
        self._thread.start()

        for _ in range(50):
            if self._data_provider and self.agent.inline_engine:
                break
            time.sleep(0.1)

    def _run_agent(self) -> None:
        try:
            self.agent.run()
        except Exception as exc:
            self._error = str(exc)
            logger.error("Agent thread failed: %s", exc)

    def _healthy(self) -> bool:
        return self._thread.is_alive() and self._error is None

    def stop(self) -> None:
        self.agent.stop()

    def get_snapshot(self) -> dict:
        if not self._healthy():
            return {
                "stats": {"total_packets": 0, "total_attacks": 0, "uptime": "00:00:00"},
                "top_attackers": [],
                "connections": [],
                "blocks": [],
                "system": {"cpu_percent": 0.0, "memory_percent": 0.0, "bridge_status": "DEGRADED",
                           "interface": os.environ.get("LIDRA_INTERFACE", "eth0"),
                           "environment": "local", "mode": "degraded"},
                "mitre": {},
                "protocols": {},
                "engine_available": False,
                "engine_error": self._error or "Engine thread terminated unexpectedly",
            }
        snap = self._data_provider.get_snapshot()
        snap["engine_available"] = True
        snap["system"]["bridge_status"] = "UP"
        snap["system"].setdefault("environment", "local")
        return snap

    def subscribe(self):  # noqa ANN201
        gen = self._data_provider.subscribe()
        return self._health_checked_events(gen)

    async def _health_checked_events(self, gen):
        async for event in gen:
            if self._healthy():
                event["engine_available"] = True
                yield event
            else:
                yield {"type": "health", "data": {"engine_available": False, "error": self._error}}

    def on_block(self, ip: str) -> None:
        if self._healthy():
            self.agent.firewall.block_ip(ip, ttl_seconds=3600)
            self._data_provider.block_ip(ip, "manual")

    def on_unblock(self, ip: str) -> None:
        if self._healthy():
            self.agent.firewall.unblock_ip(ip)
            self._data_provider.unblock_ip(ip)


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
        Binding("3", "switch_screen('config')", "Config", show=True),
        Binding("question_mark", "show_help", "Help", show=True),
        Binding("f1", "show_help", "Help", show=False),
        Binding("ctrl+t", "toggle_theme", "Theme", show=False),
        Binding("b", "block_selected", "Block", show=True),
        Binding("u", "unblock_selected", "Unblock", show=False),
        Binding("r", "refresh_screen", "Refresh", show=False),
        Binding("w", "whois_selected", "Whois", show=False),
        Binding("c", "copy_ip", "Copy IP", show=False),
        Binding("f", "cycle_severity_filter", "Filter", show=False),
        Binding("B", "bulk_block", "Bulk Blk", show=False),
        Binding("U", "bulk_unblock", "Bulk Unblk", show=False),
        Binding("x", "extend_block", "Extend", show=False),
        Binding("slash", "search", "Search", show=False),
        Binding("ctrl+l", "clear_filters", "Clear", show=False),
        Binding("d", "toggle_demo", "Demo", show=False),
        Binding("q", "quit", "Quit", show=True),
        Binding("escape", "app.pop_screen", "Back", show=False),
    ]

    def __init__(self, data_provider: Any = None, demo: bool = False) -> None:
        super().__init__()
        self.data_provider = data_provider or TUIDataProvider()
        self.packet_history = [0] * 20
        self.demo = demo
        self._theme_active = "dark"

    def on_mount(self) -> None:
        bind_tokens_provider(self._live_tokens)
        apply_theme(self, self._theme_active)
        self.install_screen(DashboardScreen(), name="dashboard")
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

    def on_unmount(self) -> None:
        """Shut down the engine provider cleanly when the TUI exits."""
        stop = getattr(self.data_provider, "stop", None)
        if callable(stop):
            stop()

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

    def action_refresh_screen(self) -> None:
        """Force-refresh the current screen (r key)."""
        screen = self.screen
        if screen is not None and hasattr(screen, "refresh_snapshot"):
            screen.refresh_snapshot()
            self.notify("Snapshot refreshed", title="LIDRA", timeout=1.5)

    def action_whois_selected(self) -> None:
        """Run a whois lookup on the selected attacker (w key)."""
        screen = self.screen
        if screen is not None and hasattr(screen, "whois_selected_attacker"):
            screen.whois_selected_attacker()

    def action_copy_ip(self) -> None:
        """Copy the selected IP to the clipboard (c key)."""
        screen = self.screen
        if screen is not None and hasattr(screen, "copy_selected_ip"):
            screen.copy_selected_ip()

    def action_cycle_severity_filter(self) -> None:
        """Cycle severity filter on the attacker table (f key)."""
        screen = self.screen
        if screen is not None and hasattr(screen, "cycle_severity_filter"):
            screen.cycle_severity_filter()

    def action_bulk_block(self) -> None:
        """Block every visible attacker in the table (B key)."""
        screen = self.screen
        if screen is not None and hasattr(screen, "bulk_block"):
            screen.bulk_block()

    def action_bulk_unblock(self) -> None:
        """Unblock every visible attacker in the table (U key)."""
        screen = self.screen
        if screen is not None and hasattr(screen, "bulk_unblock"):
            screen.bulk_unblock()

    def action_extend_block(self) -> None:
        """Extend the block for the selected IP by 24h (x key)."""
        screen = self.screen
        if screen is not None and hasattr(screen, "extend_block"):
            screen.extend_block()


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(prog="lidra tui", description="LIDRA Textual TUI")
    parser.add_argument("--local", action="store_true", help="Run in local/laptop mode (single process, in-process agent)")
    parser.add_argument("--demo", action="store_true", help="Run with synthetic demo data (no DB needed)")
    parser.add_argument("--standalone", action="store_true", help="Run as agent subprocess (reads LIDRA_TUI_SOCKET)")
    args = parser.parse_args()

    provider = None
    if args.local:
        provider = LocalProvider()
    elif args.demo:
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
                    "interface": "demo",
                    "environment": "demo",
                    "mode": "demo",
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
    if args.local:
        app.title = "LIDRA [Local]"
    elif args.demo:
        app.title = "LIDRA [Demo]"
    elif args.standalone:
        app.title = "LIDRA [IPC]"
    else:
        app.title = "LIDRA"
    app.run()


if __name__ == "__main__":
    main()
