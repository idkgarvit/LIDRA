"""Polished dashboard screen.

Layout (top to bottom):

  +----------------------------------------------------------+
  | StatusBar  LIDRA v3 | local | eth0 | dry-run | 1.2k pps |
  +----------------------------------------------------------+
  | ASCII logo  (left)  |  System stats  (right)             |
  |                     |  CPU / MEM / BRIDGE                |
  +----------------------------------------------------------+
  |  AttackerTable (60%)  |  EventLog (40%)                  |
  +----------------------------------------------------------+
  |  DetailPanel (selected IP drill-down)                    |
  +----------------------------------------------------------+
  |  PacketGauge LIVE TRAFFIC (sparkline + protocols + totals)|
  +----------------------------------------------------------+
  | Command bar  [block <ip>] [whois <ip>] [tail N]          |
  +----------------------------------------------------------+
  | Compact footer  [1] [3] [b] [?] [q]                      |
  +----------------------------------------------------------+

Interactive features:
  - Arrow keys / click to select attacker rows
  - b / u → block / unblock the selected IP
  - w → whois lookup on the selected IP
  - c → copy the selected IP to clipboard
  - f → cycle severity filter: all → critical+ → high+
  - / → fuzzy-search the attacker table by IP/country/type
  - Ctrl+l → clear all filters
  - r → force-refresh the snapshot
  - Right-click on a row → context menu (block / whois / copy)
"""

from __future__ import annotations

import logging
from typing import Optional

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Rule

from ..footer import CompactFooter
from ..widgets.ascii_logo import AsciiLogo
from ..widgets.attacker_table import AttackerTable
from ..widgets.command_bar import CommandBar
from ..widgets.context_menu import ContextMenuScreen
from ..widgets.detail_panel import DetailPanel
from ..widgets.event_log import EventLog
from ..widgets.packet_gauge import PacketGauge
from ..widgets.status_bar import StatusBar, StatusSnapshot
from ..widgets.system_stats import SystemStats

logger = logging.getLogger(__name__)


class DashboardScreen(Screen):
    """The polished main dashboard."""

    DEFAULT_CSS: str = """
    DashboardScreen {
        background: $background;
    }
    #dashboard-root {
        height: 1fr;
        padding: 0 1;
    }
    #top-row {
        height: 9;
        margin: 0 0 1 0;
    }
    #logo-cell {
        width: 60%;
        border: round $primary;
        padding: 0 1;
        content-align: center middle;
    }
    #stats-cell {
        width: 40%;
        border: round $secondary;
        padding: 0 1;
    }
    #mid-rule {
        margin: 0 0;
    }
    #mid-row {
        height: 1fr;
        min-height: 8;
        margin: 0 0 1 0;
    }
    #attacker-cell {
        width: 60%;
        border: round $primary;
    }
    #event-cell {
        width: 40%;
        border: round $secondary;
    }
    #bottom-rule {
        margin: 0 0;
    }
    #detail-panel {
        margin: 0 0 1 0;
        max-height: 8;
    }
    #bottom-row {
        height: auto;
        min-height: 7;
        max-height: 9;
        margin: 0 0 1 0;
    }
    #traffic-cell {
        width: 100%;
        border: round $secondary;
    }
    .panel-title {
        background: $primary;
        color: $background;
        text-style: bold;
        padding: 0 1;
        height: 1;
    }
    .filter-badge {
        background: $warning;
        color: $background;
        text-style: bold;
        padding: 0 1;
        margin: 0 0 0 1;
    }
    .filter-badge-none {
        background: $boost;
        color: $text-muted;
        padding: 0 1;
    }
    """

    snapshot: reactive[StatusSnapshot] = reactive(StatusSnapshot, init=False)

    SEVERITY_FILTERS = ("all", "critical+", "high+")

    def __init__(self) -> None:
        super().__init__()
        self._severity_filter: int = 0
        self._search_term: str = ""
        self._selected_ip: str = ""
        self._all_attackers: list[dict] = []
        self._filtered_attackers: list[dict] = []
        self._whois_cache: dict[str, str] = {}

    def compose(self) -> ComposeResult:
        yield StatusBar(id="status-bar")
        with Container(id="dashboard-root"):
            with Horizontal(id="top-row"):
                # ponytail: full 13-line logo clipped in the 9-row top
                # strip — compact single-line variant, width-proof.
                yield AsciiLogo(id="logo-cell", classes="dashboard-cell", compact=True)
                yield SystemStats(id="stats-cell", classes="dashboard-cell")
            yield Rule(orientation="horizontal", line_style="heavy", id="mid-rule")
            with Horizontal(id="mid-row"):
                yield AttackerTable(id="attacker-cell", classes="dashboard-cell")
                yield EventLog(id="event-cell", classes="dashboard-cell")
            yield DetailPanel(id="detail-panel")
            yield Rule(orientation="horizontal", line_style="heavy", id="bottom-rule")
            with Horizontal(id="bottom-row"):
                yield PacketGauge(id="traffic-cell", classes="dashboard-cell")
        yield CommandBar(data_provider=self.app.data_provider if hasattr(self.app, "data_provider") else None, id="cmd-bar")
        yield CompactFooter()

    def on_mount(self) -> None:
        self.set_interval(1.0, self.refresh_status_bar)
        self.set_interval(1.0, self.refresh_snapshot)
        self.refresh_status_bar()
        self.refresh_snapshot()

    def refresh_status_bar(self) -> None:
        snapshot = self._read_snapshot()
        try:
            self.query_one("#status-bar", StatusBar).update_snapshot(snapshot)
        except Exception:
            logger.debug("Status bar not yet mounted")

    def _read_snapshot(self) -> StatusSnapshot:
        snap = StatusSnapshot()
        try:
            data_snapshot = self.app.data_provider.get_snapshot()
        except Exception:
            logger.debug("data_provider.get_snapshot failed; using defaults")
            return snap
        system = data_snapshot.get("system", {}) if isinstance(data_snapshot, dict) else {}
        attackers = data_snapshot.get("top_attackers", []) if isinstance(data_snapshot, dict) else []
        blocks = data_snapshot.get("blocks", []) if isinstance(data_snapshot, dict) else []
        history = getattr(self.app, "packet_history", []) or []
        snap.attack_count = len(attackers)
        snap.blocked_count = len(blocks)
        snap.packets_per_sec = history[-1] if history else 0
        snap.interface = system.get("interface") or "eth0"
        snap.environment = system.get("environment") or "local"
        snap.mode = system.get("mode") or "dry-run"
        snap.timestamp = system.get("timestamp") or snap.timestamp
        if hasattr(self.app.data_provider, "get_kpis"):
            try:
                kpis = self.app.data_provider.get_kpis()
                snap.critical_count = int(kpis.get("critical", 0))
                snap.top_ip = str(kpis.get("top_ip", "—") or "—")
            except Exception:
                logger.debug("get_kpis failed")
        if not snap.timestamp:
            from datetime import datetime
            snap.timestamp = datetime.now().strftime("%H:%M:%S")
        return snap

    def refresh_snapshot(self) -> None:
        snapshot = self.app.data_provider.get_snapshot()
        self._all_attackers = snapshot.get("top_attackers", []) or []
        self._apply_filters()

        if hasattr(self.app.data_provider, "get_system_stats"):
            sys_stats = self.app.data_provider.get_system_stats()
            self.query_one("#stats-cell", SystemStats).update_stats(
                sys_stats.get("cpu_percent", 0.0),
                sys_stats.get("memory_percent", 0.0),
                snapshot.get("system", {}).get("bridge_status", "UNKNOWN"),
            )
        else:
            self.query_one("#stats-cell", SystemStats).update_stats(
                snapshot.get("system", {}).get("cpu_percent", 0.0),
                snapshot.get("system", {}).get("memory_percent", 0.0),
                snapshot.get("system", {}).get("bridge_status", "UNKNOWN"),
            )

        traffic = self.query_one("#traffic-cell", PacketGauge)
        try:
            real_protocols = self.app.data_provider.get_protocol_breakdown()
        except Exception:
            real_protocols = {}
        traffic.update_protocols(real_protocols or snapshot.get("protocols") or {})

        # SystemStats has UPTIME + DEMO rows that otherwise stay frozen.
        try:
            stats_cell = self.query_one("#stats-cell", SystemStats)
            stats_cell.update_uptime(snapshot.get("stats", {}).get("uptime", ""))
            stats_cell.update_demo(bool(getattr(self.app, "demo", False)))
        except Exception:
            logger.debug("stats-cell uptime/demo update skipped")

    # ── Filtering ─────────────────────────────────────────────────────────

    def _apply_filters(self) -> None:
        """Apply all active filters (severity + search) to the attacker list."""
        attackers = list(self._all_attackers)

        # Severity filter
        sev = self.SEVERITY_FILTERS[self._severity_filter]
        if sev == "critical+":
            attackers = [a for a in attackers if (a.get("severity") or "").lower() in ("critical",)]
        elif sev == "high+":
            attackers = [a for a in attackers if (a.get("severity") or "").lower() in ("critical", "high")]

        # Text search
        if self._search_term:
            term = self._search_term.lower()
            attackers = [
                a for a in attackers
                if term in (a.get("ip", "") or "").lower()
                or term in (a.get("country", "") or "").lower()
                or term in (a.get("severity", "") or "").lower()
            ]

        self._filtered_attackers = attackers
        self.query_one("#attacker-cell", AttackerTable).update_data(attackers)

        # Show active filter badge via DetailPanel flash
        filter_parts = []
        if sev != "all":
            filter_parts.append(f"sev:{sev}")
        if self._search_term:
            filter_parts.append(f'search:"{self._search_term}"')
        if filter_parts:
            self.app.notify("Filter: " + " | ".join(filter_parts), title="LIDRA", timeout=2)

    def focus_search(self) -> None:
        """Open search prompt — user types via command bar."""
        self.app.notify(
            "Search: type in the command bar: filter <term>  (Ctrl+l to clear)",
            title="LIDRA", timeout=4,
        )
        try:
            self.query_one("#cmd-bar", CommandBar)._focus_input()
        except Exception:
            pass

    def clear_filters(self) -> None:
        self._severity_filter = 0
        self._search_term = ""
        self._apply_filters()
        self.app.notify("Filters cleared", title="LIDRA", timeout=2)

    def cycle_severity_filter(self) -> None:
        self._severity_filter = (self._severity_filter + 1) % len(self.SEVERITY_FILTERS)
        label = self.SEVERITY_FILTERS[self._severity_filter]
        self._apply_filters()
        self.app.notify(f"Severity filter: {label}", title="LIDRA", timeout=2)

    def whois_selected_attacker(self) -> None:
        """Run a whois lookup on the highlighted attacker."""
        ip = self._get_selected_ip()
        if not ip:
            self.app.notify("No attacker selected", title="LIDRA", timeout=2)
            return
        self._whois_for_ip(ip)

    def copy_selected_ip(self) -> None:
        """Copy the selected IP to clipboard."""
        ip = self._get_selected_ip()
        if not ip:
            self.app.notify("No attacker selected", title="LIDRA", timeout=2)
            return
        self._copy_ip(ip)

    def bulk_block(self) -> None:
        """Block every attacker currently visible in the table."""
        count = 0
        for att in self._filtered_attackers:
            ip = att.get("ip", "")
            if ip:
                self._action_block(ip)
                count += 1
        self.app.notify(f"Blocked {count} attackers", title="LIDRA", timeout=3)

    def bulk_unblock(self) -> None:
        """Unblock every attacker currently visible in the table."""
        count = 0
        for att in self._filtered_attackers:
            ip = att.get("ip", "")
            if ip:
                self._action_unblock(ip)
                count += 1
        self.app.notify(f"Unblocked {count} attackers", title="LIDRA", timeout=3)

    def extend_block(self) -> None:
        """Extend block for the selected IP by 24h."""
        ip = self._get_selected_ip()
        if not ip:
            self.app.notify("No attacker selected", title="LIDRA", timeout=2)
            return
        try:
            self.app.data_provider.block_ip(ip, reason="extended_24h")
            self.app.notify(f"Extended block for {ip} (+24h)", title="LIDRA", timeout=3)
        except Exception:
            self.app.notify(f"Failed to extend block for {ip}", title="LIDRA", timeout=3)

    # ── Event handling ────────────────────────────────────────────────────

    def handle_event(self, etype: str, data: dict) -> None:
        if etype == "packet":
            try:
                self.query_one("#traffic-cell", PacketGauge).update_flow(
                    data.get("pkts_per_sec", 0), self.app.packet_history
                )
            except Exception:
                logger.debug("traffic-cell update skipped")
        elif etype in ("attack", "block"):
            try:
                self.query_one("#event-cell", EventLog).add_event(etype, data)
            except Exception:
                logger.debug("event-cell update skipped")
            if etype == "attack" and (data.get("severity") or "").lower() == "critical":
                try:
                    self.query_one("#status-bar", StatusBar).flash_critical(duration=2.5)
                except Exception:
                    logger.debug("StatusBar flash skipped")
        elif etype == "stats":
            try:
                self.query_one("#stats-cell", SystemStats).update_stats(
                    data.get("cpu_usage", 0.0), data.get("memory_usage", 0.0), "UP"
                )
            except Exception:
                logger.debug("stats-cell update skipped")
        elif etype == "snapshot":
            self.refresh_snapshot()

    def on_attacker_table_row_activated(self, event: AttackerTable.RowActivated) -> None:
        """Enter / click on a row — show context menu with actions."""
        self._selected_ip = event.row.ip
        self._show_detail_for_ip(event.row.ip)
        self._show_context_menu(event.row.ip)

    def _show_context_menu(self, ip: str) -> None:
        """Push the context menu for the given IP."""
        self.push_screen(
            ContextMenuScreen(ip=ip, x=0, y=0),
            self._on_context_menu_result,
        )

    def on_attacker_table_row_focused(self, event: AttackerTable.RowFocused) -> None:
        self._selected_ip = event.row.ip
        self._show_detail_for_ip(event.row.ip)

    def _on_context_menu_result(self, result) -> None:
        if result is None:
            return
        action = result.get("action", "")
        ip = result.get("ip", "")
        if action == "block":
            self._action_block(ip)
        elif action == "unblock":
            self._action_unblock(ip)
        elif action == "whois":
            self._whois_for_ip(ip)
        elif action == "details":
            self._show_detail_for_ip(ip)
        elif action == "copy":
            self._copy_ip(ip)

    def _show_detail_for_ip(self, ip: str) -> None:
        try:
            panel = self.query_one("#detail-panel", DetailPanel)
        except Exception:
            return
        detail: Optional[dict] = None
        if hasattr(self.app.data_provider, "get_attacker_detail"):
            try:
                detail = self.app.data_provider.get_attacker_detail(ip)
            except Exception as e:
                logger.debug("get_attacker_detail failed: %s", e)
        panel.show_attacker(ip, detail)

    # ── Block/Unblock actions ─────────────────────────────────────────────

    def block_selected_attacker(self) -> None:
        self._block_action_for_highlighted()

    def unblock_selected_attacker(self) -> None:
        self._unblock_action_for_highlighted()

    def _get_selected_ip(self) -> str:
        """Return the IP of the currently highlighted row, or empty string."""
        return self._selected_ip

    def _block_action_for_highlighted(self) -> None:
        if self._selected_ip:
            self._action_block(self._selected_ip)
        else:
            self.app.notify("No attacker selected", title="LIDRA")

    def _unblock_action_for_highlighted(self) -> None:
        if self._selected_ip:
            self._action_unblock(self._selected_ip)
        else:
            self.app.notify("No attacker selected", title="LIDRA")

    def _action_block(self, ip: str) -> None:
        try:
            self.app.data_provider.on_block(ip)
        except Exception:
            logger.debug("data_provider.on_block failed")
        self.app.notify(f"Blocked {ip}", title="LIDRA")
        self._show_detail_for_ip(ip)

    def _action_unblock(self, ip: str) -> None:
        try:
            self.app.data_provider.on_unblock(ip)
        except Exception:
            logger.debug("data_provider.on_unblock failed")
        self.app.notify(f"Unblocked {ip}", title="LIDRA")
        self._show_detail_for_ip(ip)

    def _whois_for_ip(self, ip: str) -> None:
        if ip in self._whois_cache:
            self.app.notify(f"Whois {ip}: {self._whois_cache[ip]}", title="LIDRA", timeout=6)
            return
        try:
            import socket as _sock
            hostname, _, _ = _sock.gethostbyaddr(ip)
            self._whois_cache[ip] = hostname
            self.app.notify(f"Whois {ip} -> {hostname}", title="LIDRA", timeout=6)
        except Exception:
            self._whois_cache[ip] = "no PTR record"
            self.app.notify(f"Whois {ip}: no PTR record", title="LIDRA", timeout=4)

    def _copy_ip(self, ip: str) -> None:
        try:
            import pyperclip
            pyperclip.copy(ip)
            self.app.notify(f"Copied {ip} to clipboard", title="LIDRA", timeout=2)
        except ImportError:
            try:
                import subprocess as _sp
                _sp.run(["xclip", "-selection", "clipboard"], input=ip.encode(), check=True, timeout=3)
                self.app.notify(f"Copied {ip} to clipboard", title="LIDRA", timeout=2)
            except Exception:
                self.app.notify(f"IP: {ip} (clipboard unavailable)", title="LIDRA", timeout=4)

    def on_status_bar_clicked(self, event) -> None:
        area = getattr(event, "area", "")
        if area == "attacks":
            try:
                self.query_one("#event-cell", EventLog).focus()
            except Exception:
                pass
        elif area == "blocked":
            try:
                self.query_one("#attacker-cell", AttackerTable).focus()
            except Exception:
                pass
        elif area == "rate":
            try:
                self.query_one("#traffic-cell", PacketGauge).focus()
            except Exception:
                pass
