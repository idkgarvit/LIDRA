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
  |  ProtocolBar (40%)  |  Sparkline (60%)                  |
  +----------------------------------------------------------+
  | Custom footer  [1] [2] [3] [b] [?] [q]                   |
  +----------------------------------------------------------+
"""

from __future__ import annotations

import logging
from typing import Optional

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
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
from ..widgets.protocol_bar import ProtocolBar
from ..widgets.sparkline import Sparkline
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
    }
    #bottom-row {
        height: 30%;
        margin: 0 0 1 0;
    }
    #protocol-cell {
        width: 40%;
        border: round $primary;
    }
    #packet-cell {
        width: 60%;
        border: round $secondary;
    }
    .panel-title {
        background: $primary;
        color: $background;
        text-style: bold;
        padding: 0 1;
        height: 1;
    }
    """

    snapshot: reactive[StatusSnapshot] = reactive(StatusSnapshot, init=False)

    def compose(self) -> ComposeResult:
        yield StatusBar(id="status-bar")
        with Container(id="dashboard-root"):
            with Horizontal(id="top-row"):
                yield AsciiLogo(id="logo-cell", classes="dashboard-cell")
                yield SystemStats(id="stats-cell", classes="dashboard-cell")
            yield Rule(orientation="horizontal", line_style="heavy", id="mid-rule")
            with Horizontal(id="mid-row"):
                yield AttackerTable(id="attacker-cell", classes="dashboard-cell")
                yield EventLog(id="event-cell", classes="dashboard-cell")
            yield DetailPanel(id="detail-panel")
            yield Rule(orientation="horizontal", line_style="heavy", id="bottom-rule")
            with Horizontal(id="bottom-row"):
                yield ProtocolBar(id="protocol-cell", classes="dashboard-cell")
                yield Sparkline(window=60, id="sparkline-cell", classes="dashboard-cell")
        yield CommandBar(data_provider=self.app.data_provider if hasattr(self.app, "data_provider") else None, id="cmd-bar")
        yield CompactFooter()

    def on_mount(self) -> None:
        self.set_interval(0.5, self.refresh_status_bar)
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
        stats = data_snapshot.get("stats", {}) if isinstance(data_snapshot, dict) else {}
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
        self.query_one("#attacker-cell", AttackerTable).update_data(snapshot.get("top_attackers", []))

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

        if hasattr(self.app.data_provider, "get_protocol_breakdown"):
            real_protocols = self.app.data_provider.get_protocol_breakdown()
            if real_protocols:
                self.query_one("#protocol-cell", ProtocolBar).update_protocols(real_protocols)
            else:
                protocol_counts = snapshot.get("protocols") or {"http": 40, "dns": 30, "tls": 30}
                self.query_one("#protocol-cell", ProtocolBar).update_protocols(protocol_counts)
        else:
            protocol_counts = snapshot.get("protocols") or {"http": 40, "dns": 30, "tls": 30}
            self.query_one("#protocol-cell", ProtocolBar).update_protocols(protocol_counts)

    def handle_event(self, etype: str, data: dict) -> None:
        if etype == "packet":
            try:
                self.query_one("#packet-cell", PacketGauge).update_flow(
                    data.get("pkts_per_sec", 0), self.app.packet_history
                )
            except Exception:
                logger.debug("packet-cell update skipped")
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
        row = event.row
        detail = (
            f"IP: {row.ip}\n"
            f"Country: {row.country}\n"
            f"Attacks: {row.attacks:,}\n"
            f"Severity: {row.severity.upper()}\n"
        )
        self.app.notify(detail, title="Attacker details", timeout=8)
        self._show_detail_for_ip(row.ip)

    def on_attacker_table_row_focused(self, event: AttackerTable.RowFocused) -> None:
        self._show_detail_for_ip(event.row.ip)

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

    def on_data_table_row_selected(self, event):
        try:
            table = self.query_one("#attacker-data", "DataTable")
        except Exception:
            return
        try:
            from textual.widgets import DataTable
            if not isinstance(event.sender, DataTable) or event.sender.id != "attacker-data":
                return
            row_index = event.cursor_row
            try:
                row = table.get_row_at(row_index)
                ip = str(row[0]) if row else ""
                if ip:
                    self.app.notify(f"Selected: {ip}", title="LIDRA", timeout=3)
            except Exception:
                logger.debug("get_row_at failed")
        except Exception:
            logger.debug("on_data_table_row_selected skipped")

    def block_selected_attacker(self) -> None:
        self._block_action_for_highlighted()

    def unblock_selected_attacker(self) -> None:
        self._unblock_action_for_highlighted()

    def focus_search(self) -> None:
        self.app.notify("Search: type to filter (press Ctrl+l to clear)", title="LIDRA")

    def clear_filters(self) -> None:
        self.app.notify("Filters cleared", title="LIDRA")

    def _block_action_for_highlighted(self) -> None:
        try:
            table = self.query_one("#attacker-data", "DataTable")
            row_index = table.cursor_row
            row = table.get_row_at(row_index)
            ip = str(row[0]) if row else None
            if ip:
                self._action_block(ip)
        except Exception:
            self.app.notify("No attacker selected", title="LIDRA")

    def _unblock_action_for_highlighted(self) -> None:
        try:
            table = self.query_one("#attacker-data", "DataTable")
            row_index = table.cursor_row
            row = table.get_row_at(row_index)
            ip = str(row[0]) if row else None
            if ip:
                self._action_unblock(ip)
        except Exception:
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

    def on_static_click(self, event) -> None:
        widget = event.widget
        widget_id = getattr(widget, "id", "") or ""
        if widget_id == "status-attacks":
            try:
                self.query_one("#event-cell", EventLog).focus()
            except Exception:
                logger.debug("Could not focus event log")
        elif widget_id == "status-blocked":
            try:
                self.app.switch_screen("config")
            except Exception:
                logger.debug("Could not switch to config")
        elif widget_id == "status-rate":
            try:
                self.query_one("#packet-cell", PacketGauge).focus()
            except Exception:
                logger.debug("Could not focus packet cell")

    def on_status_bar_clicked(self, event) -> None:
        area = getattr(event, "area", "")
        if area == "attacks":
            try:
                self.query_one("#event-cell", EventLog).focus()
            except Exception:
                pass
        elif area == "blocked":
            try:
                self.app.switch_screen("config")
            except Exception:
                pass
        elif area == "rate":
            try:
                self.query_one("#packet-cell", PacketGauge).focus()
            except Exception:
                pass
