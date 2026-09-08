"""Drill-down detail panel for a selected attacker.

Shown when an attacker row is focused/activated. Displays:
  - IP, country, org
  - First/last seen
  - Attack count + top attack types
  - Top targeted ports
  - Suggested action (auto-derived from patterns)
  - Hotkey hint: [b] block  [u] unblock  [esc] clear
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, Optional

from rich.console import Group
from rich.text import Text
from textual.app import ComposeResult
from textual.reactive import reactive
from textual.widgets import Static

logger = logging.getLogger(__name__)


SUGGESTIONS = {
    "ssh_bruteforce": "Block at firewall — credential attack in progress",
    "mysql_bruteforce": "Block at firewall — DB credential attack",
    "postgres_bruteforce": "Block at firewall — DB credential attack",
    "ftp_bruteforce": "Block at firewall — FTP credential attack",
    "pop3_bruteforce": "Block at firewall — email credential attack",
    "sql_injection": "Block immediately + audit WAF rules",
    "xss_attempt": "Verify WAF coverage; block if pattern repeats",
    "path_traversal": "Block + audit file serving endpoints",
    "command_injection": "Block immediately + audit shell handlers",
    "log4j_attempt": "Block + patch vulnerable services",
    "shellshock_attempt": "Block + patch CGI endpoints",
    "eternalblue_attempt": "Block + patch SMB (MS17-010)",
    "port_scan": "Monitor; block if port_scan count > 100",
    "broadcast_storm": "Investigate L2 loop or misconfigured device",
    "timing_evasion": "Likely DPI evasion — increase capture fidelity",
}


class DetailPanel(Static):
    """Shows detailed info about a selected attacker."""

    DEFAULT_CSS = """
    DetailPanel {
        height: auto;
        min-height: 5;
        background: $boost;
        border: round $primary;
        padding: 0 1;
    }
    DetailPanel.empty {
        border: round $border;
    }
    """

    current_ip: reactive[Optional[str]] = reactive(None)

    def __init__(self, **kwargs) -> None:
        kwargs.setdefault("id", "detail-panel")
        kwargs.setdefault("classes", "empty")
        super().__init__("", **kwargs)
        self._detail: Optional[Dict] = None
        self._refresh()

    def compose(self) -> ComposeResult:
        yield Static("", id="detail-content")

    def show_attacker(self, ip: str, detail: Optional[Dict] = None) -> None:
        self.current_ip = ip
        self._detail = detail
        self.remove_class("empty")
        self._refresh()

    def clear(self) -> None:
        self.current_ip = None
        self._detail = None
        self.add_class("empty")
        self._refresh()

    def _suggest_action(self, top_type: str, count: int) -> str:
        if top_type in SUGGESTIONS:
            return SUGGESTIONS[top_type]
        if count >= 100:
            return "Block at firewall — high volume attacker"
        if count >= 20:
            return "Monitor; escalate if pattern persists"
        return "Monitor; no immediate action needed"

    def _format_first_seen(self, ts: str) -> str:
        try:
            dt = datetime.fromisoformat(ts.replace(" ", "T").split(".")[0])
            return dt.strftime("%Y-%m-%d %H:%M")
        except (ValueError, AttributeError):
            return str(ts)[:16] if ts else "—"

    def _format_last_seen(self, ts: str) -> str:
        try:
            dt = datetime.fromisoformat(ts.replace(" ", "T").split(".")[0])
            return dt.strftime("%H:%M:%S")
        except (ValueError, AttributeError):
            return str(ts)[:8] if ts else "—"

    def _build_renderable(self):
        empty = Text(
            "  DRILL-DOWN  Select an attacker (arrow keys) to see details",
            style="dim italic",
        )
        if not self._detail:
            return empty

        d = self._detail
        ip = d.get("ip", self.current_ip or "?")
        country = d.get("country") or "??"
        org = d.get("org") or "—"
        attack_count = d.get("attack_count", 0)
        first_seen = self._format_first_seen(d.get("first_seen", ""))
        last_seen = self._format_last_seen(d.get("last_seen", ""))
        top_types = d.get("top_types", [])
        top_ports = d.get("top_ports", [])
        blocked = d.get("blocked", False)

        top_type = top_types[0][0] if top_types else "unknown"

        action = self._suggest_action(top_type, attack_count)
        if attack_count >= 50:
            action_style = "bold red"
        elif attack_count >= 10:
            action_style = "yellow"
        else:
            action_style = "default"

        title = Text()
        title.append(" DRILL-DOWN ", style="bold black on cyan")
        title.append(f"  {ip}  ", style="bold white")
        title.append(f"{country}  ", style="default")
        title.append(f"{org}", style="dim")
        if blocked:
            title.append("  ", style="default")
            title.append(" BLOCKED ", style="bold white on red")

        row1 = Text()
        row1.append("first: ", style="dim")
        row1.append(f"{first_seen}  ", style="default")
        row1.append("last: ", style="dim")
        row1.append(f"{last_seen}  ", style="default")
        row1.append("count: ", style="dim")
        row1.append(f"{attack_count:,}", style=action_style)

        rows = [title, row1]

        if top_types:
            r = Text("types: ", style="dim")
            type_strs = [f"{t}({c})" for t, c in top_types[:4]]
            r.append("  ".join(type_strs), style="default")
            rows.append(r)

        if top_ports:
            r = Text("ports: ", style="dim")
            r.append(", ".join(str(p) for p, _ in top_ports[:4]), style="default")
            rows.append(r)

        action_row = Text("→ ", style="dim")
        action_row.append(action, style=action_style)
        rows.append(action_row)

        hint = Text("hotkeys: ", style="dim")
        hint.append("[b]", style="bold")
        hint.append("lock  ", style="default")
        hint.append("[u]", style="bold")
        hint.append("nblock  ", style="default")
        hint.append("[esc]", style="bold")
        hint.append(" back", style="default")
        rows.append(hint)

        return Group(*rows)

    def _refresh(self) -> None:
        try:
            content = self._build_renderable()
            try:
                self.query_one("#detail-content", Static).update(content)
            except Exception:
                # Fallback: update the widget itself
                self.update(content)
        except Exception as e:
            logger.debug("DetailPanel refresh failed: %s", e)
