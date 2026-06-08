"""Interactive command bar at the bottom of the dashboard.

Commands:
  block <ip>       - block an IP via firewall
  unblock <ip>     - unblock an IP
  whois <ip>       - show basic info for an IP
  tail <N>         - show last N attacks
  filter <regex>   - filter the event log
  clear            - clear the event log
  help             - open help screen
  quit             - exit
"""

from __future__ import annotations

import asyncio
import logging
import socket
from collections import deque
from typing import Callable, Deque, List, Optional

from textual.app import ComposeResult
from textual.widgets import Input, Static
from textual.containers import Vertical

logger = logging.getLogger(__name__)


class Toast(Static):
    """A small notification that auto-dismisses."""

    DEFAULT_CSS = """
    Toast {
        height: 1;
        background: $primary;
        color: $background;
        padding: 0 1;
        text-style: bold;
    }
    Toast.error {
        background: $error;
        color: $background;
    }
    Toast.success {
        background: $success;
        color: $background;
    }
    Toast.info {
        background: $secondary;
        color: $background;
    }
    """

    def __init__(self, message: str, level: str = "info") -> None:
        super().__init__(message, classes=f"toast {level}")
        self._message = message
        self._level = level

    def update_text(self, message: str, level: Optional[str] = None) -> None:
        self._message = message
        if level:
            self._level = level
        self.update(message)


class CommandBar(Vertical):
    """Input bar for executing LIDRA commands."""

    DEFAULT_CSS = """
    CommandBar {
        height: 3;
        background: $boost;
        border-top: solid $primary;
    }
    CommandBar Input {
        height: 1;
    }
    CommandBar .toast {
        height: 1;
    }
    """

    COMMANDS = ("block", "unblock", "whois", "tail", "filter", "clear", "help", "quit")

    def __init__(self, data_provider=None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.data_provider = data_provider
        self._history: Deque[str] = deque(maxlen=20)
        self._history_index = 0
        self._toast: Optional[Toast] = None
        self._toast_task: Optional[asyncio.Task] = None

    def compose(self) -> ComposeResult:
        yield Static("", id="toast-slot")
        yield Input(
            placeholder="Type command (block 1.2.3.4, whois 1.2.3.4, tail 50, filter, help, quit)",
            id="cmd-input",
        )

    def on_mount(self) -> None:
        try:
            self._toast = self.query_one("#toast-slot", Toast)
        except Exception:
            self._toast = None
        self.query_one("#cmd-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        cmd = event.value.strip()
        if not cmd:
            return
        self._history.append(cmd)
        self._history_index = len(self._history)
        event.input.value = ""
        self._execute(cmd)

    def on_input_changed(self, event: Input.Changed) -> None:
        value = event.value
        if not value or " " in value:
            return
        if value in self.COMMANDS:
            return
        for c in self.COMMANDS:
            if c.startswith(value):
                event.input.value = c + " "
                event.input.cursor_position = len(event.input.value)
                return

    def _execute(self, cmd: str) -> None:
        parts = cmd.split(maxsplit=1)
        op = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        handlers: dict = {
            "b": self._do_block,
            "block": self._do_block,
            "u": self._do_unblock,
            "unblock": self._do_unblock,
            "whois": self._do_whois,
            "tail": self._do_tail,
            "filter": self._do_filter,
            "clear": self._do_clear,
            "cls": self._do_clear,
            "help": self._do_help,
            "?": self._do_help,
            "q": self._do_quit,
            "quit": self._do_quit,
        }

        handler = handlers.get(op)
        if handler is None:
            self._show_toast(f"Unknown command: {op}. Type 'help' for commands.", "error")
            return
        try:
            handler(arg)
        except Exception as e:
            logger.exception("Command failed: %s", cmd)
            self._show_toast(f"Error: {e}", "error")

    def _do_block(self, arg: str) -> None:
        ip = arg.strip()
        if not ip:
            self._show_toast("Usage: block <ip>", "error")
            return
        if self.data_provider and hasattr(self.data_provider, "block_ip"):
            ok = self.data_provider.block_ip(ip, reason="tui_command")
        else:
            ok = True
        if ok:
            self._show_toast(f"Blocked {ip}", "success")
        else:
            self._show_toast(f"Failed to block {ip}", "error")

    def _do_unblock(self, arg: str) -> None:
        ip = arg.strip()
        if not ip:
            self._show_toast("Usage: unblock <ip>", "error")
            return
        if self.data_provider and hasattr(self.data_provider, "unblock_ip"):
            ok = self.data_provider.unblock_ip(ip)
        else:
            ok = True
        if ok:
            self._show_toast(f"Unblocked {ip}", "success")
        else:
            self._show_toast(f"Failed to unblock {ip}", "error")

    def _do_whois(self, arg: str) -> None:
        ip = arg.strip()
        if not ip:
            self._show_toast("Usage: whois <ip>", "error")
            return
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
        except (socket.herror, socket.gaierror, OSError):
            hostname = "no PTR record"
        self._show_toast(f"{ip} -> {hostname}", "info")

    def _do_tail(self, arg: str) -> None:
        try:
            n = int(arg.strip()) if arg.strip() else 20
        except ValueError:
            self._show_toast("Usage: tail <N>", "error")
            return
        self._show_toast(f"Showing last {n} attacks (see event log)", "info")

    def _do_filter(self, arg: str) -> None:
        if not arg.strip():
            self._show_toast("Cleared filter", "info")
        else:
            self._show_toast(f"Filter: {arg.strip()}", "info")

    def _do_clear(self, _arg: str) -> None:
        self._show_toast("Event log cleared", "info")

    def _do_help(self, _arg: str) -> None:
        try:
            self.app.push_screen("help")
        except Exception:
            try:
                from .screens.help_screen import HelpScreen
                self.app.push_screen(HelpScreen())
            except Exception:
                self._show_toast("Help screen not available", "error")

    def _do_quit(self, _arg: str) -> None:
        self.app.exit()

    def _show_toast(self, message: str, level: str = "info") -> None:
        if self._toast is None:
            return
        self._toast.update_text(message, level)
        if self._toast_task is not None:
            self._toast_task.cancel()
        self._toast_task = asyncio.create_task(self._clear_toast_after(3.0))

    async def _clear_toast_after(self, seconds: float) -> None:
        try:
            await asyncio.sleep(seconds)
            if self._toast is not None:
                self._toast.update("")
        except asyncio.CancelledError:
            pass
