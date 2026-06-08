"""Compact custom Footer for the LIDRA TUI.

A trimmed-down footer that only surfaces the most important
keybindings (screen switches, block, help, quit). Bindings are
declared on the :class:`~tui.app.LidraApp`; this widget only renders
those with ``show=True``.
"""

from __future__ import annotations

from textual.widgets import Footer


class CompactFooter(Footer):
    """A compact footer styled for the LIDRA TUI."""

    DEFAULT_CSS: str = """
    CompactFooter {
        background: $panel;
        color: $foreground;
        height: 1;
        border-top: solid $border;
    }
    CompactFooter > .footer--button {
        background: $boost;
        color: $foreground;
    }
    CompactFooter > .footer--key {
        background: $primary;
        color: $background;
        text-style: bold;
    }
    CompactFooter > .footer--description {
        color: $text-muted;
    }
    CompactFooter > .footer--highlight {
        background: $secondary;
        color: $background;
        text-style: bold;
    }
    """
