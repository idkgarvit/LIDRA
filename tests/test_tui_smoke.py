"""The TUI must actually start.

Why this file exists
--------------------
The 377-test suite never started the interface, so a widget bug that killed the
app on launch went unnoticed: LIDRA's Toast.__init__ did not forward **kwargs,
so `Toast("", id="toast-slot")` in CommandBar.compose() raised

    TypeError: Toast.__init__() got an unexpected keyword argument 'id'

and the whole TUI died before drawing a frame. Every unit test passed. These
tests compose the real app and assert it renders, which is the only thing that
would have caught it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def _has_textual() -> bool:
    try:
        import textual  # noqa: F401
        return True
    except Exception:
        return False


requires_textual = pytest.mark.skipif(
    not _has_textual(), reason="textual not installed"
)


@requires_textual
def test_app_composes_and_renders():
    """The real app starts, composes, and produces a non-empty screen."""
    import asyncio

    from tui.app import LidraApp
    from tui.data_provider import TUIDataProvider

    async def run() -> str:
        app = LidraApp(data_provider=TUIDataProvider())
        async with app.run_test(size=(100, 30)) as pilot:
            for _ in range(3):
                await pilot.pause(0.2)
            return app.export_screenshot(title="LIDRA")

    svg = asyncio.run(run())
    assert "<svg" in svg, "export did not produce SVG"
    # A crashed or empty compose produces a nearly wordless frame. The chrome
    # alone (logo, status bar, panel titles) is well above this floor.
    import html
    import re
    raw = " ".join(
        html.unescape(re.sub(r"<[^>]+>", "", t)).strip()
        for t in re.findall(r"<text[^>]*>(.*?)</text>", svg, re.S)
    )
    # Textual renders panel titles with non-breaking spaces. Replace those
    # FIRST, then collapse whitespace — `\s` also matches `\xa0`, so doing it
    # in the other order would leave the label unmatchable.
    text = re.sub(r"[^\S\n]+", " ", raw.replace("\xa0", " "))
    words = [w for w in text.split() if w.isalpha()]
    assert len(words) > 20, (
        f"screen looks empty ({len(words)} words) — composition likely failed"
    )
    # The panels that make it a product, not a splash screen.
    for label in ("TOP ATTACKERS", "SYSTEM"):
        assert label in text, f"missing panel: {label}"


@requires_textual
def test_toast_forwards_widget_kwargs():
    """The exact bug: Toast must accept id/classes the way Textual widgets do."""
    from tui.widgets.command_bar import Toast

    toast = Toast("hello", id="toast-slot")
    assert toast.id == "toast-slot"
    # default classes still applied when the caller does not pass any
    assert "toast" in toast.classes


@requires_textual
def test_command_bar_composes():
    """CommandBar is the widget that failed; compose it directly."""
    import asyncio

    from textual.app import App, ComposeResult
    from tui.widgets.command_bar import CommandBar

    class Harness(App):
        def compose(self) -> ComposeResult:
            yield CommandBar(id="cmd-bar")

    async def run() -> bool:
        app = Harness()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause(0.2)
            return app.query_one(CommandBar) is not None

    assert asyncio.run(run())