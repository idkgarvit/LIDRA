"""ASCII art LIDRA logo widget.

Renders a multi-line logo using box-drawing characters, with a gradient
of cyan-to-green coloring via Rich's ``Text``. The widget is a plain
``Static`` that can be dropped into any container.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from rich.text import Text
from textual.app import ComposeResult
from textual.widgets import Static

logger = logging.getLogger(__name__)


LOGO: str = """\
\u256d\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256e
\u2502   \u2588\u2588\u2588   \u2588\u2588\u2588  \u2588\u2588      \u2588\u2588\u2588\u2588\u2588   \u2588\u2588\u2588\u2588\u2588\u2588  \u2588\u2588    \u2588\u2588    \u2502
\u2502   \u2588\u2588\u2588   \u2588\u2588\u2588  \u2588\u2588\u2588\u2588    \u2588\u2588   \u2588\u2588 \u2588\u2588   \u2588\u2588 \u2588\u2588    \u2588\u2588    \u2502
\u2502   \u2588\u2588\u2588   \u2588\u2588\u2588  \u2588\u2588 \u2588\u2588   \u2588\u2588    \u2588\u2588 \u2588\u2588   \u2588\u2588 \u2588\u2588    \u2588\u2588    \u2502
\u2502   \u2588\u2588\u2588   \u2588\u2588\u2588  \u2588\u2588  \u2588\u2588  \u2588\u2588    \u2588\u2588 \u2588\u2588   \u2588\u2588 \u2588\u2588    \u2588\u2588    \u2502
\u2502   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588  \u2588\u2588  \u2588\u2588  \u2588\u2588    \u2588\u2588  \u2588\u2588\u2588\u2588\u2588\u2588  \u2588\u2588    \u2502
\u2502   \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500  \u2500\u2500  \u2500\u2500  \u2500\u2500    \u2500\u2500   \u2500\u2500\u2500\u2500\u2500   \u2500\u2500    \u2502
\u2502        \u2588\u2588\u2588    \u2588\u2588\u2588  \u2588\u2588\u2588\u2588\u2588 \u2588\u2588\u2588   \u2588\u2588\u2588 \u2588\u2588\u2588   \u2588\u2588\u2588 \u2588\u2588    \u2502
\u2502      \u2588\u2588    \u2588\u2588  \u2588\u2588   \u2588\u2588 \u2588\u2588  \u2588\u2588 \u2588\u2588    \u2588\u2588  \u2588\u2588  \u2588\u2588  \u2588\u2588    \u2502
\u2502        \u2588\u2588\u2588    \u2588\u2588\u2588\u2588\u2588 \u2588\u2588  \u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588  \u2588\u2588  \u2588\u2588    \u2502
\u2502                                                              \u2502
\u2502             L I D R A   v 3 . 0 . 0                          \u2502
\u2502         IDS for the edge \u00b7 real-time \u00b7 inline              \u2502
\u2570\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256f
"""


TAGLINE: str = "IDS for the edge \u00b7 real-time \u00b7 inline"
VERSION: str = "v3.0.0"


def _build_logo_text(width: int | None = None) -> Text:
    """Build a Rich ``Text`` with cyan/green gradient for the logo."""
    text = Text()
    lines = LOGO.rstrip("\n").splitlines()
    total = max(len(lines), 1)
    for idx, line in enumerate(lines):
        ratio = idx / max(total - 1, 1)
        red = int(40 + (40 * (1 - ratio)))
        green = int(200 - (60 * ratio))
        blue = int(180 - (20 * ratio))
        color = f"#{red:02x}{green:02x}{blue:02x}"
        text.append(line, style=color)
        if idx != len(lines) - 1:
            text.append("\n")
    return text


def _build_compact_logo_text() -> Text:
    """Return a short, single-row logo suitable for narrow headers."""
    text = Text()
    text.append("\u2588\u2588\u2588", style="bold #3DD2C0")
    text.append(" LIDRA ", style="bold #E6E6E6")
    text.append(VERSION, style="#8A93A3")
    text.append(" \u00b7 ", style="#5A6472")
    text.append(TAGLINE, style="italic #4EBF71")
    return text


class AsciiLogo(Static):
    """A ``Static`` widget that renders the LIDRA ASCII logo."""

    DEFAULT_CSS: str = """
    AsciiLogo {
        height: 1fr;
    }
    """

    def __init__(self, compact: bool = False, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.compact = compact

    def render(self) -> Text:
        if self.compact:
            return _build_compact_logo_text()
        return _build_logo_text()
