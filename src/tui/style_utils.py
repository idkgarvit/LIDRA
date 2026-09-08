"""Theme token resolver for use in Rich Text styles.

Rich's ``Text.append(style=...)`` does not understand Textual CSS
variable references like ``"$text-muted"`` (the span path uses
``Console.get_style`` which delegates to Rich's parser). This module
exposes a tiny helper that resolves a token name (e.g. ``"muted"``,
``"$text-muted"``) to the live hex color value from the active theme.
"""

from __future__ import annotations

import logging
from typing import Optional

from .themes import DARK_THEME, current_tokens

logger = logging.getLogger(__name__)


def _strip_prefix(token: str) -> str:
    return token.lstrip("$")


def resolve(token: str, fallback: Optional[str] = None) -> str:
    """Return the live hex/colour value for a theme token.

    Accepts both ``"muted"`` and ``"$text-muted"``; returns ``fallback``
    (or the original token) if the token is unknown.
    """
    name = _strip_prefix(token)
    try:
        from textual._context import active_app

        app = active_app.get()
        if app is not None:
            tokens = current_tokens(app)
            value = tokens.get(name)
            if value:
                return value
    except Exception:
        logger.debug("No active app, falling back to DARK_THEME for %s", token)
    value = DARK_THEME.get(name)
    if value:
        return value
    return fallback if fallback is not None else token


