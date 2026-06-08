"""Theme system for the LIDRA TUI.

Defines ``DARK_THEME`` and ``LIGHT_THEME`` token dictionaries, a set of
severity colors shared by both, and ``apply_theme()`` which registers and
activates a theme on a Textual ``App``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, Optional

from textual.app import App
from textual.theme import Theme

logger = logging.getLogger(__name__)


DARK_THEME: Dict[str, str] = {
    "primary": "#3DD2C0",
    "secondary": "#2A6FB5",
    "success": "#4EBF71",
    "warning": "#E0A33A",
    "error": "#E84B4B",
    "foreground": "#E6E6E6",
    "background": "#0E1116",
    "accent": "#FF6E6E",
    "muted": "#5A6472",
    "panel": "#161B22",
    "surface": "#1B2230",
    "boost": "#2A3445",
    "border": "#2C3542",
    "text": "#E6E6E6",
    "text-muted": "#8A93A3",
    "critical": "bold #FF3B3B",
    "high": "#E84B4B",
    "medium": "#E0A33A",
    "low": "#4FA3F7",
    "info": "#4EBF71",
}


LIGHT_THEME: Dict[str, str] = {
    "primary": "#0F766E",
    "secondary": "#1D4ED8",
    "success": "#15803D",
    "warning": "#B45309",
    "error": "#B91C1C",
    "foreground": "#111827",
    "background": "#F5F7FA",
    "accent": "#DC2626",
    "muted": "#6B7280",
    "panel": "#FFFFFF",
    "surface": "#EEF2F7",
    "boost": "#D7DEE8",
    "border": "#CBD5E1",
    "text": "#111827",
    "text-muted": "#4B5563",
    "critical": "bold #B91C1C",
    "high": "#DC2626",
    "medium": "#B45309",
    "low": "#1D4ED8",
    "info": "#15803D",
}


SEVERITY_COLORS: Dict[str, str] = {
    "critical": DARK_THEME["critical"],
    "high": DARK_THEME["high"],
    "medium": DARK_THEME["medium"],
    "low": DARK_THEME["low"],
    "info": DARK_THEME["info"],
}


@dataclass(frozen=True)
class ThemeSpec:
    name: str
    dark: bool
    tokens: Dict[str, str]
    description: str = ""


THEMES: Dict[str, ThemeSpec] = {
    "dark": ThemeSpec(
        name="dark",
        dark=True,
        tokens=DARK_THEME,
        description="Low-light theme with cyan/green accents (default).",
    ),
    "light": ThemeSpec(
        name="light",
        dark=False,
        tokens=LIGHT_THEME,
        description="Bright theme for daylight documentation work.",
    ),
}


def _build_textual_theme(spec: ThemeSpec) -> Theme:
    tokens = spec.tokens
    variables: Dict[str, str] = {}
    css_var_map = {
        "primary": "primary",
        "secondary": "secondary",
        "success": "success",
        "warning": "warning",
        "error": "error",
        "accent": "accent",
        "foreground": "foreground",
        "background": "background",
        "panel": "panel",
        "surface": "surface",
        "boost": "boost",
        "muted": "text-muted",
        "border": "border",
        "text-muted": "text-muted",
    }
    for token, css_name in css_var_map.items():
        value = tokens.get(token)
        if value:
            variables[css_name] = value

    return Theme(
        name=spec.name,
        primary=tokens["primary"],
        secondary=tokens["secondary"],
        success=tokens["success"],
        warning=tokens["warning"],
        error=tokens["error"],
        accent=tokens["accent"],
        foreground=tokens["foreground"],
        background=tokens["background"],
        panel=tokens["panel"],
        surface=tokens["surface"],
        boost=tokens["boost"],
        dark=spec.dark,
        variables=variables,
    )


_REGISTERED: Dict[str, bool] = {}


def _register_once(app: App, spec: ThemeSpec) -> None:
    key = (id(app), spec.name)
    if _REGISTERED.get(key):
        return
    try:
        app.register_theme(_build_textual_theme(spec))
    except Exception as exc:
        logger.debug("Theme %s already registered or unsupported: %s", spec.name, exc)
    _REGISTERED[key] = True


def apply_theme(app: App, theme_name: str) -> bool:
    """Register and activate a theme by name on ``app``.

    Returns ``True`` if the theme was applied, ``False`` if the name is
    unknown (in which case the app's current theme is left untouched).
    """
    spec = THEMES.get(theme_name)
    if spec is None:
        logger.warning("Unknown theme: %s", theme_name)
        return False
    _register_once(app, spec)
    try:
        app.theme = spec.name
    except Exception as exc:
        logger.warning("Failed to apply theme %s: %s", spec.name, exc)
        return False
    try:
        app.dark = spec.dark
    except Exception:
        logger.debug("app.dark assignment unsupported on this Textual build")
    return True


def toggle_theme(app: App) -> str:
    """Switch between dark and light themes.

    Returns the name of the theme that is now active.
    """
    current = getattr(app, "theme", "dark")
    target = "light" if current == "dark" else "dark"
    apply_theme(app, target)
    return target


def severity_style(severity: str) -> str:
    """Return the color/rich style for a given severity token."""
    return SEVERITY_COLORS.get((severity or "info").lower(), SEVERITY_COLORS["info"])


def current_tokens(app: App) -> Dict[str, str]:
    """Return the active token dict for the app's current theme."""
    name = getattr(app, "theme", "dark")
    spec = THEMES.get(name) or THEMES["dark"]
    return dict(spec.tokens)
