"""Single source of truth for the LIDRA version.

Before this module the version string was duplicated in five places
(`pyproject.toml`, `cli/__init__.py`, `output/formatters.py` twice, and the TUI
ASCII logo), so they could drift and no two surfaces agreed on what a given
install was running. `lidra status` and the doctor report now read from here.

Keep in sync with `pyproject.toml`; `tests/test_version.py` asserts they match.
"""

from __future__ import annotations

from pathlib import Path

# The one string to change on release.
__version__ = "3.0.0"

VERSION = __version__


def version_string() -> str:
    """Version in the form the CLI and logs display."""
    return f"v{__version__}"


def package_version_from_pyproject() -> str:
    """Read the version out of pyproject.toml, for consistency checks.

    Returns "" when it cannot be determined (installed without the source
    tree), which the test treats as "skip", not as a mismatch.
    """
    try:
        root = Path(__file__).resolve().parent.parent.parent
        pyproject = root / "pyproject.toml"
        if not pyproject.exists():
            return ""
        for line in pyproject.read_text().splitlines():
            line = line.strip()
            if line.startswith("version") and "=" in line:
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        return ""
    return ""