# src/utils/paths.py
"""Distro-agnostic project path resolution: env var → script-relative → cwd → install defaults."""

import os
from pathlib import Path
from typing import Optional

_LIDRA_ROOT: Optional[Path] = None


def get_lidra_root() -> Path:
    global _LIDRA_ROOT
    if _LIDRA_ROOT is not None:
        return _LIDRA_ROOT

    env = os.environ.get("LIDRA_ROOT")
    if env:
        _LIDRA_ROOT = Path(env).resolve()
        return _LIDRA_ROOT

    candidates = [
        Path(__file__).resolve().parent.parent.parent,       # src/utils/paths.py → project root
        Path(__file__).resolve().parent.parent.parent.parent / "src",  # nested install
        Path.cwd(),
        Path("/opt/lidra"),
        Path("/usr/local/lidra"),
    ]
    for c in candidates:
        if (c / "config" / "config.yaml").exists():
            _LIDRA_ROOT = c.resolve()
            return _LIDRA_ROOT
    _LIDRA_ROOT = candidates[0]
    return _LIDRA_ROOT


def get_config_path() -> Path:
    return get_lidra_root() / "config" / "config.yaml"


def get_data_dir() -> Path:
    d = get_lidra_root() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def resolve_secret(category: str, key: str, config_value: Optional[str] = None) -> Optional[str]:
    env_map = {
        ("smtp", "password"): "LIDRA_SMTP_PASSWORD",
        ("abuseipdb", "api_key"): "LIDRA_ABUSEIPDB_KEY",
        ("virustotal", "api_key"): "LIDRA_VT_KEY",
        # ("dashboard", "api_key"): "LIDRA_API_KEY" — removed with the dead
        # `dashboard.api_key` config key (plan section 1.6); nothing read it.
        ("slack", "webhook"): "SLACK_WEBHOOK",
        ("discord", "webhook"): "DISCORD_WEBHOOK",
    }
    env_key = env_map.get((category, key))
    if env_key:
        val = os.environ.get(env_key)
        if val:
            return val
    return config_value
