# src/utils/config_loader.py
"""Central config cache: loaded once, shared by all modules."""

import logging
from typing import Any, Optional
from utils.paths import get_config_path, resolve_secret

logger = logging.getLogger(__name__)

_CACHE: Optional[dict] = None


def load_config() -> dict:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    import yaml
    cfg_path = get_config_path()
    if cfg_path.exists():
        try:
            with open(cfg_path) as f:
                raw = yaml.safe_load(f) or {}
            _post_process_secrets(raw)
            _CACHE = raw
            return _CACHE
        except Exception as e:
            logger.warning(f"Failed to load config from {cfg_path}: {e}")
    _CACHE = {}
    return _CACHE


def _post_process_secrets(cfg: dict):
    mapping = [
        ("alerts.email.password", "smtp", "password"),
        ("threat_intel.abuseipdb_api_key", "abuseipdb", "api_key"),
        ("threat_intel.virustotal_api_key", "virustotal", "api_key"),
        ("dashboard.api_key", "dashboard", "api_key"),
        ("alerts.slack_webhook", "slack", "webhook"),
        ("alerts.discord_webhook", "discord", "webhook"),
    ]
    for dot_key, cat, skey in mapping:
        parts = dot_key.split(".")
        target = cfg
        for p in parts[:-1]:
            target = target.setdefault(p, {})
        cur = target.get(parts[-1])
        cur_for_secret = cur if isinstance(cur, str) and cur else None
        env_val = resolve_secret(cat, skey, cur_for_secret)
        if env_val:
            target[parts[-1]] = env_val


def get_cfg(key: str, default: Any = None) -> Any:
    cfg = load_config()
    parts = key.split(".")
    for p in parts:
        if not isinstance(cfg, dict):
            return default
        cfg = cfg.get(p, {})
    return cfg if cfg != {} else default


def invalidate_cache():
    global _CACHE
    _CACHE = None
