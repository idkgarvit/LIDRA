"""Synthetic attack injector for ``lidra --demo``.

Spawns a background thread that injects realistic-looking detection events
through the agent's pipeline so they appear in the TUI as if real.
"""

import logging
import threading
import time
from datetime import datetime

logger = logging.getLogger(__name__)


_DEMO_EVENTS = [
    {"type": "attack", "data": {"ip": "45.33.22.11", "type": "Brute Force", "severity": "high"}},
    {"type": "attack", "data": {"ip": "185.12.44.7", "type": "Brute Force", "severity": "high"}},
    {"type": "attack", "data": {"ip": "45.33.22.11", "type": "Brute Force", "severity": "high"}},
    {"type": "attack", "data": {"ip": "45.33.22.11", "type": "Brute Force", "severity": "high"}},
    {"type": "attack", "data": {"ip": "185.12.44.7", "type": "Brute Force", "severity": "high"}},
    {"type": "attack", "data": {"ip": "91.240.118.22", "type": "SQLi", "severity": "high"}},
    {"type": "attack", "data": {"ip": "91.240.118.22", "type": "SQLi", "severity": "high"}},
    {"type": "attack", "data": {"ip": "203.0.113.50", "type": "Port Scan", "severity": "low"}},
    {"type": "attack", "data": {"ip": "203.0.113.50", "type": "Port Scan", "severity": "low"}},
    {"type": "attack", "data": {"ip": "203.0.113.50", "type": "Port Scan", "severity": "low"}},
    {"type": "block", "data": {"ip": "45.33.22.11", "reason": "Brute force detected"}},
    {"type": "block", "data": {"ip": "91.240.118.22", "reason": "SQL injection detected"}},
]


def inject_demo_events(agent, delay: float = 2.0) -> threading.Thread:
    """Start a daemon thread that injects demo events after *delay* seconds."""
    t = threading.Thread(target=_inject, args=(agent, delay), daemon=True, name="demo-injector")
    t.start()
    logger.info("[Demo] Injector thread started — events will fire in %.1f seconds", delay)
    return t


def _inject(agent, delay: float) -> None:
    time.sleep(delay)
    logger.info("[Demo] Injecting %d demo events into the detection pipeline", len(_DEMO_EVENTS))

    for ev in _DEMO_EVENTS:
        ev["data"]["timestamp"] = datetime.now().isoformat()
        _record_in_db(agent, ev)
        agent.push_event(ev)
        time.sleep(0.5)

    logger.info("[Demo] Demo events injected — you should see them in the TUI")


def _record_in_db(agent, ev: dict) -> None:
    if ev["type"] != "attack":
        return
    ip = ev["data"]["ip"]
    attack_type = ev["data"]["type"]
    attacker_id = agent.db.add_attacker(ip, country="", org="")
    agent.db.record_attack(attacker_id, attack_type, source_log="demo_injector", raw_line=f"[Demo] {attack_type} from {ip}", dedupe=False)
