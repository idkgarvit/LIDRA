"""Synthetic data generator for the TUI demo / screenshot mode.

Used when LIDRA is launched with ``--demo``: the TUI runs without a
real engine and pulls a steady stream of realistic-looking but
entirely fictional attackers, attacks, packet rates and connections.
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import AsyncGenerator, Dict, List, Optional

logger = logging.getLogger(__name__)


COUNTRY_CODES: List[str] = [
    "RU", "CN", "US", "BR", "IN", "DE", "GB", "FR", "NL", "UA",
    "KR", "JP", "TR", "VN", "PL", "IT", "ES", "MX", "AR", "CA",
]

ATTACK_TYPES: List[tuple[str, str]] = [
    ("SQLi", "high"),
    ("XSS", "medium"),
    ("Brute Force", "high"),
    ("Port Scan", "low"),
    ("DDoS", "critical"),
    ("DNS Tunnel", "high"),
    ("TLS Exfil", "high"),
    ("C2 Beacon", "critical"),
    ("Path Traversal", "high"),
    ("Login Spray", "medium"),
    ("SSH Probe", "medium"),
    ("HTTP Flood", "high"),
]

PROTOCOLS: List[str] = ["http", "https", "dns", "tls", "ssh", "ftp", "smtp"]


@dataclass
class DemoState:
    attackers: List[Dict] = field(default_factory=list)
    attacks: List[Dict] = field(default_factory=list)
    packet_rates: List[int] = field(default_factory=list)
    blocks: List[Dict] = field(default_factory=list)
    rate_drift: float = 0.0
    attack_seq: int = 0
    started_at: datetime = field(default_factory=datetime.now)

    def refresh(self) -> None:
        if not self.attackers:
            self.attackers = _build_attackers()
        if not self.blocks:
            self.blocks = _build_blocks(self.attackers)


def _random_ip(prefixes: Optional[List[str]] = None) -> str:
    if not prefixes:
        prefixes = ["45.33", "185.12", "203.0.113", "198.51.100", "192.0.2"]
    prefix = random.choice(prefixes)
    return f"{prefix}.{random.randint(1, 254)}"


def _build_attackers(n: int = 8) -> List[Dict]:
    out: List[Dict] = []
    for i in range(n):
        attacks_count = random.randint(50, 480)
        severity = random.choices(
            ["critical", "high", "medium", "low"],
            weights=[0.15, 0.4, 0.3, 0.15],
            k=1,
        )[0]
        out.append(
            {
                "ip": _random_ip(),
                "attacks": attacks_count,
                "severity": severity,
                "country": random.choice(COUNTRY_CODES),
                "first_seen": (
                    datetime.now() - timedelta(minutes=random.randint(2, 600))
                ).isoformat(timespec="seconds"),
            }
        )
    out.sort(key=lambda r: r["attacks"], reverse=True)
    return out


def _build_blocks(attackers: List[Dict]) -> List[Dict]:
    out: List[Dict] = []
    for attacker in attackers[:3]:
        out.append(
            {
                "ip": attacker["ip"],
                "reason": random.choice(
                    ["Repeated attacks", "DDoS", "Brute force", "C2 traffic"]
                ),
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "expires_in": random.randint(600, 7200),
            }
        )
    return out


def _new_attack(state: DemoState) -> Dict:
    state.attack_seq += 1
    name, sev = random.choice(ATTACK_TYPES)
    src = random.choice(state.attackers)["ip"] if state.attackers else _random_ip()
    return {
        "ip": src,
        "type": name,
        "severity": sev,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "proto": random.choice(PROTOCOLS),
        "seq": state.attack_seq,
    }


def _drift_rate(state: DemoState) -> int:
    state.rate_drift += random.uniform(-25, 25)
    state.rate_drift = max(-200, min(200, state.rate_drift))
    base = 1100 + state.rate_drift
    jitter = random.randint(-150, 150)
    return max(0, int(base + jitter))


def _new_block(state: DemoState) -> Dict:
    if not state.attackers:
        return {}
    target = random.choice(state.attackers[:5])
    block = {
        "ip": target["ip"],
        "reason": "Manual block from demo stream",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "expires_in": 3600,
    }
    state.blocks.append(block)
    state.blocks = state.blocks[-10:]
    return block


def _new_stats() -> Dict:
    return {
        "cpu_usage": round(random.uniform(8.0, 35.0), 1),
        "memory_usage": round(random.uniform(25.0, 55.0), 1),
        "active_connections": random.randint(50, 750),
    }


def generate_demo_data() -> Dict:
    """Return a full snapshot suitable for ``TUIDataProvider.get_snapshot``."""
    state = DemoState()
    state.refresh()
    return {
        "stats": {
            "total_packets": random.randint(900_000, 9_000_000),
            "total_attacks": random.randint(1_200, 12_000),
            "uptime": "00:00:00",
        },
        "top_attackers": state.attackers,
        "attacks": state.attacks,
        "blocks": state.blocks,
        "connections": [],
        "protocols": {
            "http": random.randint(30, 55),
            "dns": random.randint(15, 35),
            "tls": random.randint(15, 35),
            "ssh": random.randint(2, 10),
            "smtp": random.randint(1, 8),
        },
        "system": {
            "cpu_percent": random.uniform(8, 35),
            "memory_percent": random.uniform(25, 55),
            "bridge_status": "UP",
        },
        "mitre": {},
        "demo": True,
    }


def make_snapshot_provider():
    """Return a callable that produces an evolving demo snapshot."""
    state = DemoState()
    state.refresh()
    snapshot: Dict = generate_demo_data()
    snapshot["_state"] = state

    def provider() -> Dict:
        snapshot["top_attackers"] = state.attackers
        snapshot["blocks"] = state.blocks
        snapshot["attacks"] = state.attacks[-100:]
        snapshot["connections"] = []
        snapshot["protocols"] = {
            "http": random.randint(30, 55),
            "dns": random.randint(15, 35),
            "tls": random.randint(15, 35),
            "ssh": random.randint(2, 10),
            "smtp": random.randint(1, 8),
        }
        snapshot["system"] = {
            "cpu_percent": random.uniform(8, 35),
            "memory_percent": random.uniform(25, 55),
            "bridge_status": "UP",
        }
        snapshot["stats"] = {
            "total_packets": int(snapshot["stats"].get("total_packets", 0)) + random.randint(0, 5000),
            "total_attacks": int(snapshot["stats"].get("total_attacks", 0)) + random.randint(0, 5),
            "uptime": _uptime_str(state.started_at),
        }
        snapshot["demo"] = True
        return snapshot

    return provider


def _uptime_str(start: datetime) -> str:
    delta = datetime.now() - start
    seconds = int(delta.total_seconds())
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


async def demo_event_stream(state: Optional[DemoState] = None) -> AsyncGenerator[Dict, None]:
    """Yield realistic-looking live events forever."""
    if state is None:
        state = DemoState()
        state.refresh()
    while True:
        kind = random.choices(
            ["packet", "attack", "block", "stats", "heartbeat"],
            weights=[0.7, 0.13, 0.04, 0.1, 0.03],
            k=1,
        )[0]
        if kind == "packet":
            yield {
                "type": "packet",
                "data": {
                    "pkts_per_sec": _drift_rate(state),
                    "mbps": round(random.uniform(0.5, 50), 2),
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                },
            }
        elif kind == "attack":
            attack = _new_attack(state)
            state.attacks.append(attack)
            state.attacks = state.attacks[-200:]
            yield {"type": "attack", "data": attack}
        elif kind == "block":
            block = _new_block(state)
            if block:
                yield {"type": "block", "data": block}
        elif kind == "stats":
            yield {"type": "stats", "data": _new_stats()}
        else:
            yield {"type": "heartbeat", "data": {}}
