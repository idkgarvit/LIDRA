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
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


COUNTRY_CODES: List[str] = [
    "RU", "CN", "US", "BR", "IN", "DE", "GB", "FR", "NL", "UA",
    "KR", "JP", "TR", "VN", "PL", "IT", "ES", "MX", "AR", "CA",
]

@dataclass
class DemoState:
    attackers: List[Dict] = field(default_factory=list)
    attacks: List[Dict] = field(default_factory=list)
    blocks: List[Dict] = field(default_factory=list)

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


