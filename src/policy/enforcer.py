import logging
import re
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from threading import Lock

logger = logging.getLogger(__name__)

_MAC_PREFIXES: Dict[str, str] = {
    "00:1A:11": "Google",
    "00:25:00": "Apple",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "00:15:5D": "Microsoft Hyper-V",
    "00:05:69": "Cisco",
    "00:1B:17": "Intel",
}


class IdentityPolicy:
    def __init__(self, name: str, allowed_ports: List[int], allowed_protocols: List[str],
                 max_connections: int = 100, time_restriction: Optional[Tuple[int, int]] = None):
        self.name = name
        self.allowed_ports = set(allowed_ports)
        self.allowed_protocols = set(allowed_protocols)
        self.max_connections = max_connections
        self.time_restriction = time_restriction

    def check(self, dst_port: int, protocol: str, hour: int) -> Tuple[bool, str]:
        if self.time_restriction:
            start, end = self.time_restriction
            if start <= end:
                if not (start <= hour <= end):
                    return False, f"outside allowed hours ({start}:00-{end}:00)"
            else:
                if not (hour >= start or hour <= end):
                    return False, f"outside allowed hours ({start}:00-{end}:00)"
        if dst_port and dst_port not in self.allowed_ports:
            return False, f"port {dst_port} not in allowed set"
        if protocol and protocol not in self.allowed_protocols:
            return False, f"protocol {protocol} not allowed"
        return True, ""


class ZeroTrustEnforcer:
    def __init__(self, config: dict = None):
        self._config = config or {}
        self._policies: Dict[str, IdentityPolicy] = {}
        self._device_map: Dict[str, str] = {}
        self._conn_counts: Dict[str, int] = defaultdict(int)
        self._lock = Lock()
        self._last_cleanup = time.time()
        self._load_default_policies()

    def _load_default_policies(self):
        default_port_sets = {
            "workstation": {80, 443, 22, 53, 123, 389, 636},
            "server": {80, 443, 22, 53, 25, 587, 993, 3306, 5432, 6379, 27017},
            "iot": {53, 123, 443, 8883},
            "admin": {22, 443, 9090, 8080},
        }
        for name, ports in default_port_sets.items():
            self._policies[name] = IdentityPolicy(
                name=name,
                allowed_ports=ports,
                allowed_protocols={"tcp", "udp"},
                max_connections=200 if name == "server" else 50 if name == "workstation" else 20,
                time_restriction=(0, 23) if name == "server" else (6, 22),
            )

    def add_policy(self, name: str, policy: IdentityPolicy):
        with self._lock:
            self._policies[name] = policy
            logger.info(f"[ZT] Added policy: {name}")

    def register_device(self, mac: str, policy_name: str):
        with self._lock:
            self._device_map[mac] = policy_name
            logger.info(f"[ZT] Registered {mac} → {policy_name}")

    def identify_device(self, mac: str) -> str:
        if mac in self._device_map:
            return self._device_map[mac]
        prefix = mac[:8].upper()
        vendor = _MAC_PREFIXES.get(prefix, "unknown")
        if vendor in ("VMware", "VirtualBox", "Microsoft Hyper-V"):
            return "server"
        return "workstation"

    def enforce(self, packet: Dict) -> Optional[Dict]:
        src_mac = packet.get("src_mac", "")
        dst_port = packet.get("dst_port", 0)
        protocol = packet.get("protocol", "")
        src_ip = packet.get("src_ip", "")
        now = time.time()
        hour = time.localtime(now).tm_hour

        if not src_mac:
            return None

        with self._lock:
            policy_name = self._device_map.get(src_mac) or self.identify_device(src_mac)
            policy = self._policies.get(policy_name)

            if not policy:
                return None

            self._conn_counts[src_mac] = self._conn_counts.get(src_mac, 0) + 1

            if self._conn_counts[src_mac] > policy.max_connections:
                return {
                    "attack_type": "zt_policy_violation",
                    "severity": "high",
                    "source_ip": src_ip,
                    "details": f"Device {src_mac} ({policy_name}) exceeded {policy.max_connections} connections",
                    "confidence": 0.8,
                    "mitre": [],
                }

            allowed, reason = policy.check(dst_port, protocol, hour)
            if not allowed:
                return {
                    "attack_type": "zt_policy_violation",
                    "severity": "medium",
                    "source_ip": src_ip,
                    "details": f"Device {src_mac} ({policy_name}) {reason}",
                    "confidence": 0.8,
                    "mitre": [],
                }

        return None

    def cleanup(self):
        if time.time() - self._last_cleanup > 300:
            with self._lock:
                cutoff = time.time() - 3600
                self._conn_counts = {k: v for k, v in self._conn_counts.items() if v > 0}
                self._last_cleanup = time.time()
