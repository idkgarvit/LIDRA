from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)


class BridgeSetupError(RuntimeError):
    pass


class BridgePermissionError(BridgeSetupError):
    pass


class BridgeCommandNotFound(BridgeSetupError):
    pass


@dataclass
class CommandResult:
    success: bool
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    message: str = ""

    def to_dict(self) -> Dict:
        return {
            "success": self.success,
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "message": self.message,
        }


@dataclass
class BridgeStatus:
    name: str
    exists: bool
    is_up: bool
    state: str
    members: List[str] = field(default_factory=list)
    addresses: List[str] = field(default_factory=list)
    forwarding: bool = False
    raw: str = ""

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "exists": self.exists,
            "is_up": self.is_up,
            "state": self.state,
            "members": list(self.members),
            "addresses": list(self.addresses),
            "forwarding": self.forwarding,
            "raw": self.raw,
        }


def _have_root() -> bool:
    return os.geteuid() == 0


def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def _run(cmd: Sequence[str], check: bool = False, timeout: float = 10.0) -> CommandResult:
    cmd_list = list(cmd)
    logger.debug(f"[BridgeSetup] Running: {' '.join(cmd_list)}")
    try:
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        msg = f"Command not found: {cmd_list[0]}"
        logger.error(f"[BridgeSetup] {msg}")
        raise BridgeCommandNotFound(msg) from exc
    except subprocess.TimeoutExpired as exc:
        msg = f"Command timed out after {timeout}s: {' '.join(cmd_list)}"
        logger.error(f"[BridgeSetup] {msg}")
        return CommandResult(
            success=False,
            command=cmd_list,
            returncode=-1,
            stdout="",
            stderr=str(exc),
            message=msg,
        )

    out = (result.stdout or "").strip()
    err = (result.stderr or "").strip()
    success = result.returncode == 0
    if not success:
        logger.warning(
            f"[BridgeSetup] Command failed (rc={result.returncode}): "
            f"{' '.join(cmd_list)} — {err}"
        )
    if check and not success:
        raise BridgeSetupError(
            f"Command failed (rc={result.returncode}): {' '.join(cmd_list)} — {err}"
        )
    return CommandResult(
        success=success,
        command=cmd_list,
        returncode=result.returncode,
        stdout=out,
        stderr=err,
    )


def _ip_cmd() -> str:
    ip_path = _which("ip")
    if not ip_path:
        msg = "`ip` command not found. Install iproute2."
        logger.error(f"[BridgeSetup] {msg}")
        raise BridgeCommandNotFound(msg)
    return ip_path


def _nft_or_iptables() -> str:
    if _which("nft"):
        return "nft"
    if _which("iptables"):
        return "iptables"
    msg = "Neither `nft` nor `iptables` found. Install nftables or iptables."
    logger.error(f"[BridgeSetup] {msg}")
    raise BridgeCommandNotFound(msg)


def _bridge_exists(bridge_name: str) -> bool:
    ip = _ip_cmd()
    res = _run([ip, "-d", "link", "show", bridge_name], check=False)
    if not res.success:
        return False
    return "bridge" in res.stdout


def _interface_exists(name: str) -> bool:
    return Path(f"/sys/class/net/{name}").exists()


def _interface_is_in_bridge(name: str, bridge_name: str) -> bool:
    master_path = Path(f"/sys/class/net/{name}/master")
    if not master_path.exists():
        return False
    try:
        target = master_path.resolve()
        return target.name == bridge_name
    except OSError:
        return False


def _read_sysctl(path: str) -> Optional[str]:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def create_bridge(
    wan_iface: str,
    lan_iface: str,
    bridge_name: str = "br_lidra",
) -> bool:
    if not _have_root():
        raise BridgePermissionError(
            "create_bridge() requires root privileges (euid=0)."
        )
    if not wan_iface or not lan_iface:
        raise BridgeSetupError("Both wan_iface and lan_iface are required.")
    if wan_iface == lan_iface:
        raise BridgeSetupError(
            f"wan_iface and lan_iface must differ (got {wan_iface!r})."
        )

    for name in (wan_iface, lan_iface):
        if not _interface_exists(name):
            raise BridgeSetupError(f"Interface {name!r} does not exist.")

    ip = _ip_cmd()

    if _bridge_exists(bridge_name):
        logger.info(
            f"[BridgeSetup] {bridge_name} already exists; verifying members."
        )
        for iface in (wan_iface, lan_iface):
            if not _interface_is_in_bridge(iface, bridge_name):
                _run([ip, "link", "set", iface, "master", bridge_name], check=True)
                _run([ip, "link", "set", iface, "up"], check=False)
        _run([ip, "link", "set", bridge_name, "up"], check=False)
        return True

    logger.info(
        f"[BridgeSetup] Creating bridge {bridge_name} with WAN={wan_iface}, LAN={lan_iface}"
    )

    add = _run(
        [ip, "link", "add", "name", bridge_name, "type", "bridge"],
        check=False,
    )
    if not add.success:
        if "File exists" in add.stderr or "exists" in add.stderr.lower():
            logger.debug(f"[BridgeSetup] {bridge_name} appeared concurrently.")
        else:
            raise BridgeSetupError(
                f"Failed to create bridge {bridge_name}: {add.stderr}"
            )

    for iface in (wan_iface, lan_iface):
        _run([ip, "link", "set", iface, "down"], check=False)
        _run([ip, "link", "set", iface, "master", bridge_name], check=True)
        _run([ip, "link", "set", iface, "up"], check=False)

    up = _run([ip, "link", "set", bridge_name, "up"], check=False)
    if not up.success:
        raise BridgeSetupError(
            f"Failed to bring {bridge_name} up: {up.stderr}"
        )

    logger.info(f"[BridgeSetup] {bridge_name} created and up.")
    return True


def setup_forwarding_rules(
    bridge_name: str = "br_lidra",
    queue_num: int = 0,
    *,
    enable_ip_forward: bool = True,
    enable_nat: bool = False,
    wan_iface: Optional[str] = None,
    lan_iface: Optional[str] = None,
) -> bool:
    if not _have_root():
        raise BridgePermissionError(
            "setup_forwarding_rules() requires root privileges (euid=0)."
        )

    ok = True

    if enable_ip_forward:
        ipv4 = "/proc/sys/net/ipv4/ip_forward"
        if Path(ipv4).exists():
            current = _read_sysctl(ipv4)
            if current != "1":
                res = _run(
                    ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                    check=False,
                    timeout=5.0,
                )
                if res.success:
                    logger.info("[BridgeSetup] net.ipv4.ip_forward=1")
                else:
                    logger.warning(
                        f"[BridgeSetup] Could not enable ip_forward: {res.stderr}"
                    )
                    ok = False
            else:
                logger.debug("[BridgeSetup] ip_forward already enabled.")
        else:
            logger.warning(
                f"[BridgeSetup] {ipv4} missing — kernel built without IP forwarding?"
            )

    nat = _nft_or_iptables()
    if nat == "nft":
        ok &= _setup_forwarding_nft(bridge_name, queue_num)
        if enable_nat and wan_iface and lan_iface:
            ok &= _setup_nat_nft(wan_iface, lan_iface)
    else:
        ok &= _setup_forwarding_iptables(bridge_name, queue_num)
        if enable_nat and wan_iface and lan_iface:
            ok &= _setup_nat_iptables(wan_iface, lan_iface)

    return ok


def _setup_forwarding_nft(bridge_name: str, queue_num: int) -> bool:
    table = "lidra_bridge"
    chain = "lidra_forward"
    logger.info(f"[BridgeSetup] nftables FORWARD chain for {bridge_name} (queue {queue_num})")
    cmds = [
        ["nft", "add", "table", "bridge", table],
        [
            "nft", "add", "chain", "bridge", table, chain,
            "{ type filter hook forward priority filter; policy accept; }",
        ],
        ["nft", "flush", "chain", "bridge", table, chain],
        [
            "nft", "add", "rule", "bridge", table, chain,
            "queue", f"num {queue_num}", "bypass",
        ],
    ]
    for cmd in cmds:
        res = _run(cmd, check=False)
        if not res.success:
            logger.error(
                f"[BridgeSetup] nft command failed: {' '.join(cmd)} — {res.stderr}"
            )
            return False
    return True


def _setup_forwarding_iptables(bridge_name: str, queue_num: int) -> bool:
    logger.info(
        f"[BridgeSetup] iptables FORWARD chain for {bridge_name} (queue {queue_num})"
    )
    rules = [
        [
            "iptables", "-A", "FORWARD",
            "-m", "physdev", "--physdev-in", bridge_name,
            "-m", "state", "--state", "ESTABLISHED,RELATED",
            "-j", "ACCEPT",
        ],
        [
            "iptables", "-A", "FORWARD",
            "-m", "physdev", "--physdev-out", bridge_name,
            "-m", "state", "--state", "ESTABLISHED,RELATED",
            "-j", "ACCEPT",
        ],
        [
            "iptables", "-A", "FORWARD",
            "-m", "physdev", "--physdev-in", bridge_name,
            "-j", "NFQUEUE", "--queue-num", str(queue_num), "--queue-bypass",
        ],
    ]
    for rule in rules:
        res = _run(rule, check=False)
        if not res.success:
            logger.error(
                f"[BridgeSetup] iptables rule failed: {' '.join(rule)} — {res.stderr}"
            )
            return False
    return True


def _setup_nat_nft(wan_iface: str, lan_iface: str) -> bool:
    table = "lidra_nat"
    logger.info(f"[BridgeSetup] nftables NAT (masquerade) {lan_iface} -> {wan_iface}")
    cmds = [
        ["nft", "add", "table", "ip", table],
        [
            "nft", "add", "chain", "ip", table, "postrouting",
            "{ type nat hook postrouting priority srcnat; policy accept; }",
        ],
        [
            "nft", "add", "rule", "ip", table, "postrouting",
            "oifname", wan_iface, "masquerade",
        ],
    ]
    for cmd in cmds:
        res = _run(cmd, check=False)
        if not res.success and "already exists" not in res.stderr:
            logger.warning(
                f"[BridgeSetup] nft NAT command failed: {' '.join(cmd)} — {res.stderr}"
            )
            return False
    return True


def _setup_nat_iptables(wan_iface: str, lan_iface: str) -> bool:
    res = _run(
        [
            "iptables", "-t", "nat", "-A", "POSTROUTING",
            "-o", wan_iface, "-j", "MASQUERADE",
        ],
        check=False,
    )
    if not res.success and "already exists" not in res.stderr:
        logger.warning(
            f"[BridgeSetup] iptables NAT rule failed: {res.stderr}"
        )
        return False
    return True


def teardown_bridge(bridge_name: str = "br_lidra") -> bool:
    if not _have_root():
        raise BridgePermissionError(
            "teardown_bridge() requires root privileges (euid=0)."
        )
    ip = _ip_cmd()

    if not _bridge_exists(bridge_name):
        logger.info(f"[BridgeSetup] {bridge_name} not present — nothing to tear down.")
        return True

    logger.info(f"[BridgeSetup] Tearing down {bridge_name}")
    _run([ip, "link", "set", bridge_name, "down"], check=False)

    members = _list_bridge_members(bridge_name)
    for iface in members:
        _run([ip, "link", "set", iface, "nomaster"], check=False)

    res = _run([ip, "link", "delete", bridge_name], check=False)
    if not res.success and "Cannot find device" not in res.stderr:
        logger.warning(
            f"[BridgeSetup] Failed to delete {bridge_name}: {res.stderr}"
        )
        return False
    return True


def _list_bridge_members(bridge_name: str) -> List[str]:
    ip = _ip_cmd()
    res = _run([ip, "-d", "link", "show", bridge_name], check=False)
    members: List[str] = []
    if not res.success:
        return members
    for line in res.stdout.splitlines():
        if "master " + bridge_name in line:
            parts = line.split(":")
            if len(parts) >= 2:
                members.append(parts[1].strip().split(" ")[0])
    return members


def _list_bridge_addresses(bridge_name: str) -> List[str]:
    ip = _ip_cmd()
    res = _run([ip, "addr", "show", bridge_name], check=False)
    addresses: List[str] = []
    if not res.success:
        return addresses
    for line in res.stdout.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            addresses.append(line.split()[1])
    return addresses


def bridge_status(bridge_name: str = "br_lidra") -> BridgeStatus:
    ip = None
    try:
        ip = _ip_cmd()
    except BridgeCommandNotFound as exc:
        logger.warning(f"[BridgeSetup] {exc}")
        return BridgeStatus(
            name=bridge_name,
            exists=False,
            is_up=False,
            state="missing-ip",
            raw=str(exc),
        )

    res = _run([ip, "-d", "link", "show", bridge_name], check=False)
    if not res.success:
        return BridgeStatus(
            name=bridge_name,
            exists=False,
            is_up=False,
            state="absent",
            raw=res.stderr or res.stdout,
        )

    raw = res.stdout
    is_up = "state UP" in raw
    state = "UNKNOWN"
    for token in ("state UP", "state DOWN", "state UNKNOWN", "state UNKNOWN"):
        if token in raw:
            state = token.split()[1]
            break

    members = _list_bridge_members(bridge_name)
    addresses = _list_bridge_addresses(bridge_name)

    fwd = _read_sysctl("/proc/sys/net/ipv4/ip_forward")
    forwarding = fwd == "1"

    return BridgeStatus(
        name=bridge_name,
        exists=True,
        is_up=is_up,
        state=state,
        members=members,
        addresses=addresses,
        forwarding=forwarding,
        raw=raw,
    )


def is_bridge_up(bridge_name: str = "br_lidra") -> bool:
    try:
        status = bridge_status(bridge_name)
    except BridgeSetupError:
        return False
    return status.exists and status.is_up


def has_forwarding() -> bool:
    return _read_sysctl("/proc/sys/net/ipv4/ip_forward") == "1"
