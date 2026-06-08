"""Zero-config auto-detection layer for any Linux distro."""

from __future__ import annotations

import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


_DISTRO_FAMILY_PKG = {
    "debian": "apt",
    "rhel": "dnf",
    "arch": "pacman",
    "suse": "zypper",
    "alpine": "apk",
}

_LOG_CANDIDATES = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/messages",
    "/var/log/syslog",
    "/var/log/kern.log",
]


@dataclass
class DistroInfo:
    family: str = "unknown"
    name: str = "unknown"
    version: str = "unknown"
    version_id: str = ""
    init: str = "unknown"
    pkg_manager: str = "unknown"
    id_like: str = ""
    pretty_name: str = ""

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


@dataclass
class Capabilities:
    iptables: bool = False
    nftables: bool = False
    bcc: bool = False
    docker: bool = False
    systemctl: bool = False
    journalctl: bool = False
    ethtool: bool = False
    libpcap: bool = False

    def to_dict(self) -> Dict[str, bool]:
        return asdict(self)


@dataclass
class LogSources:
    files: List[str] = field(default_factory=list)
    journalctl: bool = False
    preferred: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"files": self.files, "journalctl": self.journalctl, "preferred": self.preferred}


@dataclass
class NetworkInfo:
    interface: str = ""
    ip: str = ""
    mac: str = ""
    gateway: str = ""
    netmask: str = ""

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


@dataclass
class SystemInfo:
    hostname: str = ""
    kernel: str = ""
    arch: str = ""
    python: str = ""
    python_path: str = ""
    user: str = ""
    is_root: bool = False
    uid: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _read_os_release() -> Dict[str, str]:
    data: Dict[str, str] = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    val = val.strip().strip('"').strip("'")
                    data[key] = val
            if data:
                return data
        except OSError as e:
            logger.debug(f"Could not read {path}: {e}")
    return data


def _classify_distro(os_data: Dict[str, str]) -> str:
    distro_id = (os_data.get("ID") or "").lower()
    id_like = (os_data.get("ID_LIKE") or "").lower()

    for candidate in (distro_id, *id_like.split()):
        candidate = candidate.strip()
        if not candidate:
            continue
        if candidate in (
            "debian", "ubuntu", "linuxmint", "elementary", "pop", "kali",
            "parrot", "raspbian", "deepin", "zorin", "mx",
        ):
            return "debian"
        if candidate in (
            "rhel", "centos", "fedora", "rocky", "almalinux", "ol",
            "openEuler", "amzn", "amazon", "virtuozzo", "cloudlinux",
        ):
            return "rhel"
        if candidate in ("arch", "manjaro", "endeavouros", "arcolinux", "garuda"):
            return "arch"
        if candidate in ("suse", "opensuse", "sles", "sled"):
            return "suse"
        if candidate in ("alpine",):
            return "alpine"
    return "unknown"


def _detect_pkg_manager(family: str) -> str:
    if family in _DISTRO_FAMILY_PKG:
        candidate = _DISTRO_FAMILY_PKG[family]
        if shutil.which(candidate):
            return candidate
    for pm in ("apt", "dnf", "yum", "pacman", "zypper", "apk"):
        if shutil.which(pm):
            return pm
    return "unknown"


def _detect_init() -> str:
    if os.path.isdir("/run/systemd/system") or os.path.exists("/etc/systemd"):
        return "systemd"
    if shutil.which("systemctl") and os.path.isdir("/run/systemd"):
        return "systemd"
    if os.path.isdir("/run/openrc") or shutil.which("rc-service"):
        return "openrc"
    try:
        with open("/proc/1/comm", "r") as f:
            comm = f.read().strip().lower()
    except OSError:
        comm = ""
    if comm == "systemd":
        return "systemd"
    if comm == "runit":
        return "runit"
    if comm in ("init", "sysvinit"):
        return "sysvinit"
    if comm == "openrc-init":
        return "openrc"
    return "unknown"


def detect_distro() -> Dict[str, str]:
    """Detect distro, init system, and package manager.

    Returns a dict with keys: family, name, version, version_id, init,
    pkg_manager, id_like, pretty_name.
    """
    os_data = _read_os_release()
    family = _classify_distro(os_data)
    info = DistroInfo(
        family=family,
        name=os_data.get("ID", "unknown") or "unknown",
        version=os_data.get("VERSION", "unknown") or "unknown",
        version_id=os_data.get("VERSION_ID", "") or "",
        init=_detect_init(),
        pkg_manager=_detect_pkg_manager(family),
        id_like=os_data.get("ID_LIKE", "") or "",
        pretty_name=os_data.get("PRETTY_NAME", "") or "",
    )
    return info.to_dict()


def detect_log_sources() -> List[str]:
    """Return ordered list of usable log sources.

    journalctl is prepended when available, followed by existing files
    in priority order: auth.log, secure, messages, syslog, kern.log.
    """
    files: List[str] = []
    for path in _LOG_CANDIDATES:
        if os.path.exists(path) and os.access(path, os.R_OK):
            files.append(path)
    journalctl_available = bool(shutil.which("journalctl"))
    ordered: List[str] = []
    if journalctl_available:
        ordered.append("journalctl")
    ordered.extend(files)
    return ordered


def _check_python_module(name: str) -> bool:
    try:
        import importlib.util
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def detect_capabilities() -> Dict[str, bool]:
    """Detect available system capabilities and Python modules."""
    caps = Capabilities(
        iptables=bool(shutil.which("iptables")),
        nftables=bool(shutil.which("nft")),
        bcc=_check_python_module("bcc"),
        docker=bool(shutil.which("docker")),
        systemctl=bool(shutil.which("systemctl")),
        journalctl=bool(shutil.which("journalctl")),
        ethtool=bool(shutil.which("ethtool")),
        libpcap=_check_python_module("dpkt") or _check_python_module("scapy"),
    )
    return caps.to_dict()


def _detect_network_info() -> NetworkInfo:
    info = NetworkInfo()
    try:
        from utils.interface import detect_interface
        info.interface = detect_interface()
    except Exception as e:
        logger.debug(f"[distro_detect] detect_interface failed: {e}")
        info.interface = ""

    if not info.interface:
        return info

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        import fcntl
        import struct as _struct
        ifname = info.interface.encode()[:15]
        try:
            buf = _struct.pack("256s", ifname)
            res = fcntl.ioctl(sock, 0x8927, buf)
            info.ip = socket.inet_ntoa(res[20:24])
        except OSError:
            pass
        try:
            buf = _struct.pack("256s", ifname)
            res = fcntl.ioctl(sock, 0x891B, buf)
            info.mac = ":".join(f"{b:02x}" for b in res[18:24])
        except OSError:
            pass
        try:
            buf = _struct.pack("256s", ifname)
            res = fcntl.ioctl(sock, 0x891C, buf)
            netmask = socket.inet_ntoa(res[20:24])
            info.netmask = netmask
        except OSError:
            pass
    except Exception as e:
        logger.debug(f"[distro_detect] ioctl failed: {e}")
    finally:
        sock.close()

    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[1] == "00000000" and parts[3] == "0003":
                    gw_hex = parts[2]
                    info.gateway = ".".join(
                        str(int(gw_hex[i:i + 2], 16)) for i in (6, 4, 2, 0)
                    )
                    break
    except OSError:
        pass

    return info


def _detect_system_info() -> SystemInfo:
    uid = os.getuid() if hasattr(os, "getuid") else 0
    return SystemInfo(
        hostname=socket.gethostname(),
        kernel=platform.release(),
        arch=platform.machine(),
        python=platform.python_version(),
        python_path=sys.executable,
        user=os.environ.get("USER", "") or os.environ.get("LOGNAME", ""),
        is_root=(uid == 0),
        uid=uid,
    )


def detect_all() -> Dict[str, Any]:
    """Run all detection and return a combined report."""
    distro = detect_distro()
    caps = detect_capabilities()
    logs = detect_log_sources()
    sys_info = _detect_system_info().to_dict()
    net_info = _detect_network_info().to_dict()

    log_struct = LogSources(
        files=[s for s in logs if s != "journalctl"],
        journalctl="journalctl" in logs,
        preferred=logs,
    )

    return {
        "system": sys_info,
        "distro": distro,
        "network": net_info,
        "logs": log_struct.to_dict(),
        "capabilities": caps,
        "issues": _collect_issues(distro, caps, net_info, logs, sys_info),
    }


def _collect_issues(
    distro: Dict[str, str],
    caps: Dict[str, bool],
    net: Dict[str, str],
    logs: List[str],
    sys_info: Dict[str, Any],
) -> List[Dict[str, str]]:
    issues: List[Dict[str, str]] = []

    if distro.get("family") == "unknown":
        issues.append({
            "level": "warning",
            "code": "distro_unknown",
            "message": "Could not classify distro; package manager auto-detect may be unreliable",
        })
    if not caps.get("bcc"):
        issues.append({
            "level": "info",
            "code": "bcc_missing",
            "message": "No python-bcc module — falling back to log-based detection (recommended install)",
        })
    if not caps.get("iptables") and not caps.get("nftables"):
        issues.append({
            "level": "error",
            "code": "no_firewall",
            "message": "Neither iptables nor nftables found — response module will be non-functional",
        })
    if not net.get("interface"):
        issues.append({
            "level": "error",
            "code": "no_interface",
            "message": "No network interface could be auto-detected",
        })
    if not logs:
        issues.append({
            "level": "error",
            "code": "no_logs",
            "message": "No log sources found — install rsyslog/journald or point to custom paths in config",
        })
    if sys_info.get("is_root"):
        issues.append({
            "level": "warning",
            "code": "running_as_root",
            "message": "Running as root — required for AF_PACKET/NFQUEUE, but consider a dedicated low-priv user + caps",
        })
    if not caps.get("systemctl") and distro.get("init") == "systemd":
        issues.append({
            "level": "warning",
            "code": "systemctl_missing",
            "message": "Distro uses systemd but systemctl is not on PATH",
        })
    return issues


__all__ = [
    "DistroInfo",
    "Capabilities",
    "LogSources",
    "NetworkInfo",
    "SystemInfo",
    "detect_distro",
    "detect_log_sources",
    "detect_capabilities",
    "detect_all",
]
