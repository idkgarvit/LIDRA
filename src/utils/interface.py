"""Centralized network interface detection."""

import os
import socket
import struct
import logging
import subprocess

logger = logging.getLogger(__name__)


def detect_interface(preferred: str = None) -> str:
    """Auto-detect the active network interface.

    Priority:
      1. preferred argument (from config)
      2. Default route interface (/proc/net/route)
      3. First non-loopback interface (ioctl)
      4. Raises RuntimeError if nothing found
    """
    if preferred:
        if _interface_exists(preferred):
            return preferred
        logger.warning(f"[Interface] Configured interface '{preferred}' not found, auto-detecting")

    route_iface = _default_route_interface()
    if route_iface:
        return route_iface

    detected = _first_non_loopback()
    if detected:
        logger.info(f"[Interface] Auto-detected: {detected}")
        return detected

    raise RuntimeError("No network interface found — check your network or configure interface in config.yaml")


def _interface_exists(name: str) -> bool:
    """Check if a network interface exists on this system."""
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if line.strip().startswith(name + ":"):
                    return True
    except OSError:
        pass
    try:
        import fcntl
        sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        buf = struct.pack("256s", name.encode()[:15])
        fcntl.ioctl(sck, 0x8927, buf)
        sck.close()
        return True
    except Exception:
        return False


def _default_route_interface() -> str:
    """Read default route from /proc/net/route to find the active interface."""
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[1] == "00000000" and parts[3] == "0003":
                    return parts[0]
    except OSError:
        pass
    return None


def _first_non_loopback() -> str:
    """Return the first non-loopback interface via ioctl."""
    try:
        import fcntl
        sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        MAX_IFACES = 32
        bufsize = MAX_IFACES * 32
        buf = os.urandom(bufsize)
        try:
            buf = fcntl.ioctl(sck, 0x8920, buf)
        except OSError:
            sck.close()
            return None
        sck.close()
        import array
        n = struct.unpack("I", buf[16:20])[0]
        for i in range(n):
            ifname = buf[i * 32:(i + 1) * 32].split(b"\x00")[0].decode(errors="replace")
            if ifname and ifname != "lo":
                return ifname
    except Exception:
        pass
    return None
