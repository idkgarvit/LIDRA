"""Centralized network interface detection."""

import os
import socket
import struct
import logging

logger = logging.getLogger(__name__)


def detect_interface(preferred: str = None) -> str:
    """Auto-detect the active network interface.

    Priority:
       1. LIDRA_INTERFACE env var (from CLI --interface flag)
       2. preferred argument (from config)
       3. Default route interface (/proc/net/route)
       4. First non-loopback interface (ioctl)
       5. Raises RuntimeError if nothing found
    """
    env_iface = os.environ.get("LIDRA_INTERFACE")
    if env_iface:
        preferred = env_iface
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
        logger.debug(f"[Interface] /proc/net/dev not readable for {name}")
    try:
        import fcntl
        sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        buf = struct.pack("256s", name.encode()[:15])
        fcntl.ioctl(sck, 0x8927, buf)
        sck.close()
        return True
    except Exception:
        logger.debug(f"[Interface] ioctl SIOCGIFADDR failed for {name}")
        return False


def local_ips() -> set:
    """All local addresses, v4 + v6 (primary egress + hostname addrs).

    Used to skip our own egress traffic in detectors — without this the
    sensor flags its own DNS/HTTPS as attacks on external IPs.
    """
    ips = set()
    try:  # primary egress IP (UDP connect sends no traffic)
        sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sck.connect(("8.8.8.8", 80))
        ips.add(sck.getsockname()[0])
        sck.close()
    except OSError:
        pass
    try:  # ponytail: same trick for v6 — without it every solicited v6
        # flow looks foreign (most laptop web traffic is v6).
        sck = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sck.connect(("2001:4860:4860::8888", 80))
        ips.add(sck.getsockname()[0])
        sck.close()
    except OSError:
        pass
    try:
        for fam, _, _, _, addr in socket.getaddrinfo(socket.gethostname(), None):
            # ponytail: never trust hostname -> 127.x (docker build sandbox,
            # minimal VPS /etc/hosts). Loopback attacks are real signal —
            # the pipeline inspects 127/8 by design, so it must not land here.
            if fam == socket.AF_INET and not addr[0].startswith("127."):
                ips.add(addr[0])
            elif fam == socket.AF_INET6 and not addr[0].split("%")[0].startswith(("::1", "fe80:")):
                ips.add(addr[0].split("%")[0])
    except OSError:
        pass
    return ips


def _default_route_interface() -> str:
    """Read default route from /proc/net/route to find the active interface."""
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[1] == "00000000" and parts[3] == "0003":
                    return parts[0]
    except OSError:
        logger.debug("[Interface] /proc/net/route not readable")
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
        n = struct.unpack("I", buf[16:20])[0]
        for i in range(n):
            ifname = buf[i * 32:(i + 1) * 32].split(b"\x00")[0].decode(errors="replace")
            if ifname and ifname != "lo":
                return ifname
    except Exception:
        logger.debug("[Interface] ioctl SIOCGIFCONF failed")
    return None
