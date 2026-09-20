"""Centralized network interface detection."""

import os
import socket
import struct
import logging
import time

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


def all_local_ipv4() -> set:
    """Every IPv4 address configured on this host, from the kernel.

    ``local_ips()`` answers a different question: it returns the *primary egress*
    address (found by UDP-connecting to a public address) plus hostname
    addresses. On a single-NIC laptop those coincide, which is why the gap went
    unnoticed. On a box with a second NIC, a VLAN, a bridge or an alias — i.e. a
    gateway sensor, Class C of this project — the secondary addresses are simply
    absent from ``local_ips()``.

    That matters because ``protected_ips()`` is built from it: a host could
    block its own secondary address and take that segment down. Measured in the
    netns harness: with ``10.88.0.1`` on a veth, ``local_ips()`` did not contain
    it and the F4 guard let the block through.

    Read from /proc/net/fib_trie: world-readable, no subprocess, so it works
    under a hardened systemd unit.
    """
    addrs = set()
    try:
        with open("/proc/net/fib_trie") as f:
            for line in f:
                line = line.strip()
                # Interface entries look like:  |-- 203.0.113.10
                if not line.startswith("|-- "):
                    continue
                candidate = line[4:].strip()
                if not _is_ipv4(candidate):
                    continue
                # fib_trie also lists the subnet and broadcast addresses
                # (10.88.0.0 / 10.88.0.255) and the unspecified address. Those
                # are not *this host's* address, and 0.0.0.0 in particular must
                # never be treated as a thing worth protecting.
                if candidate.startswith("127.") or candidate == "0.0.0.0":
                    continue
                addrs.add(candidate)
    except OSError:
        logger.debug("[Interface] /proc/net/fib_trie not readable")
    return addrs


def _is_ipv4(addr: str) -> bool:
    """True for a dotted-quad IPv4 literal.

    The firewall only writes IPv4 rules, so the v6 addresses ``local_ips()``
    returns must not end up in the protected set as if they were blockable.
    """
    if not addr or ":" in addr:
        return False
    try:
        socket.inet_aton(addr)
    except OSError:
        return False
    return True


def default_gateway(route_file: str = "/proc/net/route") -> str:
    """IPv4 default gateway, or "" when there is no default route.

    Reads ``/proc/net/route`` instead of shelling out to ``ip route``: the file
    is world-readable, so this works under a hardened unit (``ProtectSystem=full``)
    and cannot fail because a binary is missing. Column 1 is the destination
    (all-zero means default) and column 2 is the gateway as little-endian hex.
    An all-zero gateway is an on-link route rather than a next hop, so it is
    not reported as a gateway. ``route_file`` is injectable for tests.
    """
    try:
        with open(route_file) as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) < 3 or parts[1] != "00000000":
                    continue
                gateway = socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
                if gateway != "0.0.0.0":
                    return gateway
    except (OSError, ValueError, struct.error):
        logger.debug("[Interface] default gateway not readable")
    return ""


def dns_servers(resolv_conf: str = "/etc/resolv.conf") -> list:
    """IPv4 nameservers from a resolv.conf, in order, deduplicated.

    ``resolv_conf`` is injectable for tests. IPv6 nameservers are skipped
    because the firewall only writes IPv4 rules.
    """
    servers = []
    try:
        with open(resolv_conf) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line.startswith("nameserver"):
                    continue
                parts = line.split()
                if len(parts) >= 2 and _is_ipv4(parts[1]) and parts[1] not in servers:
                    servers.append(parts[1])
    except OSError:
        logger.debug("[Interface] /etc/resolv.conf not readable")
    return servers


# --- self-protection (F4 in docs/PRODUCTION_READINESS.md) --------------------
# The addresses this host must never block. Blocking its own address, its
# default gateway or its resolver is a self-inflicted outage: the operator
# loses the network LIDRA is defending and, on a headless box, may have no way
# back in to undo it. Cached because the answer changes slowly and
# ``local_ips()`` resolves the hostname, which is a blocking call that must not
# sit on the verdict path.
_PROTECTED_TTL_SECONDS = 60
_protected_cache = (0.0, frozenset())


def protected_ips(refresh: bool = False) -> frozenset:
    """Addresses that must never be blocked: our own + gateway + resolvers."""
    global _protected_cache
    cached_at, cached = _protected_cache
    if not refresh and cached and (time.monotonic() - cached_at) < _PROTECTED_TTL_SECONDS:
        return cached

    ips = {ip for ip in local_ips() if _is_ipv4(ip)}
    # Every configured IPv4 address, not just the primary egress one — a second
    # NIC/alias/bridge must never be blockable (see all_local_ipv4).
    ips |= all_local_ipv4()
    gateway = default_gateway()
    if gateway:
        ips.add(gateway)
    ips.update(dns_servers())

    protected = frozenset(ips)
    _protected_cache = (time.monotonic(), protected)
    return protected


def invalidate_protected_ips_cache() -> None:
    """Drop the cache — for tests, and for a network change (see S3)."""
    global _protected_cache
    _protected_cache = (0.0, frozenset())


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
