# src/response/firewall.py
"""Production firewall integration for LIDRA."""

import ipaddress
import subprocess
import logging
from typing import Optional, List
import re
import threading

logger = logging.getLogger(__name__)


_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _validate_ip(ip: str) -> str:
    """Validate and normalize an IP address. Raises ValueError on bad input."""
    if not isinstance(ip, str) or not ip:
        raise ValueError("IP must be a non-empty string")
    if not _IPV4_RE.match(ip):
        raise ValueError(f"Invalid IP format: {ip!r}")
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise ValueError(f"Invalid IPv4 address: {ip!r}") from exc
    if addr.is_multicast or addr.is_unspecified:
        raise ValueError(f"Refusing to block special-use IP: {ip}")
    if addr.is_loopback:
        raise ValueError(f"Refusing to block loopback: {ip}")
    return str(addr)


class FirewallManager:
    """Manages iptables/nftables firewall rules."""

    def __init__(self, backend: str = "iptables", dry_run: bool = False, config: dict = None):
        self.backend = backend
        self.dry_run = dry_run
        self._config = config or {}
        nft_cfg = self._config.get("nftables", {})
        self.chain = nft_cfg.get("block_chain", "LIDRA_BLOCK")
        self.NFT_TABLE = nft_cfg.get("table", "inet filter")
        self.NFT_BRIDGE_TABLE = nft_cfg.get("bridge_table", "lidra_bridge")
        self.NFT_BRIDGE_FORWARD_CHAIN = nft_cfg.get("bridge_forward_chain", "lidra_forward")
        self.NFT_BRIDGE_INPUT_CHAIN = nft_cfg.get("bridge_input_chain", "lidra_input")
        self._nft_lock = threading.Lock()
        self._use_nft = False
        if self.backend == "nftables" or (backend == "auto" and not self._has_iptables()):
            if self._has_nftables():
                self._use_nft = True
        if not dry_run:
            self._ensure_chain()

    def _ensure_chain(self):
        """Create LIDRA block chain if it doesn't exist; flush stale rules."""
        if self._use_nft:
            self._ensure_nft_chain()
        elif self._has_iptables():
            self._ensure_ipt_chain()
        else:
            logger.warning("No firewall backend available; skipping chain creation")

    def _ensure_ipt_chain(self):
        try:
            check = subprocess.run(
                ["iptables", "-L", self.chain, "-n"],
                capture_output=True, check=False
            )
            if check.returncode != 0:
                subprocess.run(["iptables", "-N", self.chain], check=False)
                subprocess.run(["iptables", "-I", "INPUT", "-j", self.chain], check=False)
                logger.info(f"Created iptables chain: {self.chain}")
            else:
                subprocess.run(["iptables", "-F", self.chain], check=False, capture_output=True)
                logger.debug(f"Flushed stale rules from existing chain: {self.chain}")
        except Exception as e:
            logger.warning(f"Could not ensure iptables chain: {e}")

    def _ensure_nft_chain(self):
        table, family = (self.NFT_TABLE.split(None, 1) + ["inet"])[:2]
        try:
            result = self._run_nft(["list", "chain", family, table, self.chain], check=False)
            if result.returncode == 0:
                self._run_nft(["flush", "chain", family, table, self.chain])
                logger.debug(f"Flushed nftables chain: {self.chain}")
            else:
                self._run_nft(["add", "chain", family, table, self.chain,
                               '{ type filter hook input priority 0; policy accept; }'])
                logger.info(f"Created nftables chain: {self.chain}")
        except Exception as e:
            logger.warning(f"Could not ensure nftables chain: {e}")

    @staticmethod
    def _has_iptables() -> bool:
        return subprocess.run(
            ["which", "iptables"], capture_output=True, check=False
        ).returncode == 0

    @staticmethod
    def _has_nftables() -> bool:
        return subprocess.run(
            ["which", "nft"], capture_output=True, check=False
        ).returncode == 0

    def block_ip(self, ip: str, ttl_seconds: int = 3600) -> bool:
        """Block an IP address. Idempotent — duplicate calls are no-ops."""
        try:
            ip = _validate_ip(ip)
        except ValueError as e:
            logger.error(f"Refusing to block invalid IP: {e}")
            return False
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would block {ip} for {ttl_seconds}s")
            return True

        if self._use_nft:
            return self._block_ip_nft(ip, ttl_seconds)
        return self._block_ip_ipt(ip, ttl_seconds)

    def _block_ip_ipt(self, ip: str, ttl_seconds: int) -> bool:
        try:
            check = subprocess.run(
                ["iptables", "-C", self.chain, "-s", ip, "-j", "DROP"],
                capture_output=True, check=False
            )
            if check.returncode == 0:
                logger.debug(f"[Firewall] {ip} already blocked in {self.chain}; skipping append")
                return True
            subprocess.run(
                ["iptables", "-A", self.chain, "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
            self._schedule_unblock(ip, ttl_seconds)
            logger.info(f"Blocked {ip} for {ttl_seconds}s")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block {ip}: {e}")
            return False
        except Exception as e:
            logger.error(f"Firewall error for {ip}: {e}")
            return False

    def _block_ip_nft(self, ip: str, ttl_seconds: int) -> bool:
        table, family = (self.NFT_TABLE.split(None, 1) + ["inet"])[:2]
        try:
            self._run_nft(["add", "rule", family, table, self.chain,
                           f"ip saddr {ip} drop"])
            self._schedule_unblock(ip, ttl_seconds)
            logger.info(f"Blocked {ip} for {ttl_seconds}s (nftables)")
            return True
        except Exception as e:
            logger.error(f"Failed to block {ip} via nftables: {e}")
            return False

    def _schedule_unblock(self, ip: str, ttl_seconds: int):
        """Schedule IP unblock after TTL using timer."""
        threading.Timer(ttl_seconds, self._unblock_ip, args=[ip]).start()

    def _unblock_ip(self, ip: str):
        """Remove block rule for IP."""
        try:
            ip = _validate_ip(ip)
        except ValueError as e:
            logger.error(f"Refusing to unblock invalid IP: {e}")
            return
        if self._use_nft:
            self._unblock_ip_nft(ip)
        else:
            self._unblock_ip_ipt(ip)

    def _unblock_ip_ipt(self, ip: str):
        try:
            subprocess.run(
                ["iptables", "-D", self.chain, "-s", ip, "-j", "DROP"],
                check=False, capture_output=True
            )
            logger.info(f"Unblocked {ip} (TTL expired)")
        except Exception as e:
            logger.error(f"Failed to unblock {ip}: {e}")

    def _unblock_ip_nft(self, ip: str):
        table, family = (self.NFT_TABLE.split(None, 1) + ["inet"])[:2]
        try:
            result = self._run_nft(["--handle", "list", "chain", family, table, self.chain],
                                   check=True)
            for line in result.stdout.split("\n"):
                if ip in line and "drop" in line:
                    m = re.search(r"handle\s+(\d+)", line)
                    if m:
                        self._run_nft(["delete", "rule", family, table, self.chain,
                                       f"handle {m.group(1)}"])
                        logger.info(f"Unblocked {ip} via nftables (TTL expired)")
                        return
            logger.debug(f"No nftables rule found for {ip}")
        except Exception as e:
            logger.error(f"Failed to unblock {ip} via nftables: {e}")

    def unblock_ip(self, ip: str) -> bool:
        """Manually unblock an IP."""
        try:
            ip = _validate_ip(ip)
        except ValueError as e:
            logger.error(f"Refusing to unblock invalid IP: {e}")
            return False
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would unblock {ip}")
            return True

        if self._use_nft:
            self._unblock_ip_nft(ip)
        else:
            try:
                subprocess.run(
                    ["iptables", "-D", self.chain, "-s", ip, "-j", "DROP"],
                    check=False, capture_output=True
                )
                logger.info(f"Manually unblocked {ip}")
                return True
            except Exception as e:
                logger.error(f"Failed to unblock {ip}: {e}")
                return False

    def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        if self.dry_run:
            return False

        if self._use_nft:
            return self._is_blocked_nft(ip)

        try:
            result = subprocess.run(
                ["iptables", "-L", self.chain, "-n", "--line-numbers"],
                capture_output=True, text=True, check=False
            )
            return ip in result.stdout
        except Exception:
            return False

    def _is_blocked_nft(self, ip: str) -> bool:
        table, family = (self.NFT_TABLE.split(None, 1) + ["inet"])[:2]
        try:
            result = self._run_nft(["--handle", "list", "chain", family, table, self.chain],
                                   check=True)
            return ip in result.stdout
        except Exception:
            return False

    def list_blocks(self) -> List[str]:
        """List all currently blocked IPs."""
        if self.dry_run:
            return []

        if self._use_nft:
            return self._list_blocks_nft()

        try:
            result = subprocess.run(
                ["iptables", "-L", self.chain, "-n"],
                capture_output=True, text=True, check=False
            )
            blocked = []
            for line in result.stdout.split('\n'):
                if 'DROP' in line:
                    parts = line.split()
                    for part in parts:
                        if self._is_ip(part):
                            blocked.append(part)
            return blocked
        except Exception:
            return []

    def _list_blocks_nft(self) -> List[str]:
        table, family = (self.NFT_TABLE.split(None, 1) + ["inet"])[:2]
        try:
            result = self._run_nft(["--handle", "list", "chain", family, table, self.chain],
                                   check=True)
            blocked = []
            for line in result.stdout.split("\n"):
                if "drop" in line:
                    m = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line)
                    if m:
                        blocked.append(m.group(1))
            return blocked
        except Exception:
            return []

    def _is_ip(self, s: str) -> bool:
        """Check if string is an IP address."""
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s))

    # --- Bridge / nftables methods ---

    def _run_nft(self, args: list, check: bool = True) -> subprocess.CompletedProcess:
        cmd = ["nft"] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=15)
            return result
        except subprocess.TimeoutExpired:
            logger.error(f"nft command timed out: {' '.join(cmd)}")
            raise
        except FileNotFoundError:
            logger.error("nftables (nft) command not found")
            raise

    def setup_bridge_nftables(self, bridge_name: str, queue_num: int = 0):
        if self.dry_run:
            logger.info("[DRY-RUN] Would set up bridge nftables table/chain")
            return
        with self._nft_lock:
            # Ensure table exists (no-op if already exists)
            self._run_nft(["add", "table", "bridge", self.NFT_BRIDGE_TABLE], check=False)
            # Ensure chain exists (no-op if already exists)
            self._run_nft([
                "add", "chain", "bridge", self.NFT_BRIDGE_TABLE, self.NFT_BRIDGE_FORWARD_CHAIN,
                "{ type filter hook forward priority filter; policy accept; }"
            ], check=False)
            # Flush chain to remove stale rules (idempotent — safe on restart/rerun)
            self._run_nft([
                "flush", "chain", "bridge", self.NFT_BRIDGE_TABLE, self.NFT_BRIDGE_FORWARD_CHAIN,
            ], check=False)
            # Add the NFQUEUE verdict rule with bypass
            self._run_nft([
                "add", "rule", "bridge", self.NFT_BRIDGE_TABLE, self.NFT_BRIDGE_FORWARD_CHAIN,
                "queue", f"num {queue_num}", "bypass"
            ], check=False)
        logger.info(f"[Firewall] Bridge nftables ready → NFQUEUE {queue_num} (queue-bypass enabled)")

    def teardown_bridge_nftables(self):
        if self.dry_run:
            logger.info("[DRY-RUN] Would tear down bridge nftables")
            return
        self._run_nft(["delete", "table", "bridge", self.NFT_BRIDGE_TABLE], check=False)
        logger.info("[Firewall] Bridge nftables removed")

    def bridge_block_ip(self, ip: str):
        try:
            ip = _validate_ip(ip)
        except ValueError as e:
            logger.error(f"Refusing to bridge-block invalid IP: {e}")
            return
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would add bridge drop rule for {ip}")
            return
        with self._nft_lock:
            self._run_nft([
                "insert", "rule", "bridge", self.NFT_BRIDGE_TABLE, self.NFT_BRIDGE_FORWARD_CHAIN,
                "ip", "saddr", ip, "drop"
            ], check=False)
        logger.info(f"[Firewall] Bridge block {ip}")

    def bridge_unblock_ip(self, ip: str):
        try:
            ip = _validate_ip(ip)
        except ValueError as e:
            logger.error(f"Refusing to bridge-unblock invalid IP: {e}")
            return
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would remove bridge drop rule for {ip}")
            return
        with self._nft_lock:
            # Remove ALL rules matching this IP (handle duplicate rules from crash recovery)
            while True:
                handle = self._find_bridge_rule_handle(ip)
                if not handle:
                    break
                self._run_nft([
                    "delete", "rule", "bridge", self.NFT_BRIDGE_TABLE,
                    self.NFT_BRIDGE_FORWARD_CHAIN, f"handle {handle}"
                ], check=False)
        logger.info(f"[Firewall] Bridge unblock {ip}")

    # --- Local mode (same-machine) iptables methods ---

    def setup_local_iptables(self, queue_num: int = 0):
        """Add NFQUEUE rule for local mode — only TCP, with --queue-bypass.

        Uses NEW,ESTABLISHED so HTTP request payloads (not just SYN) reach
        the DPI engine. UDP/ICMP pass through untouched.
        """
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would add iptables INPUT NFQUEUE rule (queue {queue_num})")
            return
        try:
            # First, flush any orphaned LIDRA NFQUEUE rules to prevent duplicates
            self._flush_local_nfqueue(queue_num)
            subprocess.run(
                [
                    "iptables", "-I", "INPUT",
                    "-p", "tcp",
                    "-m", "state", "--state", "NEW,ESTABLISHED",
                    "-j", "NFQUEUE", "--queue-num", str(queue_num), "--queue-bypass"
                ],
                check=True, capture_output=True
            )
            logger.info(f"[Firewall] INPUT NFQUEUE rule added (queue {queue_num}, TCP NEW,ESTABLISHED, bypass)")
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode() if e.stderr else str(e)
            if "already exists" in stderr or "exists" in stderr:
                logger.info(f"[Firewall] INPUT NFQUEUE rule already exists (queue {queue_num})")
            else:
                logger.warning(f"[Firewall] Failed to add INPUT NFQUEUE rule: {stderr}")

    def teardown_local_iptables(self, queue_num: int = 0):
        """Remove LIDRA's NFQUEUE rules — safe to call even if none exist."""
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would remove iptables INPUT NFQUEUE rule (queue {queue_num})")
            return
        self._flush_local_nfqueue(queue_num)
        logger.info(f"[Firewall] INPUT NFQUEUE rules cleaned")

    def _flush_local_nfqueue(self, queue_num: int = 0):
        """Remove ALL NFQUEUE rules for this queue_num from INPUT (including orphaned manual ones)."""
        try:
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "--line-numbers", "-n"],
                capture_output=True, text=True, check=False, timeout=10
            )
            # Walk in reverse so line numbers stay valid after each delete
            lines = result.stdout.split("\n")
            for i in range(len(lines) - 1, -1, -1):
                line = lines[i]
                if f"NFQUEUE num {queue_num}" in line or f"nfqueue queue:{queue_num}" in line:
                    line_num = line.split()[0]
                    if line_num.isdigit():
                        subprocess.run(
                            ["iptables", "-D", "INPUT", line_num],
                            check=False, capture_output=True, timeout=5
                        )
        except Exception as e:
            logger.warning(f"[Firewall] Failed to flush NFQUEUE rules for queue {queue_num}: {e}")

    def local_block_ip(self, ip: str):
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would add local INPUT DROP rule for {ip}")
            return
        self.block_ip(ip)

    def local_unblock_ip(self, ip: str):
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would remove local INPUT DROP rule for {ip}")
            return
        self.unblock_ip(ip)

    def _find_bridge_rule_handle(self, ip: str) -> Optional[str]:
        try:
            result = self._run_nft([
                "--handle", "list", "chain", "bridge",
                self.NFT_BRIDGE_TABLE, self.NFT_BRIDGE_FORWARD_CHAIN
            ], check=False)
            for line in result.stdout.split("\n"):
                if ip in line and "drop" in line:
                    m = re.search(r"handle\s+(\d+)", line)
                    if m:
                        return m.group(1)
        except Exception as e:
            logger.warning(f"[Firewall] Failed to find bridge rule for {ip}: {e}")
        return None
