# src/response/firewall.py
"""Production firewall integration for LIDRA."""

import subprocess
import logging
from pathlib import Path
from typing import Optional, List
import re
import threading

logger = logging.getLogger(__name__)


class FirewallManager:
    """Manages iptables/nftables firewall rules."""

    def __init__(self, backend: str = "iptables", dry_run: bool = False):
        self.backend = backend
        self.dry_run = dry_run
        self.chain = "LIDRA_BLOCK"
        self._nft_lock = threading.Lock()
        if not dry_run:
            self._ensure_chain()

    def _ensure_chain(self):
        """Create LIDRA chain if it doesn't exist."""
        try:
            result = subprocess.run(
                ["iptables", "-L", self.chain, "-n"],
                capture_output=True,
                check=False
            )
            if result.returncode != 0:
                subprocess.run(["iptables", "-N", self.chain], check=False)
                subprocess.run(["iptables", "-I", "INPUT", "-j", self.chain], check=False)
                logger.info(f"Created iptables chain: {self.chain}")
        except Exception as e:
            logger.warning(f"Could not ensure iptables chain: {e}")

    def block_ip(self, ip: str, ttl_seconds: int = 3600) -> bool:
        """Block an IP address."""
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would block {ip} for {ttl_seconds}s")
            return True

        try:
            # Add block rule
            subprocess.run(
                ["iptables", "-A", self.chain, "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            # Schedule removal
            self._schedule_unblock(ip, ttl_seconds)
            logger.info(f"Blocked {ip} for {ttl_seconds}s")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block {ip}: {e}")
            return False
        except Exception as e:
            logger.error(f"Firewall error for {ip}: {e}")
            return False

    def _schedule_unblock(self, ip: str, ttl_seconds: int):
        """Schedule IP unblock after TTL using timer."""
        threading.Timer(ttl_seconds, self._unblock_ip, args=[ip]).start()

    def _unblock_ip(self, ip: str):
        """Remove block rule for IP."""
        try:
            subprocess.run(
                ["iptables", "-D", self.chain, "-s", ip, "-j", "DROP"],
                check=False,
                capture_output=True
            )
            logger.info(f"Unblocked {ip} (TTL expired)")
        except Exception as e:
            logger.error(f"Failed to unblock {ip}: {e}")

    def unblock_ip(self, ip: str) -> bool:
        """Manually unblock an IP."""
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would unblock {ip}")
            return True

        try:
            subprocess.run(
                ["iptables", "-D", self.chain, "-s", ip, "-j", "DROP"],
                check=False,
                capture_output=True
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

        try:
            result = subprocess.run(
                ["iptables", "-L", self.chain, "-n", "--line-numbers"],
                capture_output=True,
                text=True,
                check=False
            )
            return ip in result.stdout
        except Exception:
            return False

    def list_blocks(self) -> List[str]:
        """List all currently blocked IPs."""
        if self.dry_run:
            return []

        try:
            result = subprocess.run(
                ["iptables", "-L", self.chain, "-n"],
                capture_output=True,
                text=True,
                check=False
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

    def _is_ip(self, s: str) -> bool:
        """Check if string is an IP address."""
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s))

    # --- Bridge / nftables methods ---

    NFT_BRIDGE_TABLE = "lidra_bridge"
    NFT_BRIDGE_FORWARD_CHAIN = "lidra_forward"
    NFT_BRIDGE_INPUT_CHAIN = "lidra_input"

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
        except Exception:
            pass

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
        except Exception:
            pass
        return None
