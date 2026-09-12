"""Safe-link runtime guard for LIDRA inline mode.

Why this exists
---------------
LIDRA's local (laptop) mode installs an NFQUEUE rule on the host's inbound
path. Two failure modes were reproduced on a live Kali host (kernel 7.1.5):

1. **Queue rule without a consumer.** An NFQUEUE rule whose queue has no
   listener leaves every matching packet parked in the kernel's queue until
   userspace answers. If the rule was added *without* the ``bypass`` flag
   there is nothing to answer it and connectivity stops completely
   (measured: TCP connect to 1.1.1.1 blocked until the rule was deleted,
   ICMP to the gateway silent).

2. **Crash window.** The rule is created before the netlink consumer binds.
   If the agent dies in between (startup race, SIGKILL, OOM, a traceback in
   the bind path) the rule survives and case 1 becomes permanent.

Measured behaviour of the two rule forms on the same host:

| rule                 | consumer bound | connectivity |
|----------------------|----------------|--------------|
| ``queue ... bypass`` | yes            | OK           |
| ``queue ... bypass`` | no             | OK (bypass)  |
| ``queue ...``        | no             | **DEAD**     |

What this module does
---------------------
* ``guard_after_bind`` runs a watchdog thread that proves LIDRA's queue rule
  is still present and still has a consumer. If it disappears (someone
  flushed the ruleset, another firewall tool reset the table, nftables was
  reloaded) LIDRA fails **open** deliberately and logs CRITICAL — silently
  running as a sniffer while claiming to protect is worse than being off.
* ``always_bypass`` exists so the code that builds rules can never emit a
  queue rule without the bypass flag: a LIDRA crash must never take the
  host's network with it.

The guard deliberately does not drop anything and does not re-add rules.
It reports and fails open; re-arming is an operator decision.
"""

from __future__ import annotations

import logging
import subprocess
import threading
import time
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Interval between queue-rule presence checks.
GUARD_INTERVAL_SECONDS = 5.0
# Connectivity probe budget. Kept short: this runs on the guard thread only.
PROBE_TIMEOUT_SECONDS = 3


def always_bypass(rule_args: list) -> list:
    """Return *rule_args* guaranteed to carry the NFQUEUE ``bypass`` flag.

    A rule built by LIDRA must always be bypassable: if the agent dies the
    kernel must let the packets continue. Refusing to emit a non-bypass rule
    is the single cheapest defence against the total-outage failure mode.
    """
    if "queue" not in rule_args:
        return rule_args
    if "bypass" in rule_args:
        return rule_args
    return rule_args + ["bypass"]


class SafeLink:
    """Watchdog for the inline NFQUEUE hook.

    Instantiated by InlineEngine and armed only *after* the netlink consumer
    has successfully bound, so it never reports a failure that the binder is
    about to fix.
    """

    def __init__(self, config: dict, interface: str, table: str, family: str = "inet",
                 alert_callback: Optional[Callable] = None, dry_run: bool = True):
        self._config = config
        self._interface = interface
        self._table = table
        self._family = family
        self._alert_callback = alert_callback
        self._dry_run = dry_run
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._armed_at = 0.0
        self.rolled_back = False
        self.events: list = []

    # -- lifecycle ---------------------------------------------------------

    def arm(self):
        """Arm the guard. Safe to call repeatedly; the first call wins."""
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._armed_at = time.time()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="lidra-safe-link")
        self._thread.start()
        logger.info(
            f"[SafeLink] Armed — watching queue rule on {self._interface} "
            f"(table {self._family} {self._table}); fail-open on loss"
        )

    def disarm(self):
        self._stop.set()

    @property
    def armed(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    # -- checks ------------------------------------------------------------

    def rule_present(self) -> bool:
        """True if our queue rule is still in the kernel ruleset."""
        try:
            result = subprocess.run(
                ["nft", "list", "table", self._family, self._table],
                capture_output=True, text=True, timeout=5, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.debug(f"[SafeLink] nft query failed: {e}")
            return False
        out = result.stdout or ""
        if result.returncode != 0 or not out.strip():
            return False
        has_queue = "queue" in out
        has_iface = self._interface in out or "iifname" not in out
        return has_queue and has_iface

    def queue_has_consumer(self) -> bool:
        """True if some process is bound to a netfilter queue.

        /proc/net/netfilter/nfnetlink_queue lists one row per bound queue.
        An empty file (or a missing file) means no consumer exists and any
        non-bypass rule would be blocking traffic.
        """
        try:
            with open("/proc/net/netfilter/nfnetlink_queue") as f:
                return bool(f.read().strip())
        except OSError:
            return False

    def probe_connectivity(self, target: str = "1.1.1.1") -> bool:
        """Best-effort external reachability probe (guard thread only)."""
        try:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "--max-time", str(PROBE_TIMEOUT_SECONDS),
                 f"https://{target}"],
                capture_output=True, timeout=PROBE_TIMEOUT_SECONDS + 2, check=False,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    # -- guard loop --------------------------------------------------------

    def _loop(self):
        while not self._stop.is_set():
            self._stop.wait(GUARD_INTERVAL_SECONDS)
            if self._stop.is_set():
                break
            try:
                self._check_once()
            except Exception as e:  # never let the guard die silently
                logger.debug(f"[SafeLink] check error: {e}")

    def _check_once(self):
        consumer = self.queue_has_consumer()
        present = self.rule_present()

        if present and not consumer:
            # Rule with nothing draining it. Only survivable because the rule
            # carries `bypass`; still an incident — LIDRA has stopped
            # protecting without saying so.
            self._report(
                "safe_link_consumer_lost",
                "critical",
                f"NFQUEUE rule on {self._interface} has no consumer bound — "
                f"LIDRA is no longer inspecting traffic "
                f"(rule kept because it carries `bypass`)",
            )
            return

        if not present and self._stop.is_set() is False and time.time() - self._armed_at > 10:
            self._report(
                "safe_link_rule_lost",
                "critical",
                f"LIDRA's NFQUEUE rule disappeared from {self._family} "
                f"{self._table} — failing OPEN deliberately rather than "
                f"silently sniffing while reporting protection. "
                f"Re-arm with `lidra restart`.",
            )

    def _report(self, attack_type: str, severity: str, message: str):
        # Throttle to one report per 60s per type so a persistent condition
        # cannot flood the log, the DB or the TUI.
        now = time.time()
        last = getattr(self, "_last_report", {}).get(attack_type, 0)
        if now - last < 60:
            return
        if not hasattr(self, "_last_report"):
            self._last_report = {}
        self._last_report[attack_type] = now
        self.rolled_back = True
        self.events.append({"ts": now, "type": attack_type, "message": message})
        logger.critical(f"[SafeLink] {message}")
        if self._alert_callback:
            try:
                self._alert_callback({
                    "type": "attack",
                    "data": {
                        "detection": {
                            "attack_type": attack_type,
                            "severity": severity,
                            "source_ip": "127.0.0.1",
                            "details": message,
                        },
                        "verdict": "drop",
                        "packet": {"src_ip": "127.0.0.1", "dst_ip": "127.0.0.1",
                                   "src_port": 0, "dst_port": 0, "protocol": "local"},
                        "latency_ms": 0.0,
                    },
                })
            except Exception as e:
                logger.warning(f"[SafeLink] alert dispatch failed: {e}")


def rollback_queue_table(family: str, table: str) -> bool:
    """Emergency removal of LIDRA's queue table. Last resort only."""
    try:
        subprocess.run(["nft", "delete", "table", family, table],
                       capture_output=True, timeout=5, check=False)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
