#!/usr/bin/env python3
"""
LIDRA - Intrusion Detection & Response Agent

Lightweight, same-host and inline intrusion detection using:
- Packet capture (AF_PACKET / NFQUEUE) and auth-log correlation
- eBPF kernel telemetry where the kernel and bcc allow it, with a
  log-based fallback otherwise
- MITRE ATT&CK mapped detections
- Statistical anomaly detection (per-IP baselines, behavioural analysis)
- SIEM-compatible output

Not claimed: LLM triage (soar/) and the XDP data path exist in the tree but
are not wired into this agent — see docs/PRODUCTION_READINESS.md section 3.
"""

import os
import sys
import time
import signal
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict

sys.path.insert(0, str(Path(__file__).parent))

from utils.config_loader import load_config as load_central_config

from alerts.notifier import Alert
from detection.attack_detector import AttackDetector
from ebpf import EBPFDetector

from collectors.network import create_sniffer
from collectors.syslog import create_syslog_server
from utils.interface import detect_interface
from utils.severity import is_actionable_severity
from core.agent_base import LIDRACore

try:
    from bridge.inline_engine import InlineEngine
    from bridge.bridge_manager import BridgeManager
    from tui.data_provider import TUIDataProvider
    from tui.ipc_server import TUIIPCServer
    HAS_BRIDGE = True
except ImportError as e:
    logging.warning(f"[Agent] Bridge/TUI import failed: {e}")
    InlineEngine = None
    BridgeManager = None
    TUIDataProvider = None
    TUIIPCServer = None
    HAS_BRIDGE = False

logger = logging.getLogger("LIDRA-v3")

BASE = Path(__file__).parent.parent


def _require_root():
    if os.geteuid() != 0:
        print("LIDRA requires root privileges. Re-run with sudo.")
        sys.exit(1)


# Local (laptop) mode installs a kernel-level queue rule on the host's own
# inbound path. That is the one mode where a bug takes the user's network
# down with it, so it is opt-in: `local.inline: true` in config.yaml, or
# `lidra --local-inline` on the command line. Absent both, LIDRA monitors
# the interface (AF_PACKET) and blocks by iptables rule — it cannot drop the
# first packet, but it also cannot lock the operator out of their own box.
LOCAL_INLINE_ENV = "LIDRA_LOCAL_INLINE"


def _local_inline_opt_in(config: dict) -> bool:
    """True only when the operator explicitly asked for inline interception."""
    env = os.environ.get(LOCAL_INLINE_ENV)
    if env is not None:
        return env in ("1", "true", "yes")
    return bool((config.get("local", {}) or {}).get("inline", False))


def _setup_logging(verbose: bool = False):
    log_dir = BASE / "logs"
    log_dir.mkdir(exist_ok=True)
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[
            logging.FileHandler(log_dir / "lidra_v3.log"),
            logging.StreamHandler()
        ],
        force=True,
    )


def _config_dry_run(config: dict) -> bool:
    """Single source of truth for the response.dry_run config value.

    All FirewallManager constructors and action gates read this so the
    config and the firewall can never disagree.
    """
    env = os.environ.get("LIDRA_DRY_RUN")
    if env is not None:
        return env in ("1", "true", "yes")
    return bool(config.get('response', {}).get('dry_run', True))


class LIDRAv3:
    """Backward-compatible LIDRA v3 — dispatches to the mode-specific subclass."""

    def __new__(cls, config: dict):
        mode = config.get('mode', 'inline')
        if mode == 'inline':
            from core.gateway_agent import LIDRAGateway
            instance = object.__new__(LIDRAGateway)
            instance.__init__(config)
            return instance
        elif mode == 'local':
            from core.personal_agent import LIDRAPersonal
            instance = object.__new__(LIDRAPersonal)
            instance.__init__(config)
            return instance
        else:
            return _LegacyMonitorAgent(config)


class _LegacyMonitorAgent(LIDRACore):
    """Legacy eBPF / log-based monitor mode — preserved for backward compat."""

    def _init_mode_components(self):
        from response.firewall import FirewallManager
        self.firewall = FirewallManager(
            backend=self.config.get('response', {}).get('firewall', 'iptables'),
            dry_run=_config_dry_run(self.config),
        )
        from ebpf import create_tracer
        self.tracer = create_tracer(self.config)
        self.tracer.load()
        if self.tracer.is_using_ebpf():
            self.detector = EBPFDetector()
        else:
            self.detector = AttackDetector()
        self.tracer.register_callback(self._on_security_event)
        from dashboard.cli import create_cli_dashboard
        self.cli_dashboard = create_cli_dashboard(self.db)
        self.cli_dashboard.print_welcome()
        self.sniffer = None
        self.syslog_server = None
        self._init_collectors()

    def _start_capture(self):
        self.tracer.start()
        if self.sniffer:
            self.sniffer.start()
        if self.syslog_server:
            self.syslog_server.start()
        self.cli_dashboard.start()

    def _block_ip(self, ip: str, reason: str = ""):
        self.firewall.block_ip(ip, ttl_seconds=3600)

    def _teardown_capture(self):
        self.tracer.stop()
        if self.sniffer:
            self.sniffer.stop()
        if self.syslog_server:
            self.syslog_server.stop()

    def _init_collectors(self):
        collectors = self.config.get('collectors', {})
        network_enabled = collectors.get('network', {}).get('enabled', True)
        syslog_enabled = collectors.get('syslog', {}).get('enabled', True)
        if network_enabled:
            interface = collectors.get('network', {}).get('interface') or detect_interface()
            self.sniffer = create_sniffer(interface=interface, callback=self._on_network_event)
        if syslog_enabled:
            port = collectors.get('syslog', {}).get('port', 514)
            self.syslog_server = create_syslog_server(port=port, callback=self._on_syslog_event)

    def _on_network_event(self, event):
        if not event or "attack_type" not in event:
            return
        logger.warning(f"[NETWORK] {event['attack_type']} from {event.get('source_ip', 'unknown')}")
        self._process_network_detection(event)

    def _on_syslog_event(self, event):
        if not event or "attack_type" not in event:
            return
        logger.warning(f"[SYSLOG] {event['attack_type']} from {event.get('source_ip', 'unknown')}")
        self._process_network_detection(event)

    def _process_network_detection(self, detection: Dict):
        try:
            attack_type = detection.get('attack_type', 'unknown')
            severity = detection.get('severity', 'medium')
            source_ip = detection.get('source_ip', 'unknown')
            if source_ip == 'unknown':
                return
            # Mirrors core/agent_base: the row write sits above the
            # alert/block gate, so an observation-severity detection would
            # otherwise persist without ever being actionable. No detector on
            # this path emits "info" today — this keeps the invariant true by
            # construction rather than by accident.
            if not is_actionable_severity(severity):
                return
            whitelist = self.config.get('whitelist', [])
            if source_ip in whitelist:
                return
            attacker_id = self.db.add_attacker(source_ip, "", "")
            self.db.record_attack(attacker_id, attack_type, source_log='network', raw_line=detection.get('details', ''), severity=severity)
            if severity in ('high', 'critical'):
                # ponytail: no_block suppresses BLOCKING only — alerts still
                # fire (same insider-signal reasoning as agent_base).
                if self._alert_throttle.allow(attack_type, source_ip):
                    alert = Alert(alert_type=attack_type, severity=severity, ip_address=source_ip, message=detection.get('details', attack_type))
                    self.notifier.notify(alert)
                    self.db.add_alert(attack_type, severity, source_ip, detection.get('details', '')[:500])
                no_block = self.config.get("no_block", [])
                if source_ip not in no_block:
                    if not self.is_dry_run:
                        reason = f"network_{attack_type}"
                        if self.firewall.block_ip(source_ip, ttl_seconds=3600):
                            try:
                                block_id = self.db.add_block(source_ip, reason)
                                self.db.mark_block_applied(block_id)
                            except Exception as e:
                                logger.error(f"Block persist error: {e}")
        except Exception as e:
            logger.error(f"Network detection processing error: {e}")

    def run(self):
        self.running = True
        self.tracer.start()
        if self.sniffer:
            self.sniffer.start()
        if self.syslog_server:
            self.syslog_server.start()
        sleep_time = self.config.get('main_loop', {}).get('cycle_seconds', 60)
        self.cli_dashboard.start()
        try:
            while self.running:
                if datetime.now().hour == 3:
                    self.db.cleanup_old_data(self.config.get('database', {}).get('cleanup_days', 30))
                self._detect_honeypot_events()
                time.sleep(sleep_time)
        except KeyboardInterrupt:
            logger.info("LIDRA monitor mode stopped by user")
        finally:
            self.stop()


def main():
    """Entry point with signal handling and PID file."""
    import argparse
    parser = argparse.ArgumentParser(description="LIDRA — Intrusion Detection & Response Agent")
    parser.add_argument("--demo", action="store_true", help="Auto-fire synthetic demo attacks into the TUI")
    parser.add_argument("--mode", choices=["laptop", "gateway"], default=None, help="Override config mode")
    parser.add_argument("--tui", dest="tui", action="store_true", default=None, help="Launch the TUI")
    parser.add_argument("--no-tui", dest="tui", action="store_false", help="Run headless (no TUI)")
    parser.add_argument("--dry-run", dest="dry_run", action="store_true", default=None, help="Detect only, never block")
    parser.add_argument("--no-dry-run", dest="dry_run", action="store_false", help="Allow real blocking")
    parser.add_argument("--verbose", action="store_true", help="DEBUG logging")
    parser.add_argument("--interface", default=None, help="Capture interface (overrides config)")
    parser.add_argument("--local-inline", dest="local_inline", action="store_true", default=None,
                        help="Opt in to kernel inline interception in local mode "
                             "(installs an NFQUEUE rule on the host's inbound path)")
    parser.add_argument("--no-local-inline", dest="local_inline", action="store_false",
                        help="Force monitor mode in local mode (default)")
    args = parser.parse_args()

    _setup_logging(verbose=args.verbose)
    _require_root()

    (BASE / "data").mkdir(exist_ok=True)
    (BASE / "logs").mkdir(exist_ok=True)
    (BASE / "state").mkdir(exist_ok=True)

    from metrics.server import MetricsServer
    metrics_port = int(os.environ.get("LIDRA_METRICS_PORT", 8080))
    metrics_cert = os.environ.get("LIDRA_METRICS_CERT") or None
    metrics_key = os.environ.get("LIDRA_METRICS_KEY") or None
    metrics_srv = MetricsServer(port=metrics_port, cert_path=metrics_cert, key_path=metrics_key)
    metrics_srv.start()

    pid_path = None
    for candidate in (Path("/var/run/lidra/lidra.pid"), Path("/run/lidra/lidra.pid")):
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            candidate.write_text(str(os.getpid()))
            try:
                os.chmod(candidate, 0o644)
            except OSError as e:
                logger.debug(f"PID file chmod failed: {e}")
            pid_path = candidate
            break
        except (PermissionError, OSError) as e:
            logger.debug(f"PID file {candidate} unavailable: {e}")
    if pid_path is None:
        pid_path = BASE / "state" / "lidra.pid"
        try:
            pid_path.write_text(str(os.getpid()))
        except OSError as e:
            logger.warning(f"Could not write PID file: {e}")

    config = load_central_config()
    if args.demo:
        config["demo"] = True
    if args.mode:
        # Normalise user-friendly CLI names to internal mode strings
        mode_map = {"laptop": "local", "gateway": "inline"}
        config["mode"] = mode_map.get(args.mode, args.mode)
    if args.tui is not None:
        config.setdefault("tui", {})["enabled"] = args.tui
    if args.dry_run is not None:
        config.setdefault("response", {})["dry_run"] = args.dry_run
    if args.verbose:
        config.setdefault("general", {})["verbose"] = True
    if args.interface:
        config.setdefault("collectors", {}).setdefault("network", {})["interface"] = args.interface
    if args.local_inline is not None:
        config.setdefault("local", {})["inline"] = args.local_inline
    if config.get("mode") == "local" and not _local_inline_opt_in(config):
        logger.info(
            "[Agent] Local mode: monitor-only capture (AF_PACKET). Inline "
            "interception is opt-in — pass --local-inline or set "
            "local.inline: true to install a kernel queue rule."
        )
    lidra = LIDRAv3(config)

    def _shutdown(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        lidra.stop()
        if pid_path.exists():
            pid_path.unlink()
        sys.exit(0)

    def _reload(signum, frame):
        logger.info("Received SIGHUP — reloading config...")
        try:
            new_config = load_central_config()
            lidra.reload_config(new_config)
            logger.info("Config reloaded successfully")
        except Exception as e:
            logger.error(f"Config reload failed: {e}")

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGHUP, _reload)

    if args.demo:
        from demo_injector import inject_demo_events
        inject_demo_events(lidra, delay=3.0)

    lidra.run()


if __name__ == "__main__":
    main()