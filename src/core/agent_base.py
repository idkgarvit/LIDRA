"""Shared LIDRA core — common init, lifecycle, and abstract hooks for all modes."""

from __future__ import annotations

import logging
import os
import queue
import subprocess
import sys
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

import psutil

from utils.paths import get_lidra_root
from database.db import LIDRADatabase
from intel.threat_intel import ThreatIntelOrchestrator
from intel.abuseipdb import AbuseIPDBProvider
from intel.virustotal import VirusTotalProvider
from alerts.notifier import Alert, AlertNotifier
from alerts.slack import SlackChannel
from alerts.discord import DiscordChannel
from response.firewall import FirewallManager
from detection.attack_detector import AttackDetector
from detection.mitre import MITREMapper
from detection.explainer import AttackExplainer

BASE = Path(__file__).resolve().parent.parent


def _config_dry_run(config: dict) -> bool:
    env = os.environ.get("LIDRA_DRY_RUN")
    if env is not None:
        return env in ("1", "true", "yes")
    return bool(config.get('response', {}).get('dry_run', True))


class LIDRACore(ABC):
    """Shared agent for all LIDRA modes.

    Subclasses must implement:
        _init_mode_components()  — mode-specific component setup
        _start_capture()         — start packet capture
        _block_ip(ip, reason)    — block an IP address
        _teardown_capture()      — stop capture / cleanup
    """

    def __init__(self, config: dict):
        self.config = config
        self.running = False
        self._config_mtime = 0
        self._demo_mode = config.get("demo", False)

        if config.get('general', {}).get('verbose', False) or os.environ.get("LIDRA_LOG_LEVEL") == "DEBUG":
            logging.getLogger().setLevel(logging.DEBUG)

        # ── Shared components ──────────────────────────────────────────
        # ponytail: config paths are repo-root-relative. BASE is src/ — using
        # it here created a second live DB at src/data/lidra.db while every
        # other tool read ./data/lidra.db.
        db_path = get_lidra_root() / self.config.get('database', {}).get('path', 'data/lidra.db')
        self.db = LIDRADatabase(str(db_path))

        self.detector = AttackDetector()
        self.mitre_mapper = MITREMapper()
        self.explainer = AttackExplainer()
        self.threat_intel = self._init_threat_intel()
        self.notifier = self._init_alerting()

        from utils.alert_throttle import AlertThrottle
        self._alert_throttle = AlertThrottle(
            cooldown_seconds=int(self.config.get('thresholds', {}).get('alert_cooldown_seconds', 900)))

        # ponytail: the engine fires _on_detection_callback on its verdict
        # thread while packets sit held in NFQUEUE. Re-analysis + SQLite +
        # webhook HTTP there backlogged the queue (442 hits/sec stalled
        # legit traffic). So the callback only enqueues; this daemon worker
        # does the slow side-effects. DB is thread-local + WAL, safe here.
        self._detect_queue: queue.Queue = queue.Queue()
        self._detect_worker = threading.Thread(
            target=self._detection_worker, daemon=True, name="lidra-detect")
        self._detect_worker.start()

        self.firewall: Optional[FirewallManager] = None
        self.inline_engine = None
        self.bridge_manager = None
        self.tui_data_provider = None
        self._tui_ipc_server = None
        self._tui_process = None
        self.tracer = None
        self.cli_dashboard = None

        self._init_mode_components()

    # ── Subclass hooks ─────────────────────────────────────────────────

    @abstractmethod
    def _init_mode_components(self): ...

    @abstractmethod
    def _start_capture(self): ...

    @abstractmethod
    def _block_ip(self, ip: str, reason: str = ""): ...

    @abstractmethod
    def _teardown_capture(self): ...

    # ── Shared helpers ─────────────────────────────────────────────────

    @property
    def is_dry_run(self) -> bool:
        fw = getattr(self, "firewall", None)
        if fw is not None:
            return bool(fw.dry_run)
        return _config_dry_run(self.config)

    def _init_threat_intel(self) -> ThreatIntelOrchestrator:
        providers = []
        abuse_key = self.config.get('threat_intel', {}).get('abuseipdb_api_key', '')
        vt_key = self.config.get('threat_intel', {}).get('virustotal_api_key', '')
        if abuse_key:
            providers.append(AbuseIPDBProvider(abuse_key))
        if vt_key:
            providers.append(VirusTotalProvider(vt_key))
        return ThreatIntelOrchestrator(
            providers,
            check_on_detect=self.config.get('threat_intel', {}).get('check_on_detect', True),
            cache_ttl_seconds=self.config.get('threat_intel', {}).get('cache_ttl_seconds', 3600),
            max_cache=self.config.get('threat_intel', {}).get('max_cache', 10000),
        )

    def _init_alerting(self) -> AlertNotifier:
        channels = []
        slack = self.config.get('alerts', {}).get('slack_webhook', '')
        discord = self.config.get('alerts', {}).get('discord_webhook', '')
        if slack:
            channels.append(SlackChannel(slack))
        if discord:
            channels.append(DiscordChannel(discord))
        return AlertNotifier(channels)

    def _ensure_nfqueue_module(self) -> bool:
        if os.path.exists("/proc/net/netfilter/nfnetlink_queue"):
            return True
        try:
            result = subprocess.run(
                ["modprobe", "nfnetlink_queue"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                time.sleep(0.5)
                return os.path.exists("/proc/net/netfilter/nfnetlink_queue")
            return False
        except Exception:
            return False

    def _launch_tui(self):
        # Embedded mode: TUI manages the agent in-process — skip IPC + subprocess
        if self.config.get('tui', {}).get('embedded', False):
            self._tui_ipc_server = None
            self._tui_process = None
            return

        self._tui_ipc_server = None
        if self.tui_data_provider:
            try:
                from tui.ipc_server import TUIIPCServer
                firewall = getattr(self, 'firewall', None)
                block_fn = unblock_fn = None
                if firewall:
                    block_fn = lambda ip, reason: firewall.block_ip(ip, ttl_seconds=3600)
                    unblock_fn = firewall.unblock_ip
                ipc = TUIIPCServer(
                    snapshot_fn=self.tui_data_provider.get_snapshot,
                    block_fn=block_fn,
                    unblock_fn=unblock_fn,
                )
                ipc.start()
                self._tui_ipc_server = ipc
            except Exception as e:
                self._log(f"[TUI-IPC] Failed to start: {e}")

        if self.config.get('tui', {}).get('enabled', True):
            try:
                env = dict(os.environ)
                if self._tui_ipc_server:
                    env["LIDRA_TUI_SOCKET"] = self._tui_ipc_server.socket_path
                # src/ has no __init__.py — run as top-level package with PYTHONPATH=src
                env["PYTHONPATH"] = str(BASE) + os.pathsep + env.get("PYTHONPATH", "")
                self._tui_process = subprocess.Popen(
                    [sys.executable, "-m", "tui.app", "--standalone"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
                    cwd=str(BASE),
                )
            except Exception as e:
                self._log(f"[TUI] Failed to launch: {e}")

    def push_event(self, event: dict):
        """Push an event to the TUI — public entry point for demo injector etc."""
        if self.tui_data_provider:
            self.tui_data_provider.push_event(event)
        if self._tui_ipc_server and self._tui_ipc_server.socket_path:
            self._tui_ipc_server.broadcast_event(event)

    _push_tui_event = push_event

    def _on_detection_callback(self, event: Dict):
        """Verdict-thread entry — enqueue only, never block held packets."""
        try:
            self._detect_queue.put_nowait(event)
        except Exception as e:
            self._log(f"Detection queue error: {e}")

    def _detection_worker(self):
        while True:
            try:
                self._handle_detection_event(self._detect_queue.get())
            except Exception as e:
                self._log(f"Detection worker error: {e}")
            finally:
                try:
                    self._detect_queue.task_done()
                except Exception:
                    pass

    def _handle_detection_event(self, event: Dict):
        """Slow side-effects (re-analysis, DB, alerts) — worker thread only."""
        try:
            data = event.get("data", {})
            detection = data.get("detection", {})
            verdict = data.get("verdict", "pass")

            attack_type = detection.get("attack_type", "unknown")
            severity = detection.get("severity", "medium")
            source_ip = detection.get("source_ip", "")
            details = detection.get("details", "")

            if not source_ip:
                return

            whitelist = self.config.get('whitelist', [])
            if source_ip in whitelist:
                return

            from utils.allowlist import should_suppress
            suppress, reason = should_suppress(source_ip, attack_type, self.config)
            if suppress:
                return

            detected = self.detector.analyze_packet_event(detection)
            if not detected:
                return

            attacker_id = self.db.add_attacker(source_ip, country="", org="")
            self.db.record_attack(attacker_id, attack_type, source_log="bridge_inline", raw_line=details[:500], severity=severity)

            if severity in ("high", "critical") and verdict == "drop":
                # ponytail: no_block suppresses BLOCKING only — alerts must
                # still fire (a no_block hit is insider-threat signal; burying
                # it blinded all Phase-2 web attacks from the test partner).
                # Throttle gates notify + DB row only — TUI feed and blocking
                # below still run for every high/critical drop verdict.
                if self._alert_throttle.allow(attack_type, source_ip):
                    pcap = detection.get("forensics_pcap", "")
                    msg = f"[INLINE] {details} — {verdict}"
                    if pcap:
                        msg += f" [pcap: {pcap}]"
                    alert = Alert(
                        alert_type=attack_type, severity=severity,
                        ip_address=source_ip, message=msg
                    )
                    self.notifier.notify(alert)
                    self.db.add_alert(attack_type, severity, source_ip, details[:500])

                no_block = self.config.get("no_block", [])
                if source_ip not in no_block:
                    if not self.is_dry_run:
                        self._block_ip(source_ip, f"inline_{attack_type}")
                        try:
                            from metrics import collector as _m
                            _m.record_block("inline")
                        except Exception:
                            pass
                        self._push_tui_event({"type": "block", "data": {
                            "ip": source_ip,
                            "reason": f"Inline detection: {attack_type}",
                            "timestamp": datetime.now().isoformat(),
                        }})

            self._push_tui_event({"type": "attack", "data": {
                "ip": source_ip,
                "type": attack_type,
                "severity": severity,
                "timestamp": datetime.now().isoformat(),
            }})

        except Exception as e:
            self._log(f"Detection callback error: {e}")

    def _on_security_event(self, event):
        """Handle events from eBPF / log tracer."""
        try:
            pre = (event.raw_data or {}).get('attack') if hasattr(event, 'raw_data') else None
            if pre:
                detection = {
                    'attack_type': pre.get('attack_type', 'unknown'),
                    'severity': pre.get('severity', 'medium'),
                    'mitre': pre.get('mitre', []),
                    'details': pre.get('details', {}),
                }
            else:
                detection = self.detector.analyze_event(event)

            if not detection:
                return

            attack_type = detection.get('attack_type', 'unknown')
            severity = detection.get('severity', 'medium')

            ip_address = getattr(event, 'dst_ip', '') or getattr(event, 'ip_address', '') or 'unknown'

            from utils.allowlist import should_suppress
            suppress, reason = should_suppress(ip_address, attack_type, self.config)
            if suppress:
                return

            intel = self.threat_intel.lookup_ip(ip_address)
            context = {'detection': detection, 'event': event, 'threat_intel': intel}
            explanation = self.explainer.explain(detection, context)

            if ip_address != 'unknown':
                attacker_id = self.db.add_attacker(
                    ip_address,
                    country=intel.get('details', {}).get('AbuseIPDB', {}).get('country'),
                    org=intel.get('details', {}).get('AbuseIPDB', {}).get('isp'),
                )
                self.db.record_attack(
                    attacker_id, attack_type,
                    source_log='ebpf' if self.tracer and self.tracer.is_using_ebpf() else 'log',
                    raw_line=explanation[:500],
                )

            if severity in ('high', 'critical'):
                alert = Alert(alert_type=attack_type, severity=severity, ip_address=ip_address, message=explanation)
                self.notifier.notify(alert)
                self.db.add_alert(attack_type, severity, ip_address, explanation[:500])

            if severity == 'critical' and not self.is_dry_run:
                if intel.get('is_malicious') or intel.get('threat_score', 0) >= 70:
                    self._block_ip(ip_address, f"auto_{attack_type}")
        except Exception as e:
            self._log(f"Event processing error: {e}")

    def _detect_honeypot_events(self):
        # ponytail: repo-root-relative like the DB — BASE=src/ sent the agent
        # looking in src/logs while the honeypot wrote to ./logs.
        honeypot_log = get_lidra_root() / self.config.get('deception', {}).get('honeypot_log', 'logs/honeypot.log')
        state_file = get_lidra_root() / self.config.get('deception', {}).get('state_file', 'state/honeypot_processed.txt')

        processed_ips = set()
        if state_file.exists():
            with open(state_file) as f:
                processed_ips = {line.strip() for line in f if line.strip()}

        new_ips = []
        if honeypot_log.exists():
            with open(honeypot_log) as f:
                for line in f:
                    if "[HIT]" in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == "from" and i + 1 < len(parts):
                                ip = parts[i + 1].rstrip(",")
                                if ip and ip not in processed_ips:
                                    new_ips.append(ip)
                                    self._process_honeypot_detection(ip, "honeypot_connection")

        last_processed = 0
        if state_file.exists():
            try:
                with open(state_file) as f:
                    for line in f:
                        if line.startswith("honeyfile:"):
                            last_processed = int(line.split(":")[1])
            except (OSError, ValueError, IOError):
                pass

        conn = self.db._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, ip_address, file_path FROM honeyfile_hits WHERE id > ?", (last_processed,))
        # ponytail: persist the high-water mark — without this every cycle
        # re-alerts, re-records, and re-blocks the same honeyfile hits
        max_seen = last_processed
        for hit_id, ip, file_path in cursor.fetchall():
            max_seen = max(max_seen, hit_id)
            if ip:
                self._process_honeypot_detection(ip, "honeyfile_access", {"file_path": file_path})
        if max_seen > last_processed:
            with open(state_file, "a") as f:
                f.write(f"honeyfile:{max_seen}\n")

        if new_ips:
            with open(state_file, "a") as f:
                for ip in new_ips:
                    f.write(f"{ip}\n")

    def _process_honeypot_detection(self, ip: str, attack_type: str, details: Dict = None):
        attacker_id = self.db.add_attacker(ip, country="", org="")
        self.db.record_attack(attacker_id, attack_type, source_log="honeypot", raw_line=f"Deception detected {attack_type} from {ip}")
        alert = Alert(alert_type=attack_type, severity="critical", ip_address=ip, message=f"Honeypot: {attack_type} from {ip}")
        self.notifier.notify(alert)
        self.db.add_alert(attack_type, "critical", ip, f"Honeypot from {ip}")
        if not self.is_dry_run:
            self._block_ip(ip, f"honeypot_{attack_type}")

    def reload_config(self, new_config: dict):
        old_mode = self.config.get("mode")
        new_mode = new_config.get("mode")
        self.config = new_config
        if old_mode != new_mode:
            self._log(f"Mode changed from {old_mode} to {new_mode} — restart required for full effect")
        if self.config.get("general", {}).get("verbose", False):
            logging.getLogger().setLevel(logging.DEBUG)
        self.threat_intel = self._init_threat_intel()
        self.notifier = self._init_alerting()
        if hasattr(self, "firewall") and self.firewall:
            self.firewall.dry_run = _config_dry_run(self.config)
        self._config_mtime = time.time()

    def _cleanup_loop_body(self):
        self.db.cleanup_old_data(self.config.get('database', {}).get('cleanup_days', 30))
        if self.inline_engine and hasattr(self.inline_engine, 'blocklist'):
            self.inline_engine.blocklist.cleanup_expired()

    def run(self):
        """Common main loop for inline and local modes (TUI push every 1s, cleanup every 300s)."""
        self.running = True
        self._start_capture()

        cleanup_interval = 300
        last_cleanup = time.time()

        try:
            while self.running:
                now = time.time()
                if now - last_cleanup > cleanup_interval:
                    self._cleanup_loop_body()
                    last_cleanup = now

                if self.inline_engine:
                    try:
                        stats = self.inline_engine.get_stats()
                        cpu = psutil.cpu_percent(interval=None)
                        mem = psutil.virtual_memory().percent
                        active = self.inline_engine.connection_tracker.get_stats().get("active_connections", 0)
                        # Prometheus gauges — this loop is already the agent's
                        # 1 Hz stats tick, so the write costs nothing extra.
                        try:
                            from metrics import collector as _m
                            _m.set_gauges_from_stats(stats, cpu_percent=cpu,
                                                     memory_percent=mem,
                                                     active_connections=active)
                        except Exception:
                            pass
                        self._push_tui_event({"type": "packet", "data": {
                            "pkts_per_sec": round(stats.get("packet_rate", 0), 1),
                            "mbps": round(stats.get("packets_in", 0) * 1500 / 1_000_000, 2),
                            "timestamp": datetime.now().isoformat(),
                        }})
                        self._push_tui_event({"type": "stats", "data": {
                            "cpu_usage": cpu,
                            "memory_usage": mem,
                            "active_connections": active,
                        }})
                    except Exception:
                        pass  # best-effort TUI stats
                self._push_tui_event({"type": "snapshot", "data": {}})
                time.sleep(1)
        except KeyboardInterrupt:
            self._log("Stopped by user")
        finally:
            self.stop()

    def stop(self):
        self.running = False
        self._teardown_capture()
        if self._tui_process:
            self._tui_process.terminate()
            try:
                self._tui_process.wait(timeout=3)
            except Exception:
                self._tui_process.kill()
        if self._tui_ipc_server:
            self._tui_ipc_server.stop()
            self._tui_ipc_server = None
        if self.cli_dashboard:
            self.cli_dashboard.stop()
        if self.firewall:
            self.firewall.teardown_local_iptables(0)
        self.db.close()

    def _log(self, msg: str):
        logger = logging.getLogger("LIDRA-core")
        logger.info(msg)
