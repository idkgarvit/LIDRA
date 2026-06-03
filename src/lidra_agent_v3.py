#!/usr/bin/env python3
"""
LIDRA v3 - eBPF-Powered Detection System

Lightweight, enterprise-grade intrusion detection using:
- eBPF kernel-level telemetry (with log fallback)
- MITRE ATT&CK mapped detections
- Statistical ML anomaly detection  
- LLM-powered explanations
- SIEM-compatible output
"""

import os
import sys
import time
import logging
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import json

import psutil
import yaml

sys.path.insert(0, str(Path(__file__).parent))

from database.db import LIDRADatabase
from intel.threat_intel import ThreatIntelOrchestrator
from intel.abuseipdb import AbuseIPDBProvider
from intel.virustotal import VirusTotalProvider
from alerts.notifier import Alert, AlertNotifier
from alerts.slack import SlackChannel
from alerts.discord import DiscordChannel
from response.firewall import FirewallManager
from response.blocklist import Blocklist
from detection.log_parser import LogParser
from detection.attack_detector import AttackDetector
from detection.mitre import MITREMapper
from detection.ml.anomaly import AnomalyDetector
from detection.explainer import AttackExplainer
from ebpf import EBPFTracer, EBPFDetector, create_tracer
from dashboard.cli import create_cli_dashboard
from collectors.network import create_sniffer
from collectors.syslog import create_syslog_server
from utils.interface import detect_interface

try:
    from bridge.inline_engine import InlineEngine
    from bridge.bridge_manager import BridgeManager
    from tui.data_provider import TUIDataProvider
    from tui.ipc_server import TUIIPCServer
    HAS_BRIDGE = True
except ImportError:
    InlineEngine = None
    BridgeManager = None
    TUIDataProvider = None
    TUIIPCServer = None
    HAS_BRIDGE = False

try:
    from dashboard.main import collector_state
except ImportError:
    collector_state = None

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "lidra_v3.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("LIDRA-v3")

BASE = Path(__file__).parent.parent
CFG = BASE / "config" / "config.yaml"


def load_config() -> dict:
    """Load configuration."""
    if not CFG.exists():
        logger.warning(f"Config not found: {CFG}, using defaults")
        return {}
    with open(CFG) as f:
        return yaml.safe_load(f)


class LIDRAv3:
    """
    Main LIDRA v3 orchestrator with eBPF-powered detection.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.running = False
        self.mode = config.get('mode', 'inline')

        mode_label = {
            "inline": "INLINE BRIDGE",
            "local": "LOCAL (same-machine)",
        }.get(self.mode, "eBPF-Powered")
        logger.info("=" * 60)
        logger.info(f"LIDRA v3 - {mode_label} Detection System")
        logger.info("=" * 60)

        self.inline_engine = None
        self.bridge_manager = None
        self.tui_data_provider = None
        self._tui_process = None

        self._init_components()
    
    def _init_components(self):
        """Initialize all detection components."""

        # Database
        db_path = BASE / self.config.get('database', {}).get('path', 'data/lidra.db')
        self.db = LIDRADatabase(str(db_path))
        logger.info(f"[DB] {db_path}")

        if self.mode == 'inline':
            self._init_bridge_mode()
            return

        if self.mode == 'local':
            self._init_local_mode()
            return

        # Legacy monitor mode — eBPF / log-based
        self.tracer = create_tracer(self.config)
        loaded = self.tracer.load()

        if self.tracer.is_using_ebpf():
            logger.info("[eBPF] Kernel-level telemetry ACTIVE")
            self.detector = EBPFDetector()
        else:
            logger.info("[eBPF] FALLBACK: Using log-based detection")
            self.detector = AttackDetector(str(CFG))

        self.tracer.register_callback(self._on_security_event)

        self.mitre_mapper = MITREMapper()
        logger.info("[MITRE] ATT&CK framework loaded")

        self.anomaly_detector = AnomalyDetector()
        logger.info("[ML] Statistical anomaly detection enabled")

        self.explainer = AttackExplainer()
        logger.info("[AI] Attack explanations enabled")

        self.threat_intel = self._init_threat_intel()
        self.notifier = self._init_alerting()

        self.firewall = FirewallManager(
            backend=self.config.get('response', {}).get('firewall', 'iptables'),
            dry_run=self.config.get('response', {}).get('dry_run', True)
        )
        logger.info(f"[Firewall] dry_run={self.firewall.dry_run}")

        self.dashboard_thread = None
        self.cli_dashboard = create_cli_dashboard(self.db)
        self.cli_dashboard.print_welcome()
        logger.info("[CLI] Terminal dashboard ready")

        self.sniffer = None
        self.syslog_server = None
        self._init_collectors()

    def _push_tui_event(self, event: dict):
        """Push event to TUI — both in-process data provider and IPC subprocess."""
        if self.tui_data_provider:
            self.tui_data_provider.push_event(event)
        if self._tui_ipc_server and self._tui_ipc_server.socket_path:
            self._tui_ipc_server.broadcast_event(event)

    def _init_bridge_mode(self):
        """Initialize inline bridge mode components."""
        logger.info("=" * 60)
        logger.info("BRIDGE MODE — Inline Transparent Gateway")
        logger.info("=" * 60)

        self.detector = AttackDetector(str(CFG))
        self.mitre_mapper = MITREMapper()
        logger.info("[MITRE] ATT&CK framework loaded")

        self.anomaly_detector = AnomalyDetector()
        self.explainer = AttackExplainer()
        logger.info("[AI] Attack explanations enabled")

        self.threat_intel = self._init_threat_intel()
        self.notifier = self._init_alerting()

        self.firewall = FirewallManager(
            backend=self.config.get('response', {},).get('firewall', 'nftables'),
            dry_run=self.config.get('response', {}).get('dry_run', True)
        )
        logger.info(f"[Firewall] dry_run={self.firewall.dry_run}")

        if HAS_BRIDGE:
            self.inline_engine = InlineEngine(
                config=self.config,
                db=self.db,
                detector=self.detector,
                response_handler=self.firewall,
                metrics_collector=None
            )
            self.inline_engine.register_detection_callback(self._on_packet_detection)

            self.bridge_manager = BridgeManager(self.config)
            self.tui_data_provider = TUIDataProvider(
                inline_engine=self.inline_engine,
                bridge_manager=self.bridge_manager,
                db=self.db
            )
            self._tui_ipc_server = None
            logger.info("[Bridge] Inline engine + TUI data provider ready")
        else:
            logger.warning("[Bridge] Bridge modules not available — install dependencies")
            self.inline_engine = None
            self.bridge_manager = None

        self.dashboard_thread = None
        self.cli_dashboard = create_cli_dashboard(self.db)
        self.cli_dashboard.print_welcome()
        logger.info("[Bridge] Initialization complete")

    def _init_local_mode(self):
        logger.info("=" * 60)
        logger.info("LOCAL MODE — Same-Machine Inline Detection")
        logger.info("=" * 60)

        self.detector = AttackDetector(str(CFG))
        self.mitre_mapper = MITREMapper()
        self.anomaly_detector = AnomalyDetector()
        self.explainer = AttackExplainer()
        self.threat_intel = self._init_threat_intel()
        self.notifier = self._init_alerting()

        self.firewall = FirewallManager(
            backend='iptables',
            dry_run=self.config.get('response', {}).get('dry_run', True)
        )
        logger.info(f"[Firewall] dry_run={self.firewall.dry_run}")

        if HAS_BRIDGE:
            self.inline_engine = InlineEngine(
                config=self.config,
                db=self.db,
                detector=self.detector,
                response_handler=self.firewall,
                metrics_collector=None
            )
            self.inline_engine.register_detection_callback(self._on_packet_detection)
            self.tui_data_provider = TUIDataProvider(
                inline_engine=self.inline_engine,
                bridge_manager=None,
                db=self.db
            )
            logger.info("[Local] Inline engine + TUI data provider ready")
        else:
            logger.warning("[Local] Bridge modules not available — install dependencies")
            self.inline_engine = None

        self.dashboard_thread = None
        self.cli_dashboard = create_cli_dashboard(self.db)
        self.cli_dashboard.print_welcome()
        logger.info("[Local] Initialization complete")

    def _init_collectors(self):
        """Initialize network collectors."""
        collectors = self.config.get('collectors', {})
        network_enabled = collectors.get('network', {}).get('enabled', True)
        syslog_enabled = collectors.get('syslog', {}).get('enabled', True)

        if network_enabled:
            interface = collectors.get('network', {}).get('interface') or detect_interface()
            self.sniffer = create_sniffer(interface=interface, callback=self._on_network_event)
            logger.info(f"[Network] Packet sniffer ready (interface: {interface})")

        if syslog_enabled:
            port = collectors.get('syslog', {}).get('port', 514)
            self.syslog_server = create_syslog_server(port=port, callback=self._on_syslog_event)
            logger.info(f"[Syslog] Server ready (port: {port})")

    def _on_network_event(self, event):
        """Handle network packet events."""
        if not event:
            return

        if "attack_type" in event:
            logger.warning(f"[NETWORK] {event['attack_type']} from {event.get('source_ip', 'unknown')}")
            self._process_network_detection(event)

    def _on_syslog_event(self, event):
        """Handle syslog events."""
        if not event:
            return

        if "attack_type" in event:
            logger.warning(f"[SYSLOG] {event['attack_type']} from {event.get('source_ip', 'unknown')}")
            self._process_network_detection(event)

    def _process_network_detection(self, detection: Dict):
        """Process network/syslog detection."""
        try:
            attack_type = detection.get('attack_type', 'unknown')
            severity = detection.get('severity', 'medium')
            source_ip = detection.get('source_ip', 'unknown')

            if source_ip == 'unknown':
                return

            attacker_id = self.db.add_attacker(source_ip, "", "")
            self.db.record_attack(attacker_id, attack_type, source_log='network', raw_line=detection.get('details', ''))

            if severity in ('high', 'critical'):
                alert = Alert(
                    alert_type=attack_type,
                    severity=severity,
                    ip_address=source_ip,
                    message=detection.get('details', attack_type)
                )
                self.notifier.notify(alert)
                self.db.add_alert(attack_type, severity, source_ip, detection.get('details', '')[:500])

                if not self.config.get('response', {}).get('dry_run', True):
                    self.firewall.block_ip(source_ip, f"network_{attack_type}")
                    logger.info(f"[BLOCKED] {source_ip} via network detection")

        except Exception as e:
            logger.error(f"Network detection processing error: {e}")
    
    def _init_threat_intel(self) -> ThreatIntelOrchestrator:
        """Initialize threat intelligence."""
        providers = []
        
        abuse_key = self.config.get('threat_intel', {}).get('abuseipdb_api_key', '')
        vt_key = self.config.get('threat_intel', {}).get('virustotal_api_key', '')
        
        if abuse_key:
            providers.append(AbuseIPDBProvider(abuse_key))
        
        if vt_key:
            providers.append(VirusTotalProvider(vt_key))
        
        return ThreatIntelOrchestrator(
            providers,
            check_on_detect=self.config.get('threat_intel', {}).get('check_on_detect', True)
        )
    
    def _init_alerting(self) -> AlertNotifier:
        """Initialize alerting channels."""
        channels = []
        
        slack = self.config.get('alerts', {}).get('slack_webhook', '')
        discord = self.config.get('alerts', {}).get('discord_webhook', '')
        
        if slack:
            channels.append(SlackChannel(slack))
        
        if discord:
            channels.append(DiscordChannel(discord))
        
        return AlertNotifier(channels)
    
    def _on_packet_detection(self, event: Dict):
        """Handle detections from the inline engine pipeline."""
        try:
            data = event.get("data", {})
            detection = data.get("detection", {})
            verdict = data.get("verdict", "pass")

            attack_type = detection.get("attack_type", "unknown")
            severity = detection.get("severity", "medium")
            source_ip = detection.get("source_ip", "")
            details = detection.get("details", "")
            packet_info = data.get("packet", {})

            if not source_ip:
                return

            detected = self.detector.analyze_packet_event(detection)
            if not detected:
                return

            attacker_id = self.db.add_attacker(
                source_ip,
                country="",
                org=""
            )
            self.db.record_attack(
                attacker_id,
                attack_type,
                source_log="bridge_inline",
                raw_line=details[:500]
            )

            if severity in ("high", "critical") and verdict == "drop":
                alert = Alert(
                    alert_type=attack_type,
                    severity=severity,
                    ip_address=source_ip,
                    message=f"[INLINE] {details} — {verdict}"
                )
                self.notifier.notify(alert)
                self.db.add_alert(attack_type, severity, source_ip, details[:500])

                if not self.config.get('response', {}).get('dry_run', True):
                    self.firewall.bridge_block_ip(source_ip)
                    logger.info(f"[INLINE] Dropped & blocked {source_ip} — {attack_type}")
                    self._push_tui_event({
                            "type": "block",
                            "data": {
                                "ip": source_ip,
                                "reason": f"Inline detection: {attack_type}",
                                "timestamp": datetime.now().isoformat(),
                            }
                        })

            logger.info(f"[INLINE] {attack_type} | {source_ip} | {severity} | verdict={verdict}")

            # Push to TUI data provider
            self._push_tui_event({
                    "type": "attack",
                    "data": {
                        "ip": source_ip,
                        "type": attack_type,
                        "severity": severity,
                        "timestamp": datetime.now().isoformat(),
                    }
                })

        except Exception as e:
            logger.error(f"Packet detection callback error: {e}")

    def _on_security_event(self, event):
        """Handle security events from eBPF/logs."""
        try:
            # Analyze event for attacks
            detection = self.detector.analyze_event(event)
            
            if not detection:
                return
            
            attack_type = detection.get('attack_type', 'unknown')
            severity = detection.get('severity', 'medium')
            mitre = detection.get('mitre', [])
            
            # Get source IP
            ip_address = getattr(event, 'dst_ip', '') or getattr(event, 'ip_address', '') or 'unknown'
            
            # Enrich with threat intel
            intel = self.threat_intel.lookup_ip(ip_address)
            
            # Generate explanation
            context = {
                'detection': detection,
                'event': event,
                'threat_intel': intel
            }
            explanation = self.explainer.explain(detection, context)
            
            # Store in database
            if ip_address != 'unknown':
                attacker_id = self.db.add_attacker(
                    ip_address,
                    country=intel.get('details', {}).get('AbuseIPDB', {}).get('country'),
                    org=intel.get('details', {}).get('AbuseIPDB', {}).get('isp')
                )
                
                self.db.record_attack(
                    attacker_id,
                    attack_type,
                    source_log='ebpf' if self.tracer.is_using_ebpf() else 'log',
                    raw_line=explanation[:500]
                )
            
            # Check if we should alert
            if severity in ('high', 'critical'):
                alert = Alert(
                    alert_type=attack_type,
                    severity=severity,
                    ip_address=ip_address,
                    message=explanation
                )
                self.notifier.notify(alert)
                
                self.db.add_alert(
                    attack_type,
                    severity,
                    ip_address,
                    explanation[:500]
                )
                
                logger.warning(f"[ALERT] {attack_type} from {ip_address} - {severity}")
            
            # Auto-block if critical and configured
            if (severity == 'critical' and 
                not self.config.get('response', {}).get('dry_run', True)):
                
                if intel.get('is_malicious') or intel.get('threat_score', 0) >= 70:
                    self.firewall.block_ip(
                        ip_address,
                        self.config.get('response', {}).get('block_ttl_seconds', 3600)
                    )
                    logger.info(f"[BLOCKED] {ip_address}")
            
            # Log detection
            logger.info(f"[DETECT] {attack_type} | {ip_address} | {severity} | MITRE: {mitre}")
            
        except Exception as e:
            logger.error(f"Event processing error: {e}")
    
    def start_dashboard(self):
        """Start web dashboard."""
        try:
            from dashboard.main import app
            import uvicorn
            dash_port = self.config.get("dashboard", {}).get("port", 9090)
            
            def run_dashboard():
                uvicorn.run(app, host="0.0.0.0", port=dash_port, log_level="warning")
            
            self.dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
            self.dashboard_thread.start()
            logger.info(f"[Dashboard] http://0.0.0.0:{dash_port}")
        except Exception as e:
            logger.warning(f"Dashboard not started: {e}")
    
    def run(self):
        """Main run loop."""
        self.running = True

        if self.mode == 'inline':
            self._run_inline_mode()
            return

        if self.mode == 'local':
            self._run_local_mode()
            return

        # Legacy monitor mode
        self.tracer.start()

        if self.sniffer:
            self.sniffer.start()
        if self.syslog_server:
            self.syslog_server.start()

        sleep_time = 60 if self.config.get('mode') == 'development' else 300

        logger.info(f"[Config] Mode: {self.config.get('mode', 'production')}")
        logger.info(f"[Config] Detection: {'eBPF' if self.tracer.is_using_ebpf() else 'Log-based'}")
        logger.info(f"[Config] Cycle: {sleep_time}s")

        self.start_dashboard()
        self.cli_dashboard.start()

        try:
            while self.running:
                # Daily cleanup
                if datetime.now().hour == 3:
                    cleanup_days = self.config.get('database', {}).get('cleanup_days', 30)
                    self.db.cleanup_old_data(cleanup_days)
                    logger.info("[Cleanup] Old data removed")

                # Honeypot/Honeyfile detection
                self._detect_honeypot_events()

                # ML baseline learning (occasional)
                self._learn_baselines()

                # Push collector stats to dashboard
                if collector_state is not None:
                    collector_state.update({
                        "network": self.sniffer.get_stats() if self.sniffer else {"packets_captured": 0},
                        "syslog": self.syslog_server.get_stats() if self.syslog_server else {"messages_received": 0}
                    })
                
                logger.debug(f"[Cycle] Complete, sleeping {sleep_time}s")
                time.sleep(sleep_time)
                
        except KeyboardInterrupt:
            logger.info("LIDRA v3 stopped by user")
        finally:
            self.stop()
    
    def _run_inline_mode(self):
        """Run LIDRA in inline bridge mode."""
        logger.info("=" * 60)

        bridge_ok = False
        if self.bridge_manager:
            try:
                bridge_ok = self.bridge_manager.setup()
                if bridge_ok:
                    logger.info("[Bridge] Bridge network setup complete")
                    self.firewall.setup_bridge_nftables(
                        self.config.get('bridge', {}).get('bridge_name', 'br_lidra'),
                        self.config.get('bridge', {}).get('nfqueue_num', 0)
                    )
                else:
                    logger.warning("[Bridge] Bridge setup skipped — traffic will be captured passively")
            except Exception as e:
                logger.warning(f"[Bridge] Bridge setup failed ({e}) — falling back to passive capture")
        else:
            logger.warning("[Bridge] No bridge manager — packet processing only")

        if self.inline_engine:
            self.inline_engine.start()
            logger.info("[InlineEngine] Packet processing started")
        else:
            logger.error("[InlineEngine] Not available — cannot process packets")
            self.running = False
            return

        self.start_dashboard()

        # Start IPC server so TUI subprocess gets live data
        self._tui_ipc_server = None
        if self.tui_data_provider and TUIIPCServer:
            try:
                ipc = TUIIPCServer(
                    snapshot_fn=self.tui_data_provider.get_snapshot,
                )
                ipc.start()
                self._tui_ipc_server = ipc
                logger.info(f"[TUI-IPC] Server at {ipc.socket_path}")
            except Exception as e:
                logger.warning(f"[TUI-IPC] Failed to start: {e}")

        # Launch Textual TUI as a subprocess (main thread required by LinuxDriver)
        tui_process = None
        if self.config.get('tui', {}).get('enabled', True):
            try:
                env = dict(os.environ)
                if self._tui_ipc_server:
                    env["LIDRA_TUI_SOCKET"] = self._tui_ipc_server.socket_path
                tui_process = subprocess.Popen(
                    [sys.executable, "-m", "src.tui.app", "--standalone"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env,
                )
                logger.info(f"[TUI] Textual dashboard launched (PID {tui_process.pid})")
            except Exception as e:
                logger.warning(f"[TUI] Failed to launch: {e}")
        else:
            logger.info("[TUI] TUI disabled in config")
        self._tui_process = tui_process

        cleanup_interval = 300
        last_cleanup = time.time()

        logger.info(f"[INLINE] Bridge gateway ACTIVE — processing packets")
        logger.info(f"[INLINE] Press Ctrl+C to stop")

        try:
            while self.running:
                now = time.time()
                if now - last_cleanup > cleanup_interval:
                    cleanup_days = self.config.get('database', {}).get('cleanup_days', 30)
                    self.db.cleanup_old_data(cleanup_days)
                    self.inline_engine.blocklist.cleanup_expired()
                    logger.info("[Cleanup] Old data and expired blocks removed")
                    last_cleanup = now

                # Push periodic stats to TUI
                if self.inline_engine:
                    stats = self.inline_engine.get_stats()
                    self._push_tui_event({
                        "type": "packet",
                        "data": {
                            "pkts_per_sec": round(stats.get("packet_rate", 0), 1),
                            "mbps": round(stats.get("packets_in", 0) * 1500 / 1_000_000, 2),
                            "timestamp": datetime.now().isoformat(),
                        }
                    })
                    self._push_tui_event({
                        "type": "stats",
                        "data": {
                            "cpu_usage": psutil.cpu_percent(interval=None),
                            "memory_usage": psutil.virtual_memory().percent,
                            "active_connections": self.inline_engine.connection_tracker.get_stats().get("active_connections", 0),
                        }
                    })
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("LIDRA v3 inline mode stopped by user")
        finally:
            self.stop()

    def _ensure_nfqueue_module(self) -> bool:
        """Load nfnetlink_queue kernel module if not already loaded."""
        import os
        if os.path.exists("/proc/net/netfilter/nfnetlink_queue"):
            return True
        try:
            result = subprocess.run(
                ["modprobe", "nfnetlink_queue"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                # Give the module a moment to register
                time.sleep(0.5)
                if os.path.exists("/proc/net/netfilter/nfnetlink_queue"):
                    logger.info("[NFQUEUE] Kernel module loaded successfully")
                    return True
                else:
                    logger.warning("[NFQUEUE] modprobe succeeded but /proc entry missing")
                    return False
            else:
                logger.warning(f"[NFQUEUE] modprobe failed: {result.stderr.strip()}")
                return False
        except Exception as e:
            logger.warning(f"[NFQUEUE] Failed to load kernel module: {e}")
            return False

    def _run_local_mode(self):
        logger.info("=" * 60)

        local_cfg = self.config.get('local', {})
        queue_num = local_cfg.get('nfqueue_num', 0)

        # 1. Ensure NFQUEUE kernel module is loaded
        nfqueue_ok = self._ensure_nfqueue_module()

        # 2. Add NFQUEUE iptables rule (safe: TCP NEW only, with --queue-bypass)
        if nfqueue_ok:
            self.firewall.setup_local_iptables(queue_num)
        else:
            logger.warning("[NFQUEUE] Module not available — will use passive detection")

        if self.inline_engine:
            self.inline_engine.start()
            logger.info("[InlineEngine] Packet processing started")
        else:
            logger.error("[InlineEngine] Not available — cannot process packets")
            self.running = False
            return

        self.start_dashboard()

        # Start IPC server so TUI subprocess gets live data
        self._tui_ipc_server = None
        if self.tui_data_provider and TUIIPCServer:
            try:
                ipc = TUIIPCServer(
                    snapshot_fn=self.tui_data_provider.get_snapshot,
                )
                ipc.start()
                self._tui_ipc_server = ipc
                logger.info(f"[TUI-IPC] Server at {ipc.socket_path}")
            except Exception as e:
                logger.warning(f"[TUI-IPC] Failed to start: {e}")

        tui_process = None
        if self.config.get('tui', {}).get('enabled', True):
            try:
                env = dict(os.environ)
                if self._tui_ipc_server:
                    env["LIDRA_TUI_SOCKET"] = self._tui_ipc_server.socket_path
                tui_process = subprocess.Popen(
                    [sys.executable, "-m", "src.tui.app", "--standalone"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env,
                )
                logger.info(f"[TUI] Textual dashboard launched (PID {tui_process.pid})")
            except Exception as e:
                logger.warning(f"[TUI] Failed to launch: {e}")
        else:
            logger.info("[TUI] TUI disabled in config")
        self._tui_process = tui_process

        cleanup_interval = 300
        last_cleanup = time.time()

        logger.info(f"[LOCAL] Inline detection ACTIVE — monitoring INPUT via NFQUEUE {queue_num}")
        logger.info(f"[LOCAL] Press Ctrl+C to stop")

        try:
            while self.running:
                now = time.time()
                if now - last_cleanup > cleanup_interval:
                    cleanup_days = self.config.get('database', {}).get('cleanup_days', 30)
                    self.db.cleanup_old_data(cleanup_days)
                    if self.inline_engine:
                        self.inline_engine.blocklist.cleanup_expired()
                    logger.info("[Cleanup] Old data and expired blocks removed")
                    last_cleanup = now

                if self.inline_engine:
                    stats = self.inline_engine.get_stats()
                    self._push_tui_event({
                        "type": "packet",
                        "data": {
                            "pkts_per_sec": round(stats.get("packet_rate", 0), 1),
                            "mbps": round(stats.get("packets_in", 0) * 1500 / 1_000_000, 2),
                            "timestamp": datetime.now().isoformat(),
                        }
                    })
                    self._push_tui_event({
                        "type": "stats",
                        "data": {
                            "cpu_usage": psutil.cpu_percent(interval=None),
                            "memory_usage": psutil.virtual_memory().percent,
                            "active_connections": self.inline_engine.connection_tracker.get_stats().get("active_connections", 0),
                        }
                    })
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("LIDRA v3 local mode stopped by user")
        finally:
            self.stop()

    def _learn_baselines(self):
        """Periodically learn normal behavior patterns."""
        # This would learn from historical data
        # Skipped for v1 - can be added later

    def _detect_honeypot_events(self):
        """Detect honeypot and honeyfile hits."""
        import os

        honeypot_log = BASE / self.config.get('deception', {}).get('honeypot_log', 'logs/honeypot.log')
        state_file = BASE / self.config.get('deception', {}).get('state_file', 'state/honeypot_processed.txt')

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
            except:
                pass

        conn = self.db._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, ip_address, file_path FROM honeyfile_hits WHERE id > ?", (last_processed,))
        new_honeyfile_hits = cursor.fetchall()

        for hit_id, ip, file_path in new_honeyfile_hits:
            if ip:
                self._process_honeypot_detection(ip, "honeyfile_access", {"file_path": file_path})

        if new_ips or new_honeyfile_hits:
            with open(state_file, "a") as f:
                for ip in new_ips:
                    f.write(f"{ip}\n")
                if new_honeyfile_hits:
                    max_id = max(h[0] for h in new_honeyfile_hits)
                    f.write(f"honeyfile:{max_id}\n")

    def _process_honeypot_detection(self, ip: str, attack_type: str, details: Dict = None):
        """Process honeypot/honeyfile detection and create alert."""

        detection = {
            "attack_type": attack_type,
            "severity": "critical",
            "mitre": ["T1595", "T1589"] if attack_type == "honeypot_connection" else ["T1595", "T1083"],
            "details": details or {}
        }

        attacker_id = self.db.add_attacker(
            ip,
            country="",
            org=""
        )
        self.db.record_attack(
            attacker_id,
            attack_type,
            source_log="honeypot",
            raw_line=f"Deception system detected {attack_type} from {ip}"
        )

        alert = Alert(
            alert_type=attack_type,
            severity="critical",
            ip_address=ip,
            message=f"Honeypot/Honeyfile detection: {attack_type} from {ip}"
        )
        self.notifier.notify(alert)
        self.db.add_alert(attack_type, "critical", ip, f"Honeypot/Honeyfile detection from {ip}")

        if not self.config.get('response', {}).get('dry_run', True):
            self.firewall.block_ip(ip, f"honeypot_{attack_type}")

        logger.warning(f"[HONEYPOT] {attack_type} from {ip} - auto-blocked")
    
    def stop(self):
        """Stop LIDRA v3."""
        self.running = False

        if self.mode in ('inline', 'local'):
            if self.inline_engine:
                self.inline_engine.stop()
                logger.info("[InlineEngine] Stopped")
            if self.bridge_manager:
                self.bridge_manager.teardown()
                logger.info("[Bridge] Torn down")
            if self._tui_process:
                self._tui_process.terminate()
                try:
                    self._tui_process.wait(timeout=3)
                except Exception:
                    self._tui_process.kill()
                logger.info("[TUI] Subprocess terminated")
            if self._tui_ipc_server:
                self._tui_ipc_server.stop()
                self._tui_ipc_server = None
                logger.info("[TUI-IPC] Server stopped")
            if self.mode == 'inline':
                self.firewall.teardown_bridge_nftables()
            elif self.mode == 'local':
                local_cfg = self.config.get('local', {})
                queue_num = local_cfg.get('nfqueue_num', 0)
                self.firewall.teardown_local_iptables(queue_num)
            self.cli_dashboard.stop()
            self.db.close()
            label = "inline" if self.mode == 'inline' else "local"
            logger.info(f"LIDRA v3 ({label} mode) shutdown complete")
            return

        self.tracer.stop()
        if self.sniffer:
            self.sniffer.stop()
        if self.syslog_server:
            self.syslog_server.stop()
        self.cli_dashboard.stop()
        self.db.close()
        logger.info("LIDRA v3 (monitor mode) shutdown complete")


def main():
    """Entry point."""
    (BASE / "data").mkdir(exist_ok=True)
    (BASE / "logs").mkdir(exist_ok=True)
    (BASE / "state").mkdir(exist_ok=True)
    
    config = load_config()
    lidra = LIDRAv3(config)
    lidra.run()


if __name__ == "__main__":
    main()