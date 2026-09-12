"""LIDRA Personal — same-machine AF_PACKET detection with iptables blocking."""

from __future__ import annotations

import logging
import os

from core.agent_base import LIDRACore, _config_dry_run
from utils.interface import detect_interface
from dashboard.cli import create_cli_dashboard

logger = logging.getLogger("LIDRA-personal")

try:
    from bridge.inline_engine import InlineEngine
    from tui.data_provider import TUIDataProvider
    HAS_BRIDGE = True
except ImportError:
    InlineEngine = None
    TUIDataProvider = None
    HAS_BRIDGE = False


class LIDRAPersonal(LIDRACore):
    """Laptop / same-machine mode — AF_PACKET capture + iptables DROP."""

    def _init_mode_components(self):
        # Config-first, then auto-detect: `--interface` / local.interface must
        # win over heuristic detection, or on a box with both a dead eth0 and
        # a live wlan0 every local-mode consumer targets the wrong NIC.
        configured = (
            self.config.get("local", {}).get("interface")
            or self.config.get("collectors", {}).get("network", {}).get("interface")
        )
        iface = detect_interface(configured)
        if iface and os.path.exists(f"/sys/class/net/{iface}/wireless"):
            logger.warning(f"[WiFi] Interface {iface} is wireless — using AF_PACKET")

        from response.firewall import FirewallManager
        self.firewall = FirewallManager(
            backend=self.config.get('response', {}).get('firewall', 'iptables'),
            dry_run=_config_dry_run(self.config),
        )

        from ebpf import create_tracer
        self.tracer = create_tracer(self.config)
        self.tracer.load()
        if self.tracer.is_using_ebpf():
            logger.info("[eBPF] Kernel-level telemetry ACTIVE (local mode)")
        else:
            logger.info("[eBPF] FALLBACK: Log-based detection (local mode)")
        self.tracer.register_callback(self._on_security_event)

        self.inline_engine = None
        self.bridge_manager = None
        self.tui_data_provider = None

        if HAS_BRIDGE:
            self.inline_engine = InlineEngine(
                config=self.config, db=self.db, detector=self.detector,
                response_handler=self.firewall, metrics_collector=None,
            )
            self.inline_engine.register_detection_callback(self._on_detection_callback)
            self.tui_data_provider = TUIDataProvider(
                inline_engine=self.inline_engine, bridge_manager=None, db=self.db,
            )
            logger.info("[Local] Inline engine + TUI data provider ready")
        else:
            logger.warning("[Local] Bridge modules not available")

        self.cli_dashboard = create_cli_dashboard(self.db)
        if not self.config.get('tui', {}).get('embedded', False):
            self.cli_dashboard.print_welcome()
        logger.info("[Local] Initialization complete")

    def _start_capture(self):
        if self.inline_engine:
            self.inline_engine.start()
            logger.info("[InlineEngine] Packet processing started")
        if self.tracer:
            self.tracer.start()
            logger.info("[Tracer] Log monitoring started")
        self._launch_tui()

    def _block_ip(self, ip: str, reason: str = ""):
        self.firewall.block_ip(ip, ttl_seconds=3600)

    def _teardown_capture(self):
        if self.inline_engine:
            self.inline_engine.stop()
        if self.tracer:
            self.tracer.stop()
