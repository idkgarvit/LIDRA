"""LIDRA Gateway — transparent inline bridge with NFQUEUE / NF_DROP."""

from __future__ import annotations

import logging

from core.agent_base import LIDRACore, _config_dry_run
from dashboard.cli import create_cli_dashboard

logger = logging.getLogger("LIDRA-gateway")

try:
    from bridge.inline_engine import InlineEngine
    from bridge.bridge_manager import BridgeManager
    from tui.data_provider import TUIDataProvider
    HAS_BRIDGE = True
except ImportError:
    InlineEngine = None
    BridgeManager = None
    TUIDataProvider = None
    HAS_BRIDGE = False


class LIDRAGateway(LIDRACore):
    """Transparent inline gateway mode — NFQUEUE capture + NF_DROP verdicts."""

    def _init_mode_components(self):
        from response.firewall import FirewallManager
        self.firewall = FirewallManager(
            backend=self.config.get('response', {}).get('firewall', 'nftables'),
            dry_run=_config_dry_run(self.config),
        )

        self.inline_engine = None
        self.bridge_manager = None
        self.tui_data_provider = None

        if HAS_BRIDGE:
            self.inline_engine = InlineEngine(
                config=self.config, db=self.db, detector=self.detector,
                response_handler=self.firewall, metrics_collector=None,
            )
            self.inline_engine.register_detection_callback(self._on_detection_callback)

            self.bridge_manager = BridgeManager(self.config)
            self.tui_data_provider = TUIDataProvider(
                inline_engine=self.inline_engine, bridge_manager=self.bridge_manager, db=self.db,
            )
            logger.info("[Gateway] Inline engine + bridge + TUI data provider ready")
        else:
            logger.warning("[Gateway] Bridge modules not available")

        self.cli_dashboard = create_cli_dashboard(self.db)
        self.cli_dashboard.print_welcome()
        logger.info("[Gateway] Initialization complete")

    def _start_capture(self):
        bridge_ok = False
        if self.bridge_manager:
            try:
                bridge_ok = self.bridge_manager.setup()
                if bridge_ok:
                    logger.info("[Gateway] Bridge network setup complete")
                    self.firewall.setup_bridge_nftables(
                        self.config.get('bridge', {}).get('bridge_name', 'br_lidra'),
                        self.config.get('bridge', {}).get('nfqueue_num', 0),
                    )
                else:
                    logger.warning("[Gateway] Bridge setup skipped — passive capture")
            except Exception as e:
                logger.warning(f"[Gateway] Bridge setup failed ({e}) — passive capture")

        if self.inline_engine:
            self.inline_engine.start()
            logger.info("[Gateway] Packet processing started")
        else:
            logger.error("[Gateway] No inline engine — cannot process packets")
            self.running = False
            return

        self._launch_tui()

    def _block_ip(self, ip: str, reason: str = ""):
        # ponytail: own IPs (mgmt + locals) must never be bridge-blocked —
        # multicast noise scores the gateway itself and one self-block kills it.
        try:
            from utils.interface import local_ips
            own = set(local_ips())
        except Exception:
            own = set()
        mgmt = str(self.config.get("bridge", {}).get("management_ip", "")).split("/")[0]
        if mgmt:
            own.add(mgmt)
        self.firewall.bridge_block_ip(ip, own_ips=own)

    def _teardown_capture(self):
        if self.inline_engine:
            self.inline_engine.stop()

        if self.bridge_manager:
            self.bridge_manager.teardown()

        self.firewall.teardown_bridge_nftables()
