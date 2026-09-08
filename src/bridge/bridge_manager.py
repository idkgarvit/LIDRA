import logging
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.interface import detect_interface

logger = logging.getLogger(__name__)

class BridgeManager:
    def __init__(self, config: dict):
        self._config = config.get("bridge", {})
        self._wan = self._config.get("interfaces", {}).get("wan") or detect_interface()
        self._lan = self._config.get("interfaces", {}).get("lan") or detect_interface()
        self._bridge_name = self._config.get("bridge_name", "br_lidra")
        self._mgmt_ip = self._config.get("management_ip", "10.0.0.1/24")
        self._stp_enabled = self._config.get("stp_enabled", True)
        self._bridge_up = False

    def _run(self, cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
        logger.debug(f"[Bridge] Running: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=30)
            if result.returncode != 0:
                logger.warning(f"[Bridge] Command failed: {result.stderr.strip()}")
            return result
        except subprocess.TimeoutExpired:
            logger.error(f"[Bridge] Command timed out: {' '.join(cmd)}")
            raise
        except FileNotFoundError:
            logger.error(f"[Bridge] Command not found: {cmd[0]}. Is it installed?")
            raise

    def setup(self) -> bool:
        try:
            self._create_bridge()
            self._enslave_interfaces()
            self._configure_stp()
            self._assign_management_ip()
            # nftables queue rules are managed by FirewallManager.setup_bridge_nftables()
            self._bridge_up = True
            logger.info(f"[Bridge] {self._bridge_name} ready (WAN={self._wan}, LAN={self._lan})")
            return True
        except Exception as e:
            logger.error(f"[Bridge] Setup failed: {e}")
            self._bridge_up = False
            return False

    def _create_bridge(self):
        self._run(["ip", "link", "add", "name", self._bridge_name, "type", "bridge"])
        self._run(["ip", "link", "set", self._bridge_name, "up"])
        logger.info(f"[Bridge] Created {self._bridge_name}")

    def _enslave_interfaces(self):
        for iface in [self._wan, self._lan]:
            self._run(["ip", "link", "set", iface, "down"])
            self._run(["ip", "link", "set", iface, "master", self._bridge_name])
            self._run(["ip", "link", "set", iface, "up"])
            logger.info(f"[Bridge] Enslaved {iface} to {self._bridge_name}")

    def _configure_stp(self):
        if self._stp_enabled:
            self._run(["ip", "link", "set", self._bridge_name, "type", "bridge", "stp_state", "1"])
        else:
            self._run(["ip", "link", "set", self._bridge_name, "type", "bridge", "stp_state", "0"])
        logger.info(f"[Bridge] STP {'enabled' if self._stp_enabled else 'disabled'}")

    def _assign_management_ip(self):
        self._run(["ip", "addr", "add", self._mgmt_ip, "dev", self._bridge_name])
        logger.info(f"[Bridge] Management IP: {self._mgmt_ip}")

    def teardown(self):
        if not self._bridge_up:
            return
        try:
            # nftables teardown handled by FirewallManager.teardown_bridge_nftables()
            self._release_interfaces()
            self._run(["ip", "link", "set", self._bridge_name, "down"], check=False)
            self._run(["ip", "link", "delete", self._bridge_name], check=False)
            self._bridge_up = False
            logger.info(f"[Bridge] {self._bridge_name} removed")
        except Exception as e:
            logger.error(f"[Bridge] Teardown error: {e}")

    def _release_interfaces(self):
        for iface in [self._wan, self._lan]:
            self._run(["ip", "link", "set", iface, "nomaster"], check=False)

    def get_bridge_info(self) -> Dict:
        info = {
            "bridge_name": self._bridge_name,
            "wan": self._wan,
            "lan": self._lan,
            "is_up": self._bridge_up,
            "mgmt_ip": self._mgmt_ip,
            "stp_enabled": self._stp_enabled,
        }
        try:
            result = self._run(["ip", "-d", "link", "show", self._bridge_name], check=False)
            info["details"] = result.stdout.strip()
        except Exception:
            info["details"] = ""
        return info

    def is_healthy(self) -> bool:
        if not self._bridge_up:
            return False
        try:
            result = self._run(["ip", "link", "show", self._bridge_name], check=False)
            return "state UP" in result.stdout or "UP" in result.stdout.split("<")[1].split(">")[0] if ">" in result.stdout else False
        except Exception:
            return False

    def reload_config(self, config: dict):
        self._config = config.get("bridge", {})
        self._wan = self._config.get("interfaces", {}).get("wan") or detect_interface()
        self._lan = self._config.get("interfaces", {}).get("lan") or detect_interface()
        self._stp_enabled = self._config.get("stp_enabled", True)
        logger.info("[Bridge] Config reloaded")
