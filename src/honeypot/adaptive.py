import json
import logging
import os
import socket
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_MITRE_STAGE_MAP = {
    "T1046": {"service": "http", "port": 80},
    "T1190": {"service": "http", "port": 80},
    "T1021": {"service": "ssh", "port": 22},
    "T1572": {"service": "dns", "port": 53},
    "T1505": {"service": "http", "port": 443},
}


class AdaptiveHoneypot:
    def __init__(self, config: dict = None):
        self._config = config or {}
        self._deploy_dir = Path(self._config.get("deploy_dir", "./state/honeypots"))
        self._deploy_dir.mkdir(parents=True, exist_ok=True)
        self._active_pots: Dict[str, Dict] = {}
        self._lock = threading.Lock()

    def deploy_for_mitre(self, mitre_ids: List[str], src_ip: str) -> Optional[Dict]:
        for mitre_id in mitre_ids:
            stage = _MITRE_STAGE_MAP.get(mitre_id)
            if stage:
                return self._deploy(stage["service"], stage["port"], src_ip)
        return None

    def _deploy(self, service: str, port: int, src_ip: str) -> Optional[Dict]:
        key = f"{src_ip}_{service}"
        with self._lock:
            if key in self._active_pots:
                return self._active_pots[key]

        if service == "ssh":
            return self._deploy_cowrie(port, src_ip)
        elif service == "http":
            return self._deploy_http(port, src_ip)
        return None

    def _deploy_cowrie(self, port: int, src_ip: str) -> Dict:
        config = {
            "type": "cowrie",
            "port": port,
            "target_ip": src_ip,
            "deployed_at": datetime.now().isoformat(),
        }
        logger.info(f"[Honeypot] Deployed cowrie on port {port} for {src_ip}")
        return config

    def _deploy_http(self, port: int, src_ip: str) -> Dict:
        config = {
            "type": "http",
            "port": port,
            "target_ip": src_ip,
            "deployed_at": datetime.now().isoformat(),
        }
        logger.info(f"[Honeypot] Deployed HTTP honeypot on port {port} for {src_ip}")
        return config

    def record_interaction(self, src_ip: str, data: Dict):
        log_path = self._deploy_dir / f"{src_ip}.jsonl"
        try:
            with open(log_path, "a") as f:
                f.write(json.dumps({"ts": time.time(), **data}) + "\n")
        except Exception as e:
            logger.warning(f"[Honeypot] Log failed: {e}")

    def cleanup(self):
        with self._lock:
            self._active_pots.clear()
            logger.info("[Honeypot] All honeypots cleaned up")
