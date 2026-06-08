import json
import logging
import os
import socket
import ssl
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class FederatedExchange:
    def __init__(self, config: dict = None):
        self._config = config or {}
        self._peers: List[Dict] = self._config.get("peers", [])
        self._my_id = self._config.get("node_id", socket.gethostname())
        self._private_key = self._config.get("private_key", "")
        self._trust_scores: Dict[str, float] = defaultdict(lambda: 0.5)
        self._shared_iocs: Dict[str, Set[str]] = defaultdict(set)
        self._lock = threading.Lock()
        self._sync_interval = self._config.get("sync_interval", 300)

    def share_ioc(self, ioc_type: str, value: str, confidence: float = 0.8):
        with self._lock:
            self._shared_iocs[ioc_type].add(value)
        msg = {
            "type": "ioc_share",
            "node": self._my_id,
            "ioc_type": ioc_type,
            "value": value,
            "confidence": confidence,
            "timestamp": time.time(),
        }
        for peer in self._peers:
            self._send(peer, msg)

    def receive_ioc(self, msg: Dict) -> Optional[Dict]:
        peer_id = msg.get("node", "")
        ioc_type = msg.get("ioc_type", "")
        value = msg.get("value", "")
        confidence = msg.get("confidence", 0.5)

        trust = self._trust_scores[peer_id]
        adjusted = confidence * trust

        if adjusted > 0.3:
            with self._lock:
                self._shared_iocs[ioc_type].add(value)
            return {"type": "ioc_share", "ioc_type": ioc_type, "value": value, "effective_confidence": adjusted}
        return None

    def _send(self, peer: Dict, msg: Dict):
        try:
            host = peer.get("host", "")
            port = peer.get("port", 8444)
            use_tls = peer.get("tls", True)
            data = json.dumps(msg).encode()

            sock = socket.create_connection((host, port), timeout=5)
            if use_tls:
                ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock)
            sock.sendall(data + b"\n")
            sock.close()
            self._trust_scores[peer["host"]] = min(self._trust_scores[peer["host"]] + 0.05, 1.0)
        except Exception as e:
            logger.debug(f"[Federated] Send to {peer.get('host')} failed: {e}")
            self._trust_scores[peer.get("host", "")] = max(self._trust_scores[peer.get("host", "")] - 0.1, 0.0)

    def get_iocs(self) -> Dict[str, Set[str]]:
        with self._lock:
            return dict(self._shared_iocs)

    def get_trust_scores(self) -> Dict[str, float]:
        return dict(self._trust_scores)
