import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import Dict, List, Optional, Tuple
from utils.config_loader import get_cfg

logger = logging.getLogger(__name__)


@dataclass
class Connection:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    state: str = "NEW"
    created: float = 0.0
    last_seen: float = 0.0
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    flags: List[str] = field(default_factory=list)
    app_protocol: str = ""
    tags: List[str] = field(default_factory=list)


def _connection_key(pkt: Dict) -> Tuple:
    return (
        pkt.get("src_ip", ""),
        pkt.get("dst_ip", ""),
        pkt.get("src_port", 0),
        pkt.get("dst_port", 0),
        pkt.get("protocol", ""),
    )


_HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"PATCH",
                 b"HEAD", b"OPTIONS", b"CONNECT", b"TRACE"}


def _detect_protocol_from_payload(payload: bytes) -> str:
    if not payload:
        return ""
    first_word = payload.split(b" ")[0] if b" " in payload[:16] else payload[:16]
    if first_word in _HTTP_METHODS or b"HTTP/" in payload[:64]:
        return "http"
    if payload[:4] == b"SSH-":
        return "ssh"
    if len(payload) > 5 and payload[0] == 0x16 and payload[5] in (0x01, 0x02):
        return "tls"
    if payload[:4] in (b"EHLO", b"HELO") or payload[:9] in (b"MAIL FROM", b"RCPT TO"):
        return "smtp"
    if payload[:4] in (b"USER", b"PASS") or payload[:5] == b"QUIT\r\n":
        return "ftp"
    return ""


def _get_proto_map():
    raw = get_cfg("service_port_map", {})
    if raw:
        return {int(k) if isinstance(k, str) and k.isdigit() else k: v for k, v in raw.items()}
    return {80: "http", 443: "tls", 22: "ssh", 53: "dns", 21: "ftp",
            25: "smtp", 110: "pop3", 143: "imap", 3306: "mysql",
            5432: "postgresql", 6379: "redis", 27017: "mongodb",
            8080: "http", 8081: "http", 8082: "http", 8443: "tls",
            8888: "http", 8000: "http", 3000: "http", 5000: "http"}


class ConnectionTracker:
    def __init__(self, config: dict):
        self._lock = Lock()
        self._connections: Dict[Tuple, Connection] = {}
        self._config = config

    def track(self, packet: Dict) -> Optional[Connection]:
        key = _connection_key(packet)
        now = time.time()
        src_port = packet.get("src_port", 0)
        dst_port = packet.get("dst_port", 0)

        with self._lock:
            conn = self._connections.get(key)
            if not conn:
                reverse_key = (
                    packet.get("dst_ip", ""),
                    packet.get("src_ip", ""),
                    dst_port,
                    src_port,
                    packet.get("protocol", ""),
                )
                conn = self._connections.get(reverse_key)
                if conn:
                    if conn.state in ("NEW", "SYN_SENT", "SYN_RECV"):
                        conn.state = "ESTABLISHED"
                    conn.last_seen = now
                    conn.bytes_recv += packet.get("payload_len", 0)
                    conn.packets_recv += 1
                    return conn

                conn = Connection(
                    src_ip=packet.get("src_ip", ""),
                    dst_ip=packet.get("dst_ip", ""),
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=packet.get("protocol", "tcp"),
                    created=now,
                    last_seen=now,
                )
                dst_port_key = dst_port if dst_port in _get_proto_map() else src_port
                conn.app_protocol = _get_proto_map().get(dst_port_key, "")
                payload = packet.get("payload", b"")
                if payload:
                    sniffed = _detect_protocol_from_payload(payload)
                    if sniffed:
                        conn.app_protocol = sniffed
                self._connections[key] = conn

            conn.last_seen = now
            conn.packets_sent += 1
            conn.bytes_sent += packet.get("payload_len", 0)

            flags = packet.get("flags", "")
            if "S" in flags and "A" not in flags:
                conn.state = "SYN_SENT"
                conn.flags.append("SYN")
            elif "S" in flags and "A" in flags:
                conn.state = "SYN_RECV"
            elif "F" in flags:
                conn.state = "CLOSED"
                conn.flags.append("FIN")
            elif "R" in flags:
                conn.state = "CLOSED"
                conn.flags.append("RST")

            return conn

    def get_connection(self, key: Tuple) -> Optional[Connection]:
        with self._lock:
            return self._connections.get(key)

    def get_active_connections(self, limit: int = 100) -> List[Connection]:
        with self._lock:
            active = [c for c in self._connections.values() if c.state not in ("CLOSED",)]
            sorted_active = sorted(active, key=lambda c: c.last_seen, reverse=True)
            return sorted_active[:limit]

    def get_connections_by_ip(self, ip: str) -> List[Connection]:
        with self._lock:
            return [
                c for c in self._connections.values()
                if c.src_ip == ip or c.dst_ip == ip
            ]

    def cleanup_stale(self, timeout_seconds: int = 300):
        with self._lock:
            now = time.time()
            stale = [key for key, conn in self._connections.items()
                     if now - conn.last_seen > timeout_seconds]
            for key in stale:
                del self._connections[key]
            if stale:
                logger.debug(f"[ConnTracker] Cleaned {len(stale)} stale connections")

    def get_stats(self) -> Dict:
        with self._lock:
            active = sum(1 for c in self._connections.values() if c.state not in ("CLOSED",))
            by_proto: Dict[str, int] = {}
            for c in self._connections.values():
                proto = c.app_protocol or c.protocol
                by_proto[proto] = by_proto.get(proto, 0) + 1
            return {
                "total_connections": len(self._connections),
                "active_connections": active,
                "by_protocol": by_proto,
            }
