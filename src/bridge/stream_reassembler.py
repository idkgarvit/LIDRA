import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class TcpStream:
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    client_buffer: bytearray = field(default_factory=bytearray)
    server_buffer: bytearray = field(default_factory=bytearray)
    client_seq: int = 0
    server_seq: int = 0
    last_activity: float = 0.0
    is_complete: bool = False


_STREAM_KEY = Tuple[str, str, int, int]


def _stream_key(client_ip: str, server_ip: str, client_port: int, server_port: int) -> _STREAM_KEY:
    return (client_ip, server_ip, client_port, server_port)


class StreamReassembler:
    def __init__(self, max_streams: int = 10000):
        self._streams: Dict[_STREAM_KEY, TcpStream] = {}
        self._max_streams = max_streams

    def add_segment(self, packet: Dict, direction: str = "client") -> Optional[List[bytes]]:
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        src_port = packet.get("src_port", 0)
        dst_port = packet.get("dst_port", 0)
        seq = packet.get("tcp_seq", 0)
        payload = packet.get("payload", b"")

        if not payload:
            return None

        if direction == "client":
            key = _stream_key(src_ip, dst_ip, src_port, dst_port)
            is_client = True
        else:
            key = _stream_key(dst_ip, src_ip, dst_port, src_port)
            is_client = False

        stream = self._streams.get(key)
        if not stream:
            if len(self._streams) >= self._max_streams:
                return None
            stream = TcpStream(
                client_ip=src_ip if is_client else dst_ip,
                server_ip=dst_ip if is_client else src_ip,
                client_port=src_port if is_client else dst_port,
                server_port=dst_port if is_client else src_port,
            )
            self._streams[key] = stream

        stream.last_activity = time.time()

        if is_client:
            if payload and seq >= stream.client_seq:
                stream.client_buffer.extend(payload)
                stream.client_seq = seq + len(payload)
                complete_messages = self._extract_messages(stream.client_buffer, stream.server_port)
                return complete_messages
        else:
            if payload and seq >= stream.server_seq:
                stream.server_buffer.extend(payload)
                stream.server_seq = seq + len(payload)
                complete_messages = self._extract_messages(stream.server_buffer, stream.server_port)
                return complete_messages

        return None

    def _extract_messages(self, buffer: bytearray, dst_port: int) -> List[bytes]:
        messages = []
        if dst_port == 80:
            while True:
                header_end = buffer.find(b"\r\n\r\n")
                if header_end == -1:
                    break
                content_start = header_end + 4
                content_length = 0
                header_part = buffer[:header_end].decode("utf-8", errors="replace")
                for line in header_part.split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        try:
                            content_length = int(line.split(":")[1].strip())
                        except ValueError:
                            break
                total_size = content_start + content_length
                if len(buffer) >= total_size:
                    msg = bytes(buffer[:total_size])
                    messages.append(msg)
                    del buffer[:total_size]
                else:
                    break
        return messages

    def get_stream(self, key: _STREAM_KEY) -> Optional[TcpStream]:
        return self._streams.get(key)

    def cleanup_stale(self, timeout: int = 300):
        now = time.time()
        stale = [key for key, stream in self._streams.items()
                 if now - stream.last_activity > timeout]
        for key in stale:
            del self._streams[key]
        if stale:
            logger.debug(f"[StreamReasm] Cleaned {len(stale)} stale streams")
