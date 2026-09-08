"""Unix socket IPC server — bridges LIDRA engine → TUI subprocess.

The engine starts this server in a daemon thread. The TUI subprocess connects
and receives real-time events + snapshot data that the in-process engine
TUIDataProvider would have received if they shared an address space.
"""

import json
import logging
import os
import socket
import threading
from typing import Callable, Dict, Optional, Set

logger = logging.getLogger(__name__)

SOCKET_DIR = "/tmp"
SOCKET_PREFIX = "lidra_tui"


class TUIIPCServer:
    """Unix-socket server that streams engine events to the TUI subprocess."""

    def __init__(self, snapshot_fn: Callable[[], Dict], event_queue=None,
                 block_fn: Callable[[str], None] = None,
                 unblock_fn: Callable[[str], None] = None):
        self._snapshot_fn = snapshot_fn
        self._event_queue = event_queue  # Optional shared asyncio.Queue from engine's TUIDataProvider
        self._block_fn = block_fn
        self._unblock_fn = unblock_fn
        self._clients: Set[socket.socket] = set()
        self._lock = threading.Lock()
        self._running = False
        self._server_thread: Optional[threading.Thread] = None
        self._socket_path = ""
        self._server_sock: Optional[socket.socket] = None

    @property
    def socket_path(self) -> str:
        return self._socket_path

    def start(self):
        pid = os.getpid()
        self._socket_path = f"{SOCKET_DIR}/{SOCKET_PREFIX}_{pid}.sock"

        # Cleanup stale socket from previous run
        try:
            os.unlink(self._socket_path)
        except FileNotFoundError:
            logger.debug("[TUI-IPC] No stale socket to unlink")

        self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_sock.bind(self._socket_path)
        # ponytail: agent runs as root, TUI as the user — without this the
        # TUI silently falls back to mock data and shows fake attackers.
        # Local single-user tool; restrict the dir if multi-user matters.
        os.chmod(self._socket_path, 0o666)
        self._server_sock.listen(5)
        self._server_sock.settimeout(1.0)
        self._running = True

        self._server_thread = threading.Thread(
            target=self._accept_loop, daemon=True, name="tui-ipc-server"
        )
        self._server_thread.start()
        logger.info(f"[TUI-IPC] Server listening on {self._socket_path}")

    def stop(self):
        self._running = False
        with self._lock:
            for client in list(self._clients):
                try:
                    client.close()
                except Exception:
                    logger.debug("[TUI-IPC] Client close error (remote disconnect)")
            self._clients.clear()
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                logger.debug("[TUI-IPC] Server socket close error")
        try:
            os.unlink(self._socket_path)
        except FileNotFoundError:
            logger.debug("[TUI-IPC] Socket path already removed")
        logger.info("[TUI-IPC] Server stopped")

    def broadcast_event(self, event: dict):
        """Push an event to all connected TUI clients."""
        if not self._running or not self._clients:
            return
        payload = (json.dumps({"type": "event", "data": event}) + "\n").encode()
        dead = set()
        with self._lock:
            for client in self._clients:
                try:
                    client.sendall(payload)
                except Exception:
                    dead.add(client)
            for client in dead:
                self._clients.discard(client)
                try:
                    client.close()
                except Exception:
                    logger.debug("[TUI-IPC] Dead client close error")

    def _accept_loop(self):
        while self._running:
            try:
                client, _ = self._server_sock.accept()
                client.settimeout(5.0)
                with self._lock:
                    self._clients.add(client)
                # Handle client in a dedicated thread
                threading.Thread(
                    target=self._handle_client, args=[client], daemon=True
                ).start()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.warning("[TUI-IPC] Accept error")
                break

    def _handle_client(self, client: socket.socket):
        """Handle a single TUI client connection."""
        buf = b""
        try:
            while self._running:
                try:
                    data = client.recv(4096)
                except socket.timeout:
                    # Send periodic heartbeat
                    continue
                except Exception:
                    break

                if not data:
                    break

                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        msg = json.loads(line)
                        self._handle_message(msg, client)
                    except json.JSONDecodeError:
                        continue
        finally:
            with self._lock:
                self._clients.discard(client)
            try:
                client.close()
            except Exception:
                logger.debug("[TUI-IPC] Client cleanup error")

    def _handle_message(self, msg: dict, client: socket.socket):
        cmd = msg.get("command", "")
        if cmd == "SUBSCRIBE":
            ack = (json.dumps({"type": "event", "data": {"type": "subscribed"}}) + "\n").encode()
            try:
                client.sendall(ack)
            except Exception:
                pass
        elif cmd == "SNAPSHOT":
            try:
                snapshot = self._snapshot_fn()
                payload = (json.dumps({"type": "snapshot", "data": snapshot}) + "\n").encode()
                client.sendall(payload)
            except Exception as e:
                logger.warning(f"[TUI-IPC] Snapshot error: {e}")
        elif cmd == "BLOCK":
            ip = msg.get("ip", "")
            reason = msg.get("reason", "tui_block")
            if ip and self._block_fn:
                try:
                    self._block_fn(ip, reason)
                    logger.info(f"[TUI-IPC] Blocked {ip} from TUI")
                except Exception as e:
                    logger.warning(f"[TUI-IPC] Block {ip} failed: {e}")
        elif cmd == "UNBLOCK":
            ip = msg.get("ip", "")
            if ip and self._unblock_fn:
                try:
                    self._unblock_fn(ip)
                    logger.info(f"[TUI-IPC] Unblocked {ip} from TUI")
                except Exception as e:
                    logger.warning(f"[TUI-IPC] Unblock {ip} failed: {e}")