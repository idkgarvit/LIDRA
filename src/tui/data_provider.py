"""Data bridge between LIDRA engine and Textual TUI.

Three modes:
  - mock (standalone testing): random fake data
  - real (in-process): connected to InlineEngine directly (shared memory)
  - ipc (subprocess): connected via Unix socket to engine process
"""

import asyncio
import json
import os
import random
import socket
import time
import psutil
from typing import AsyncGenerator, Dict, List, Optional
from datetime import datetime


def _resolve_socket_path() -> Optional[str]:
    """Find the most recent LIDRA TUI IPC socket."""
    sock_dir = "/tmp"
    prefix = "lidra_tui_"
    candidates = []
    try:
        for name in os.listdir(sock_dir):
            if name.startswith(prefix) and name.endswith(".sock"):
                pid = name[len(prefix):-5]
                path = os.path.join(sock_dir, name)
                if pid.isdigit() and os.path.exists(f"/proc/{pid}"):
                    candidates.append((int(pid), path))
    except (PermissionError, FileNotFoundError):
        pass
    if candidates:
        candidates.sort(reverse=True)
        return candidates[0][1]
    return None


class TUIDataProvider:
    """Bridges LIDRA engine to Textual TUI."""

    def __init__(self, inline_engine=None, bridge_manager=None, db=None):
        self._engine = inline_engine
        self._bridge = bridge_manager
        self._db = db
        self._queue: asyncio.Queue = asyncio.Queue()
        self._start_time = time.time()

        # IPC mode: if engine not provided but socket exists
        self._socket_path = None
        engine_provided = inline_engine is not None

        if not engine_provided:
            # Check env var first (set by lidra_agent_v3 when launching TUI)
            env_path = os.environ.get("LIDRA_TUI_SOCKET")
            if env_path and os.path.exists(env_path):
                self._socket_path = env_path
            else:
                path = _resolve_socket_path()
                if path:
                    self._socket_path = path
            if self._socket_path:
                self._reader_task: Optional[asyncio.Task] = None

        self.is_mock = (not engine_provided) and (self._socket_path is None)
        if self._socket_path:
            self._mode = "ipc"
        elif engine_provided:
            self._mode = "real"
        else:
            self._mode = "mock"

    # ── Engine pushes events here (only in 'real' mode) ──────────────────
    def push_event(self, event: dict):
        """Thread-safe push from the non-async engine into the async TUI."""
        self._queue.put_nowait(event)

    # ── Async subscription consumed by the TUI ─────────────────────────
    async def subscribe(self) -> AsyncGenerator[Dict, None]:
        """Yield events as they arrive."""
        if self.is_mock:
            async for ev in self._mock_events():
                yield ev
        elif self._mode == "ipc":
            async for ev in self._ipc_events():
                yield ev
        else:
            while True:
                try:
                    event = await asyncio.wait_for(self._queue.get(), timeout=0.25)
                    yield event
                except asyncio.TimeoutError:
                    yield {"type": "heartbeat", "data": {}}

    async def _ipc_events(self) -> AsyncGenerator[Dict, None]:
        """Connect to the engine's IPC server and receive real-time events."""
        reader, writer = None, None
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(self._socket_path)
            sock.setblocking(False)
            loop = asyncio.get_event_loop()
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            transport, _ = await loop.create_connection(
                lambda: protocol, sock=sock
            )
            writer = transport

            # Subscribe to events
            writer.write(b'{"command": "SUBSCRIBE"}\n')
            await writer.drain()

            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=1.0)
                except asyncio.TimeoutError:
                    # Poll for snapshot periodically
                    writer.write(b'{"command": "SNAPSHOT"}\n')
                    await writer.drain()
                    yield {"type": "heartbeat", "data": {}}
                    continue

                if not line:
                    break

                try:
                    msg = json.loads(line.decode().strip())
                    msg_type = msg.get("type", "")
                    if msg_type == "event":
                        yield msg["data"]
                    elif msg_type == "snapshot":
                        yield {"type": "snapshot", "data": msg["data"]}
                    elif msg_type == "heartbeat":
                        yield {"type": "heartbeat", "data": {}}
                except (json.JSONDecodeError, KeyError):
                    continue

        except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
            # Fallback to mock if IPC fails
            self.is_mock = True
            async for ev in self._mock_events():
                yield ev
        finally:
            if writer:
                try:
                    writer.close()
                except Exception:
                    pass

    async def _mock_events(self) -> AsyncGenerator[Dict, None]:
        while True:
            etype = random.choices(
                ["attack", "packet", "block", "stats"], weights=[0.1, 0.7, 0.05, 0.15], k=1
            )[0]
            data = {}
            if etype == "attack":
                data = {
                    "ip": f"192.168.1.{random.randint(10, 250)}",
                    "type": random.choice(["SQLi", "XSS", "Brute Force", "Port Scan"]),
                    "severity": random.choice(["critical", "high", "medium"]),
                    "timestamp": datetime.now().isoformat(),
                }
            elif etype == "packet":
                data = {
                    "pkts_per_sec": random.randint(100, 1500),
                    "mbps": random.uniform(0.5, 50.0),
                    "timestamp": datetime.now().isoformat(),
                }
            elif etype == "block":
                data = {
                    "ip": f"10.0.0.{random.randint(2, 254)}",
                    "reason": "Repeated attacks",
                    "timestamp": datetime.now().isoformat(),
                }
            elif etype == "stats":
                data = {
                    "cpu_usage": random.uniform(5.0, 45.0),
                    "memory_usage": random.uniform(20.0, 60.0),
                    "active_connections": random.randint(10, 500),
                }
            yield {"type": etype, "data": data}
            await asyncio.sleep(random.uniform(0.1, 1.0))

    # ── Snapshot (polled by the TUI every ~1 s) ────────────────────────
    def get_snapshot(self) -> Dict:
        if self.is_mock:
            return self._mock_snapshot()

        if self._mode == "ipc":
            return self._mock_snapshot()  # fallback — real snapshots come via IPC stream

        engine_stats = self._engine.get_stats() if self._engine else {}
        uptime_s = int(time.time() - self._start_time)
        hours, remainder = divmod(uptime_s, 3600)
        minutes, seconds = divmod(remainder, 60)

        blocklist = self._engine.blocklist if self._engine else None
        rate_limiter = self._engine.rate_limiter if self._engine else None
        conn_tracker = self._engine.connection_tracker if self._engine else None

        active_blocks = blocklist.get_all() if blocklist else []
        top_talkers = rate_limiter.get_top_talkers(10) if rate_limiter else []
        conn_stats = conn_tracker.get_stats() if conn_tracker else {}
        active_conns = conn_tracker.get_active_connections(50) if conn_tracker else []

        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        bridge_status = "UP" if (self._bridge and self._bridge.is_healthy()) else "DOWN"

        return {
            "stats": {
                "total_packets": engine_stats.get("packets_in", 0),
                "total_attacks": engine_stats.get("packets_dropped", 0),
                "uptime": f"{hours:02d}:{minutes:02d}:{seconds:02d}",
            },
            "top_attackers": [
                {"ip": r.ip, "attacks": r.packet_count, "severity": "high" if r.is_throttled else "medium"}
                for r in top_talkers
            ],
            "connections": active_conns,
            "blocks": [
                {"ip": b["ip"], "reason": b.get("reason", ""), "timestamp": b.get("expires_at", "")}
                for b in active_blocks
            ],
            "system": {"cpu_percent": cpu, "memory_percent": mem, "bridge_status": bridge_status},
            "mitre": {},
        }

    def _mock_snapshot(self) -> Dict:
        return {
            "stats": {
                "total_packets": random.randint(100000, 1000000),
                "total_attacks": random.randint(100, 1000),
                "uptime": "02:14:55",
            },
            "top_attackers": [
                {"ip": f"45.33.2.{i}", "attacks": random.randint(50, 200), "severity": "high", "country": "RU"}
                for i in range(1, 6)
            ],
            "connections": [],
            "blocks": [
                {"ip": f"185.12.3.{i}", "reason": "DDoS", "timestamp": "2026-05-30 10:00:00"}
                for i in range(1, 4)
            ],
            "system": {"cpu_percent": 12.5, "memory_percent": 34.2, "bridge_status": "UP"},
            "mitre": {},
        }

    def on_block(self, ip: str):
        if self._engine:
            self._engine.blocklist.block(ip, "manual", 3600)

    def on_unblock(self, ip: str):
        if self._engine:
            self._engine.blocklist.unblock(ip)