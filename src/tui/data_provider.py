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
import sqlite3
import time
import logging
import psutil
from typing import AsyncGenerator, Dict, List, Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_DB_CANDIDATES = (
    "data/lidra.db",
    "./data/lidra.db",
    "/path/to/LIDRA/data/lidra.db",
)


def _resolve_db_path() -> Optional[Path]:
    """Locate the LIDRA SQLite database, trying a few common locations."""
    env = os.environ.get("LIDRA_DB_PATH")
    candidates: List[Path] = []
    if env:
        candidates.append(Path(env))
    candidates.extend(Path(p) for p in _DEFAULT_DB_CANDIDATES)
    for c in candidates:
        try:
            if c.exists():
                return c
        except OSError:
            continue
    cwd_db = Path.cwd() / "data" / "lidra.db"
    if cwd_db.exists():
        return cwd_db
    return None

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
        logger.debug("[TUI] No socket candidates")
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
        self._ipc_failed = False
        try:
            psutil.cpu_percent()  # prime: first real call always returns 0.0
        except Exception:
            pass

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

        self._last_ipc_snapshot: Optional[Dict] = None
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
        writer = None
        try:
            # ponytail: raw transports have no drain() on 3.8+ — the old
            # create_connection dance crashed every IPC stream. One call,
            # proper StreamWriter.
            reader, writer = await asyncio.open_unix_connection(
                path=self._socket_path)

            # Subscribe to events
            writer.write(b'{"command": "SUBSCRIBE"}\n')
            await writer.drain()

            import time as _time
            last_poll = 0.0

            async def _poll_snapshot():
                nonlocal last_poll
                writer.write(b'{"command": "SNAPSHOT"}\n')
                await writer.drain()
                last_poll = _time.monotonic()

            await _poll_snapshot()
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=1.0)
                except asyncio.TimeoutError:
                    await _poll_snapshot()
                    yield {"type": "heartbeat", "data": {}}
                    continue
                # ponytail: busy engines never hit the 1s idle timeout, so
                # without this the panels starve on a live network.
                if _time.monotonic() - last_poll > 5:
                    await _poll_snapshot()

                if not line:
                    break

                try:
                    msg = json.loads(line.decode().strip())
                    msg_type = msg.get("type", "")
                    if msg_type == "event":
                        yield msg["data"]
                    elif msg_type == "snapshot":
                        self._last_ipc_snapshot = msg["data"]
                        yield {"type": "snapshot", "data": msg["data"]}
                    elif msg_type == "heartbeat":
                        yield {"type": "heartbeat", "data": {}}
                except (json.JSONDecodeError, KeyError):
                    continue

        except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
            # Agent unreachable: stay quiet, don't invent attacks.
            self._ipc_failed = True
            logger.warning("[TUI] IPC failed (%s) — showing offline, not mock", e)
            while True:
                await asyncio.sleep(1)
                yield {"type": "heartbeat", "data": {}}
        finally:
            if writer:
                try:
                    writer.close()
                except Exception:
                    logger.debug("[TUI] Writer close error")

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
            if self._last_ipc_snapshot:
                return self._last_ipc_snapshot
            # ponytail: no fake attackers when the agent is unreachable —
            # an honestly empty "offline" panel beats mock data masquerading
            # as detections. Status bar surfaces system.mode == "offline".
            return {
                "stats": {"total_packets": 0, "total_attacks": 0, "uptime": "00:00:00"},
                "top_attackers": [],
                "connections": [],
                "blocks": [],
                "system": {"cpu_percent": 0.0, "memory_percent": 0.0,
                           "bridge_status": "UNKNOWN", "mode": "offline",
                           "interface": os.environ.get("LIDRA_INTERFACE", "eth0"),
                           "environment": "ipc"},
                "mitre": {},
                "protocols": {},
                "offline": True,
            }

        engine_stats = self._engine.get_stats() if self._engine else {}
        uptime_s = int(time.time() - self._start_time)
        hours, remainder = divmod(uptime_s, 3600)
        minutes, seconds = divmod(remainder, 60)

        blocklist = self._engine.blocklist if self._engine else None
        rate_limiter = self._engine.rate_limiter if self._engine else None
        conn_tracker = self._engine.connection_tracker if self._engine else None

        active_blocks = blocklist.get_all() if blocklist else []
        top_talkers = rate_limiter.get_top_talkers(10) if rate_limiter else []
        active_conns = conn_tracker.get_active_connections(50) if conn_tracker else []

        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        bridge_status = "UP" if (self._bridge and self._bridge.is_healthy()) else "DOWN"

        attacker_countries = self._get_attacker_countries([r.ip for r in top_talkers]) if top_talkers else {}

        try:
            protocols = self.get_protocol_breakdown(60)
        except Exception:
            protocols = {}

        return {
            "stats": {
                "total_packets": engine_stats.get("packets_in", 0),
                "total_attacks": engine_stats.get("packets_dropped", 0),
                "uptime": f"{hours:02d}:{minutes:02d}:{seconds:02d}",
            },
            "top_attackers": [
                {
                    "ip": r.ip,
                    "attacks": r.packet_count,
                    "severity": "high" if r.is_throttled else "medium",
                    "country": attacker_countries.get(r.ip, "??"),
                }
                for r in top_talkers
            ],
            # ponytail: raw Connection dataclasses killed json.dumps in
            # the IPC server — every snapshot silently died server-side.
            "connections": [
                {
                    "src_ip": c.src_ip, "src_port": c.src_port,
                    "dst_ip": c.dst_ip, "dst_port": c.dst_port,
                    "protocol": c.protocol, "state": c.state,
                    "bytes": c.bytes_sent + c.bytes_recv,
                    "duration": f"{max(0, c.last_seen - c.created):.0f}s",
                }
                for c in active_conns
            ],
            "blocks": [
                {"ip": b["ip"], "reason": b.get("reason", ""), "timestamp": b.get("expires_at", "")}
                for b in active_blocks
            ],
            "system": {"cpu_percent": cpu, "memory_percent": mem, "bridge_status": bridge_status,
                         "interface": self._engine_interface(),
                         "environment": "local",
                         "mode": self._engine_mode()},
            "mitre": {},
            "protocols": protocols,
        }

    def _engine_interface(self) -> str:
        """Best-effort capture interface name for the status bar."""
        try:
            if self._engine is not None and hasattr(self._engine, "_get_interface"):
                return str(self._engine._get_interface())
        except Exception:
            pass
        return os.environ.get("LIDRA_INTERFACE", "eth0")

    def _engine_mode(self) -> str:
        """Wire truth: monitor (log-only) vs enforce (wire drops)."""
        try:
            if self._engine is not None and getattr(self._engine, "_monitor_only", True):
                return "monitor"
        except Exception:
            pass
        return "enforce"

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
            "system": {"cpu_percent": 12.5, "memory_percent": 34.2, "bridge_status": "UP",
                         "interface": "eth0", "environment": "demo", "mode": "demo"},
            "mitre": {},
            "protocols": {},
        }

    def on_block(self, ip: str):
        if self._mode == "ipc" and self._socket_path:
            self._send_ipc_command("BLOCK", ip=ip, reason="tui_block")
        else:
            self.block_ip(ip, "manual")

    def on_unblock(self, ip: str):
        if self._mode == "ipc" and self._socket_path:
            self._send_ipc_command("UNBLOCK", ip=ip)
        else:
            self.unblock_ip(ip)

    def _send_ipc_command(self, command: str, **kwargs):
        """Send a one-shot command to the agent via IPC socket."""
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect(self._socket_path)
            payload = json.dumps({"command": command, **kwargs}) + "\n"
            s.sendall(payload.encode())
            s.close()
        except Exception as e:
            logger.warning(f"[TUI] IPC command {command} failed: {e}")

    # ── Direct DB accessors used by widgets (real, fast, <100 ms each) ──
    def _get_db_path(self) -> Optional[Path]:
        if getattr(self, "_db_path_override", None) is not None:
            return self._db_path_override
        return _resolve_db_path()

    def set_db_path(self, path: str) -> None:
        """Override the SQLite path used by the direct-accessor methods."""
        self._db_path_override = Path(path)
        self._db_path_override.parent.mkdir(parents=True, exist_ok=True)

    def _open_ro(self) -> Optional[sqlite3.Connection]:
        path = self._get_db_path()
        if path is None:
            return None
        try:
            uri = f"file:{path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=2.0)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.OperationalError:
            try:
                conn = sqlite3.connect(str(path), timeout=2.0)
                conn.row_factory = sqlite3.Row
                return conn
            except sqlite3.Error as exc:
                logger.debug("[TUI] DB open failed: %s", exc)
                return None
        except sqlite3.Error as exc:
            logger.debug("[TUI] DB open failed: %s", exc)
            return None

    def _open_rw(self) -> Optional[sqlite3.Connection]:
        path = self._get_db_path()
        if path is None:
            return None
        try:
            conn = sqlite3.connect(str(path), timeout=2.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout = 5000")
            return conn
        except sqlite3.Error as exc:
            logger.debug("[TUI] DB rw open failed: %s", exc)
            return None

    def _get_attacker_countries(self, ips: List[str]) -> Dict[str, str]:
        """Batch lookup country for a list of IPs from the attacker DB."""
        if not ips:
            return {}
        conn = self._open_ro()
        if conn is None:
            return {}
        try:
            placeholders = ",".join("?" for _ in ips)
            rows = conn.execute(
                f"SELECT DISTINCT ip_address, country FROM attackers WHERE ip_address IN ({placeholders})",
                ips,
            ).fetchall()
            return {r[0]: r[1] or "??" for r in rows}
        except sqlite3.Error:
            return {}
        finally:
            conn.close()

    def get_protocol_breakdown(self, window_seconds: int = 60) -> Dict[str, int]:
        """Count attacks-per-protocol in the recent window.

        LIDRA does not log every packet, so we approximate traffic share
        by bucketing the recorded attacks in the ``attacks`` table by
        their inferred target protocol (via ``ATTACK_TYPE_TO_PROTOCOL``).
        Returns ``{}`` if the DB is unavailable.
        """
        from .protocol_map import classify_attack_type

        conn = self._open_ro()
        if conn is None:
            return {}
        try:
            rows = conn.execute(
                "SELECT attack_type, COUNT(*) AS c FROM attacks "
                "WHERE timestamp >= datetime('now', ?) "
                "GROUP BY attack_type",
                (f"-{int(window_seconds)} seconds",),
            ).fetchall()
        except sqlite3.Error as exc:
            logger.debug("[TUI] protocol breakdown query failed: %s", exc)
            conn.close()
            return {}
        finally:
            conn.close()
        out: Dict[str, int] = {}
        for r in rows:
            proto = classify_attack_type(r["attack_type"] or "")
            out[proto] = out.get(proto, 0) + int(r["c"])
        return out

    def get_top_attackers(self, limit: int = 10) -> List[Dict]:
        """Return the top ``limit`` attackers ranked by attack_count."""
        conn = self._open_ro()
        if conn is None:
            return []
        try:
            rows = conn.execute(
                "SELECT ip_address, attack_count, last_seen, country, threat_score "
                "FROM attackers ORDER BY attack_count DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        except sqlite3.Error as exc:
            logger.debug("[TUI] top attackers query failed: %s", exc)
            conn.close()
            return []
        finally:
            conn.close()
        out: List[Dict] = []
        for r in rows:
            score = int(r["threat_score"] or 0)
            if score >= 80:
                sev = "critical"
            elif score >= 50:
                sev = "high"
            elif score >= 20:
                sev = "medium"
            else:
                sev = "low"
            out.append(
                {
                    "ip": str(r["ip_address"]),
                    "attacks": int(r["attack_count"] or 0),
                    "last_seen": str(r["last_seen"] or ""),
                    "severity": sev,
                    "country": str(r["country"] or "??"),
                }
            )
        return out

    def get_recent_attacks(self, limit: int = 50) -> List[Dict]:
        """Return the most recent attacks joined with attacker IP / country."""
        conn = self._open_ro()
        if conn is None:
            return []
        try:
            rows = conn.execute(
                "SELECT a.id, a.attack_type, a.timestamp, a.source_log, "
                "at.ip_address, at.country "
                "FROM attacks a JOIN attackers at ON a.attacker_id = at.id "
                "ORDER BY a.timestamp DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        except sqlite3.Error as exc:
            logger.debug("[TUI] recent attacks query failed: %s", exc)
            conn.close()
            return []
        finally:
            conn.close()
        return [
            {
                "id": int(r["id"]),
                "type": str(r["attack_type"]),
                "timestamp": str(r["timestamp"]),
                "ip": str(r["ip_address"]),
                "country": str(r["country"] or "??"),
                "source_log": r["source_log"],
            }
            for r in rows
        ]

    def get_threat_stats(self) -> Dict:
        """Aggregate threat counters for the dashboard header strip."""
        conn = self._open_ro()
        empty = {
            "total_attacks": 0,
            "total_blocked": 0,
            "by_severity": {},
            "by_type": {},
            "last_24h": 0,
        }
        if conn is None:
            return empty
        try:
            total = conn.execute("SELECT COUNT(*) AS c FROM attacks").fetchone()["c"]
            blocked = conn.execute(
                "SELECT COUNT(*) AS c FROM blocks "
                "WHERE block_until > datetime('now')"
            ).fetchone()["c"]
            last_24h = conn.execute(
                "SELECT COUNT(*) AS c FROM attacks "
                "WHERE timestamp >= datetime('now', '-24 hours')"
            ).fetchone()["c"]
            by_type = {
                str(r["attack_type"]): int(r["c"])
                for r in conn.execute(
                    "SELECT attack_type, COUNT(*) AS c FROM attacks "
                    "GROUP BY attack_type ORDER BY c DESC LIMIT 20"
                ).fetchall()
            }
        except sqlite3.Error as exc:
            logger.debug("[TUI] threat stats query failed: %s", exc)
            conn.close()
            return empty
        finally:
            conn.close()
        return {
            "total_attacks": int(total),
            "total_blocked": int(blocked),
            "by_severity": {},
            "by_type": by_type,
            "last_24h": int(last_24h),
        }

    def get_attacker_detail(self, ip: str) -> Dict:
        """Return full drill-down info for a single IP."""
        empty = {
            "ip": ip,
            "country": "",
            "org": "",
            "attack_count": 0,
            "first_seen": "",
            "last_seen": "",
            "top_types": [],
            "top_ports": [],
            "blocked": False,
        }
        conn = self._open_ro()
        if conn is None:
            return empty
        try:
            row = conn.execute(
                "SELECT id, country, org, first_seen, last_seen FROM attackers WHERE ip_address = ?",
                (ip,),
            ).fetchone()
            if row is None:
                return empty
            attacker_id = row["id"]
            country = row["country"] or ""
            org = row["org"] or ""

            count_row = conn.execute(
                "SELECT COUNT(*) AS c, MIN(timestamp) AS first, MAX(timestamp) AS last FROM attacks WHERE attacker_id = ?",
                (attacker_id,),
            ).fetchone()
            attack_count = count_row["c"] if count_row else 0
            first_seen = count_row["first"] if count_row else row["first_seen"] or ""
            last_seen = count_row["last"] if count_row else row["last_seen"] or ""

            type_rows = conn.execute(
                "SELECT attack_type, COUNT(*) AS c FROM attacks WHERE attacker_id = ? GROUP BY attack_type ORDER BY c DESC LIMIT 5",
                (attacker_id,),
            ).fetchall()
            top_types = [(r["attack_type"] or "unknown", r["c"]) for r in type_rows]

            port_rows = conn.execute(
                "SELECT raw_line, COUNT(*) AS c FROM attacks WHERE attacker_id = ? GROUP BY raw_line ORDER BY c DESC LIMIT 5",
                (attacker_id,),
            ).fetchall()
            top_ports = []
            for r in port_rows:
                raw = r["raw_line"] or ""
                port = self._extract_port(raw)
                if port:
                    top_ports.append((port, r["c"]))
            top_ports = top_ports[:5]

            blocked_row = conn.execute(
                "SELECT 1 FROM blocks WHERE ip_address = ? AND active = 1 LIMIT 1",
                (ip,),
            ).fetchone()
            blocked = blocked_row is not None

            return {
                "ip": ip,
                "country": country,
                "org": org,
                "attack_count": attack_count,
                "first_seen": first_seen or "",
                "last_seen": last_seen or "",
                "top_types": top_types,
                "top_ports": top_ports,
                "blocked": blocked,
            }
        except Exception as e:
            logger.debug("get_attacker_detail failed for %s: %s", ip, e)
            return empty
        finally:
            conn.close()

    @staticmethod
    def _extract_port(raw_line: str) -> Optional[str]:
        if not raw_line:
            return None
        import re
        m = re.search(r"port\s*(\d{1,5})", raw_line, re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r"\b(\d{1,5})/tcp\b", raw_line)
        if m:
            return m.group(1)
        return None

    def get_kpis(self) -> Dict:
        """Return the 5-KPI summary for the status bar."""
        stats = self.get_threat_stats()
        system = self.get_system_stats() if hasattr(self, "get_system_stats") else {}
        rate_hist = self.get_packet_rate_history(window_seconds=5) if hasattr(self, "get_packet_rate_history") else []
        current_rate = rate_hist[-1] if rate_hist else 0

        top_attackers = self.get_top_attackers(limit=1)
        top_ip = top_attackers[0]["ip"] if top_attackers else "—"

        by_type = stats.get("by_type", {}) or {}
        critical_types = {"exploit_attempt", "rce_attempt", "shellcode_detected", "command_injection", "log4j_attempt", "shellshock_attempt", "eternalblue_attempt", "sql_injection"}
        critical_count = sum(by_type.get(t, 0) for t in critical_types)

        return {
            "rate": int(current_rate),
            "attacks": int(stats.get("last_24h", 0)),
            "blocked": int(stats.get("total_blocked", 0)),
            "critical": int(critical_count),
            "top_ip": top_ip,
            "cpu": float(system.get("cpu_percent", 0.0)),
            "mem": float(system.get("memory_percent", 0.0)),
        }

    def block_ip(self, ip: str, reason: str = "manual") -> bool:
        """Block an IP. Records the block in the DB and asks the engine."""
        ok = False
        if self._engine is not None:
            try:
                self._engine.blocklist.block(ip, reason, 3600)
                ok = True
            except Exception as exc:
                logger.debug("[TUI] engine block failed: %s", exc)
        conn = self._open_rw()
        if conn is not None:
            try:
                conn.execute(
                    "INSERT INTO blocks (ip_address, reason, block_until) "
                    "VALUES (?, ?, datetime('now', '+1 hour'))",
                    (ip, reason),
                )
                conn.commit()
                ok = True
            except sqlite3.Error as exc:
                logger.debug("[TUI] DB block record failed: %s", exc)
            finally:
                conn.close()
        return ok

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP. Removes the active rule and marks the block row."""
        ok = False
        if self._engine is not None:
            try:
                self._engine.blocklist.unblock(ip)
                ok = True
            except Exception as exc:
                logger.debug("[TUI] engine unblock failed: %s", exc)
        conn = self._open_rw()
        if conn is not None:
            try:
                conn.execute(
                    "DELETE FROM blocks WHERE ip_address = ? "
                    "AND block_until > datetime('now')",
                    (ip,),
                )
                conn.commit()
                ok = True
            except sqlite3.Error as exc:
                logger.debug("[TUI] DB unblock record failed: %s", exc)
            finally:
                conn.close()
        return ok

    def get_system_stats(self) -> Dict:
        """Return live CPU / memory / disk / uptime counters."""
        try:
            cpu = float(psutil.cpu_percent(interval=None))
        except Exception:
            cpu = 0.0
        try:
            mem = float(psutil.virtual_memory().percent)
        except Exception:
            mem = 0.0
        try:
            disk = float(psutil.disk_usage("/").percent)
        except Exception:
            disk = 0.0
        try:
            uptime_seconds = int(time.time() - psutil.boot_time())
        except Exception:
            uptime_seconds = int(time.time() - self._start_time)
        return {
            "cpu_percent": cpu,
            "memory_percent": mem,
            "disk_percent": disk,
            "uptime_seconds": uptime_seconds,
        }

    def get_packet_rate_history(self, window_seconds: int = 60) -> List[int]:
        """Return per-second attack counts over the last ``window_seconds``."""
        conn = self._open_ro()
        if conn is None:
            return [0] * int(window_seconds)
        try:
            rows = conn.execute(
                "SELECT strftime('%s', timestamp) AS bucket, COUNT(*) AS c "
                "FROM attacks "
                "WHERE timestamp >= datetime('now', ?) "
                "GROUP BY bucket "
                "ORDER BY bucket ASC",
                (f"-{int(window_seconds)} seconds",),
            ).fetchall()
        except sqlite3.Error as exc:
            logger.debug("[TUI] packet rate query failed: %s", exc)
            conn.close()
            return [0] * int(window_seconds)
        finally:
            conn.close()
        now = int(time.time())
        buckets: Dict[int, int] = {}
        for r in rows:
            try:
                buckets[int(r["bucket"])] = int(r["c"])
            except (TypeError, ValueError):
                continue
        return [buckets.get(now - i, 0) for i in range(int(window_seconds) - 1, -1, -1)]