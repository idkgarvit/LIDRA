# src/database/db.py
"""LIDRA Database Layer - SQLite backend for production use."""

import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timedelta, timezone

from utils.alert_throttle import AlertThrottle
from database.migrations import (
    SchemaTooNewError,
    migrate,
    record_binary_version,
)

logger = logging.getLogger(__name__)


class LIDRADatabase:
    """Thread-safe SQLite database wrapper for LIDRA."""

    def __init__(self, db_path: str, record_dedupe_seconds: int = 60):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        # ponytail: one flood = thousands of identical rows (disk bloat, slow
        # queries) while alerts were already throttled. Cooldown per
        # (attacker, type) here — the one spot all record paths route through.
        self._record_dedupe = AlertThrottle(cooldown_seconds=record_dedupe_seconds)
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection with WAL mode."""
        if not hasattr(self._local, 'connection'):
            self._local.connection = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                isolation_level=None
            )
            self._local.connection.row_factory = sqlite3.Row
            c = self._local.connection
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA foreign_keys = ON")
            c.execute("PRAGMA busy_timeout = 5000")
            c.execute("PRAGMA auto_vacuum=INCREMENTAL")
        return self._local.connection

    @contextmanager
    def transaction(self):
        """Context manager for database transactions."""
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _init_schema(self):
        """Bring the database up to the current schema version.

        Uses the migration runner instead of replaying schema.sql and ignoring
        "already exists" — that approach silently left an upgraded install on
        its old schema while reporting success. See database/migrations.py.
        """
        conn = self._get_connection()
        try:
            version = migrate(conn, db_path=str(self.db_path))
            if version:
                try:
                    from utils.version import __version__
                    record_binary_version(conn, __version__)
                except Exception:
                    pass
        except SchemaTooNewError:
            # Refusing to open is the correct behaviour, but it must be loud.
            raise
        except sqlite3.Error as e:
            logger.error("[DB] Schema migration failed: %s", e)
            raise

    def add_attacker(self, ip: str, country: str = None, org: str = None) -> int:
        """Add or update attacker record. Returns attacker_id."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, attack_count FROM attackers WHERE ip_address = ?", (ip,))
        row = cursor.fetchone()

        if row:
            cursor.execute(
                "UPDATE attackers SET last_seen = ?, attack_count = attack_count + 1, country = COALESCE(?, country), org = COALESCE(?, org) WHERE id = ?",
                # ponytail: UTC, matching CURRENT_TIMESTAMP defaults elsewhere —
                # local now() mixed IST rows into the same column and broke
                # last_seen ordering.
                (datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), country, org, row['id'])
            )
            return row['id']
        else:
            cursor.execute(
                "INSERT INTO attackers (ip_address, country, org) VALUES (?, ?, ?)",
                (ip, country, org)
            )
            return cursor.lastrowid

    # ponytail: threat_score was write-never (every attacker sat at 0, so any
    # score-based response threshold was dead). Severity-weighted bump here —
    # the one spot all record paths route through.
    _SEVERITY_WEIGHT = {"low": 1, "medium": 3, "high": 10, "critical": 25}

    def record_attack(self, attacker_id: int, attack_type: str, source_log: str = None,
                      raw_line: str = None, severity: str = "medium", dedupe: bool = True):
        """Record an attack event. Dup (attacker, type) hits inside the record
        cooldown are skipped — pass dedupe=False for manual/demo inserts."""
        if dedupe and not self._record_dedupe.allow(attack_type, attacker_id):
            return
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO attacks (attacker_id, attack_type, source_log, raw_line) VALUES (?, ?, ?, ?)",
            (attacker_id, attack_type, source_log, raw_line)
        )
        cursor.execute(
            "UPDATE attackers SET threat_score = MIN(100, threat_score + ?) WHERE id = ?",
            (self._SEVERITY_WEIGHT.get((severity or "medium").lower(), 3), attacker_id)
        )

    def get_attackers(self, limit: int = 100, offset: int = 0) -> list:
        """Get list of attackers with stats."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT a.*, COUNT(at.id) as total_attacks
               FROM attackers a
               LEFT JOIN attacks at ON a.id = at.attacker_id
               GROUP BY a.id
               ORDER BY a.last_seen DESC
               LIMIT ? OFFSET ?""",
            (limit, offset)
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_attacker_stats(self) -> dict:
        """Get overall attacker statistics."""
        conn = self._get_connection()
        cursor = conn.cursor()

        stats = {}
        cursor.execute("SELECT COUNT(*) as count FROM attackers")
        stats['total_attackers'] = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM attacks WHERE timestamp >= datetime('now', '-24 hours')")
        stats['attacks_24h'] = cursor.fetchone()['count']

        cursor.execute("SELECT country, COUNT(*) as count FROM attackers WHERE country IS NOT NULL GROUP BY country ORDER BY count DESC LIMIT 10")
        stats['top_countries'] = [dict(row) for row in cursor.fetchall()]

        return stats

    def add_block(self, ip: str, reason: str, ttl_seconds: int = 3600) -> int:
        """Add a block record."""
        conn = self._get_connection()
        cursor = conn.cursor()
        block_until = (datetime.now() + timedelta(seconds=ttl_seconds)).isoformat()
        cursor.execute(
            "INSERT INTO blocks (ip_address, reason, block_until) VALUES (?, ?, ?)",
            (ip, reason, block_until)
        )
        return cursor.lastrowid

    def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM blocks WHERE ip_address = ? AND block_until > ? AND applied = 1",
            (ip, datetime.now().isoformat())
        )
        return cursor.fetchone() is not None

    def mark_block_applied(self, block_id: int):
        """Mark a block as applied to firewall."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE blocks SET applied = 1 WHERE id = ?", (block_id,))

    def log_audit(self, actor: str, action: str, target: str = "",
                  detail: str = "", source: str = "") -> int:
        """Record an action that changed (or tried to change) firewall state.

        The table was created by schema migration v2 and nothing wrote to it
        until this was wired: block/unblock from the CLI, TUI and IPC socket
        left no record of *who* did it, which is the first question asked after
        an incident (plan section 5.9). ``actor`` is resolved by the caller —
        for the IPC path it comes from the kernel's peer credentials, not from
        anything the client claims.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO audit_log (actor, action, target, detail, source) "
            "VALUES (?, ?, ?, ?, ?)",
            (actor or "unknown", action, target or "", detail or "", source or ""),
        )
        return cursor.lastrowid

    def get_audit_log(self, limit: int = 50) -> list:
        """Most recent audit entries, newest first."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT actor, action, target, detail, source, created_at "
            "FROM audit_log ORDER BY id DESC LIMIT ?",
            (int(limit),),
        )
        return [dict(row) for row in cursor.fetchall()]

    def record_honeyfile_hit(self, file_path: str, ip: str = None, event_type: str = None):
        """Record honeyfile access."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO honeyfile_hits (file_path, ip_address, event_type) VALUES (?, ?, ?)",
            (file_path, ip, event_type)
        )

    def create_honeypot_session(self, session_id: str, ip: str, port: int) -> int:
        """Create a new honeypot session record."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO honeypot_sessions (session_id, ip_address, port) VALUES (?, ?, ?)",
            (session_id, ip, port)
        )
        return cursor.lastrowid

    def update_honeypot_session(self, session_id: str, commands: str = None, status: str = 'closed'):
        """Update honeypot session."""
        conn = self._get_connection()
        cursor = conn.cursor()
        if commands:
            cursor.execute(
                "UPDATE honeypot_sessions SET commands = ?, status = ?, end_time = ? WHERE session_id = ?",
                (commands, status, datetime.now().isoformat(), session_id)
            )
        else:
            cursor.execute(
                "UPDATE honeypot_sessions SET status = ?, end_time = ? WHERE session_id = ?",
                (status, datetime.now().isoformat(), session_id)
            )

    def get_honeypot_sessions(self, limit: int = 50) -> list:
        """Get recent honeypot sessions."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM honeypot_sessions ORDER BY start_time DESC LIMIT ?",
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def add_alert(self, alert_type: str, severity: str, ip: str = None, message: str = None):
        """Add security alert."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (alert_type, severity, ip_address, message) VALUES (?, ?, ?, ?)",
            (alert_type, severity, ip, message)
        )
        return cursor.lastrowid

    def get_unsent_alerts(self) -> list:
        """Get alerts that haven't been sent yet."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts WHERE sent = 0 ORDER BY created_at ASC")
        return [dict(row) for row in cursor.fetchall()]

    def mark_alert_sent(self, alert_id: int):
        """Mark alert as sent."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE alerts SET sent = 1 WHERE id = ?", (alert_id,))

    def get_recent_alerts(self, limit: int = 20) -> list:
        """Get recent alerts."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?",
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_recent_attacks(self, limit: int = 100) -> list:
        """Get recent attack events with attacker info."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT a.*, at.ip_address, at.country
               FROM attacks a
               JOIN attackers at ON a.attacker_id = at.id
               ORDER BY a.timestamp DESC
               LIMIT ?""",
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def cleanup_old_data(self, days: int = 30):
        """Remove data older than specified days."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM attacks WHERE timestamp < datetime('now', ?)",
            (f'-{days} days',)
        )
        cursor.execute(
            "DELETE FROM honeypot_sessions WHERE end_time < datetime('now', ?)",
            (f'-{days} days',)
        )
        cursor.execute(
            "DELETE FROM alerts WHERE created_at < datetime('now', ?)",
            (f'-{days} days',)
        )
        conn.execute("PRAGMA incremental_vacuum(10)")

    def close(self):
        """Close database connection."""
        if hasattr(self._local, 'connection'):
            self._local.connection.close()
            del self._local.connection
