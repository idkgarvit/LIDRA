"""Schema migrations.

Before this module `_init_schema()` ran the whole `schema.sql` through
`executescript` and swallowed any "already exists" error. That is fine for a
fresh database and silently wrong for an existing one: the moment a release
changes a table, an upgraded install keeps the old shape and queries fail at
runtime, long after the upgrade reported success.

Model
-----
* `PRAGMA user_version` holds the schema version.
* `MIGRATIONS` is an ordered list of (version, description, statements).
  Version 1 is the original schema; later entries are applied in order.
* `migrate(conn)` takes a backup of the database file first, applies only the
  missing steps inside a transaction, then stamps the new version.
* A database newer than the binary is refused, not "upgraded" downwards.

Rules for adding a migration
---------------------------
* Append only. Never edit or renumber a released step.
* Steps must be idempotent where practical (`IF NOT EXISTS`, guarded ALTERs),
  because a crash mid-migration is retried.
* Statement lists are plain SQL strings; no parameters, no dynamic SQL.
"""

from __future__ import annotations

import logging
import shutil
import sqlite3
import time
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger(__name__)

# Version 1 == the original src/database/schema.sql, reproduced here so a fresh
# database and a migrated one end up identical.
#
# src/database/schema.sql itself was deleted once this list existed. It was the
# only other copy of the schema, no code imported it, and two hand-maintained
# copies of the same DDL is precisely the drift the migration runner exists to
# prevent. This list is now the single definition of the schema — verified
# statement-for-statement equal to the file before it was removed.
_V1 = [
    """CREATE TABLE IF NOT EXISTS attackers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE NOT NULL,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        attack_count INTEGER DEFAULT 1,
        threat_score INTEGER DEFAULT 0,
        country TEXT,
        org TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attacker_id INTEGER NOT NULL,
        attack_type TEXT NOT NULL,
        source_log TEXT,
        raw_line TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (attacker_id) REFERENCES attackers(id)
    )""",
    """CREATE TABLE IF NOT EXISTS blocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        reason TEXT,
        block_until TIMESTAMP,
        applied INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS honeyfile_hits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT NOT NULL,
        ip_address TEXT,
        event_type TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS honeypot_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE,
        ip_address TEXT NOT NULL,
        port INTEGER,
        start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        end_time TIMESTAMP,
        commands TEXT,
        status TEXT DEFAULT 'active'
    )""",
    """CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        ip_address TEXT,
        message TEXT NOT NULL,
        sent INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",
    "CREATE INDEX IF NOT EXISTS idx_attackers_ip ON attackers(ip_address)",
    "CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_blocks_until ON blocks(block_until)",
]

# Version 2 adds an operator audit trail: who blocked/unblocked what, and when.
# A security tool that changes firewall state needs an answer to "who did that".
_V2 = [
    """CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT,
        detail TEXT,
        source TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",
    "CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)",
]

# Version 3 records the binary version that last touched the database, so a
# downgrade can be detected instead of corrupting data.
_V3 = [
    """CREATE TABLE IF NOT EXISTS schema_meta (
        key TEXT PRIMARY KEY,
        value TEXT
    )""",
]

MIGRATIONS: List[Tuple[int, str, List[str]]] = [
    (1, "initial schema", _V1),
    (2, "operator audit log", _V2),
    (3, "schema metadata table", _V3),
]

SCHEMA_VERSION = MIGRATIONS[-1][0]


class SchemaTooNewError(RuntimeError):
    """The database was written by a newer LIDRA than this binary."""


def current_version(conn: sqlite3.Connection) -> int:
    try:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
    except (sqlite3.Error, TypeError, IndexError):
        return 0


def _backup(db_path: str) -> str:
    """Copy the database beside itself before migrating. Returns the path."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = f"{db_path}.pre-migration-{stamp}"
    try:
        shutil.copy2(db_path, backup)
    except OSError as e:
        logger.warning("[schema] Could not back up %s before migrating: %s", db_path, e)
        return ""
    return backup


def migrate(conn: sqlite3.Connection, db_path: str = "") -> int:
    """Bring `conn` up to SCHEMA_VERSION. Returns the resulting version."""
    have = current_version(conn)

    if have > SCHEMA_VERSION:
        raise SchemaTooNewError(
            f"database schema is v{have} but this LIDRA supports v{SCHEMA_VERSION}; "
            "refusing to open it. Upgrade LIDRA, or restore a backup."
        )

    if have == SCHEMA_VERSION:
        # Still stamp a fresh DB's version if it somehow has 0 tables.
        return have

    if have and db_path:
        backup = _backup(db_path)
        if backup:
            logger.info("[schema] Pre-migration backup: %s", backup)

    for version, description, statements in MIGRATIONS:
        if version <= have:
            continue
        logger.info("[schema] Applying migration v%s (%s)", version, description)
        try:
            for stmt in statements:
                conn.execute(stmt)
            # PRAGMA cannot be parameterised; version is an int from our own list.
            conn.execute(f"PRAGMA user_version = {int(version)}")
            conn.commit()
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(
                "[schema] Migration v%s (%s) failed and was rolled back: %s",
                version, description, e,
            )
            raise
        have = version

    return have


def record_binary_version(conn: sqlite3.Connection, version: str) -> None:
    """Record which binary version last opened the database."""
    try:
        conn.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('binary_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (version,),
        )
        conn.commit()
    except sqlite3.Error as e:
        # Never fatal: a missing metadata row must not stop the agent.
        logger.debug("[schema] Could not record binary version: %s", e)