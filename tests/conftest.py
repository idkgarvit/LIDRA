"""Shared test guards.

The suite must not touch the operator's real database. Two rows of test
residue in ``data/lidra.db`` once made ``lidra status`` report an active block
that had never been applied to the kernel, and a stray audit row claimed an
operator had blocked their own gateway — both were tests, not the human.

Every test therefore gets an automatic before/after fingerprint of the repo
database and fails if it changed. Use ``tmp_path`` (or stub ``_open_db``) for
anything that writes.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

_REPO_DB = Path(__file__).resolve().parent.parent / "data" / "lidra.db"
_WATCHED_TABLES = ("blocks", "audit_log")


def _db_fingerprint() -> tuple | None:
    """Row counts for the tables a test might pollute, or None if no DB."""
    if not _REPO_DB.exists():
        return None
    try:
        conn = sqlite3.connect(f"file:{_REPO_DB}?mode=ro", uri=True, timeout=2)
    except sqlite3.Error:
        return None
    try:
        counts = []
        for table in _WATCHED_TABLES:
            try:
                counts.append(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            except sqlite3.Error:
                counts.append(None)
        return tuple(counts)
    finally:
        conn.close()


@pytest.fixture(autouse=True)
def _suite_must_not_touch_the_real_database():
    before = _db_fingerprint()
    yield
    after = _db_fingerprint()
    assert before == after, (
        f"a test wrote to the real database {_REPO_DB} "
        f"(blocks, audit_log) {before} -> {after}. Use tmp_path or stub "
        f"_open_db / _resolve_db_path instead of the live DB."
    )