"""Stage 1 fixes: socket relocation + permissions, schema migration, version.

Covers the blocking items from docs/PRODUCTION_READINESS.md section 1:

* 1.1 — socket no longer lives in /tmp, so systemd PrivateTmp=true cannot hide
  it from a user-shell TUI. The server binds under utils/runtime's directory
  (overridable via LIDRA_RUNTIME_DIR) and clients discover it there, with the
  legacy /tmp path kept as a fallback so an upgrade does not orphan a running
  agent's socket.
* 1.2 — the socket is 0660, the runtime dir is 0750. Anything world-writable
  fails.
* 1.5 — schema is versioned (PRAGMA user_version) and migrated transactionally
  with a backup; a newer DB than the binary refuses to open.
* 4.5 — one version string (utils/version.py) read by the CLI, both output
  formatters and the TUI logo, and matched against pyproject.toml. The version
  tests below also *scan the tree*, because the original check only inspected
  the modules that had already been converted — which is how the TUI status bar
  kept a hardcoded "v3.0.0" through the first pass.
* 1.4 — no advertisement for a mechanism the product does not reliably use
  (the banners claimed "eBPF-Powered" while eBPF is inert without `bcc`).
"""

import ast
import json
import os
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

SRC = Path(__file__).resolve().parent.parent / "src"


# --- 1.1: socket location ----------------------------------------------------

class TestRuntimeDirResolution:
    def test_env_override_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LIDRA_RUNTIME_DIR", str(tmp_path / "custom"))
        from utils import runtime
        got = runtime.get_runtime_dir()
        assert got == tmp_path / "custom"
        assert got.is_dir()

    def test_run_lidra_preferred_when_writable(self, monkeypatch):
        monkeypatch.delenv("LIDRA_RUNTIME_DIR", raising=False)
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        from utils import runtime
        got = runtime.get_runtime_dir()
        # On this machine /run/lidra may or may not be writable; either way we
        # must get a real writable directory or None — never /tmp.
        if got is not None:
            assert str(got) != "/tmp"
            assert os.access(got, os.W_OK | os.X_OK)

    def test_socket_path_for_builds_pid_name(self, tmp_path):
        from utils import runtime
        p = runtime.socket_path_for(12345, directory=tmp_path)
        assert p == tmp_path / "lidra_tui_12345.sock"

    def test_find_socket_ignores_dead_pids(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LIDRA_RUNTIME_DIR", str(tmp_path))
        (tmp_path / "lidra_tui_99999999.sock").touch()
        from utils import runtime
        assert runtime.find_socket() is None

    def test_find_socket_returns_live_highest_pid(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LIDRA_RUNTIME_DIR", str(tmp_path))
        for pid in (1001, 1002):
            (tmp_path / f"lidra_tui_{pid}.sock").touch()
        from utils import runtime
        found = runtime.find_socket(pid_alive_check=lambda p: True)
        assert found == str(tmp_path / "lidra_tui_1002.sock")

    def test_legacy_tmp_scanned_as_fallback(self, tmp_path, monkeypatch):
        """An upgrade must not orphan a running agent bound to the old /tmp path."""
        import utils.runtime as rt
        legacy = tmp_path / "legacy-tmp"
        legacy.mkdir()
        (legacy / "lidra_tui_4242.sock").touch()
        monkeypatch.setattr(rt, "LEGACY_SOCKET_DIR", str(legacy))
        monkeypatch.setenv("LIDRA_RUNTIME_DIR", str(tmp_path / "empty"))
        found = rt.find_socket(pid_alive_check=lambda p: True)
        assert found == str(legacy / "lidra_tui_4242.sock")


class TestSocketPermissions:
    def test_server_binds_outside_tmp_with_0660(self, tmp_path, monkeypatch):
        # AF_UNIX paths are capped at ~108 bytes, and `tmp_path` inherits $TMPDIR.
        # A long TMPDIR (e.g. a CI or agent scratch dir nested deep in $HOME) pushes
        # the socket path over the limit and this test fails with
        # "OSError: AF_UNIX path too long" — a harness artefact, not a product bug,
        # but it looks exactly like one. Bind under a short base instead, keeping
        # the name long enough to still exercise the real path length.
        short = Path(tempfile.mkdtemp(prefix="lidra-sock-", dir="/tmp"))
        monkeypatch.setenv("LIDRA_RUNTIME_DIR", str(short))
        from tui.ipc_server import TUIIPCServer
        srv = TUIIPCServer(snapshot_fn=lambda: {})
        srv.start()
        try:
            mode = stat.S_IMODE(os.stat(srv.socket_path).st_mode)
            assert mode == 0o660, f"socket mode is {oct(mode)}, must be 0660"
            # Must sit in the configured runtime dir — never in the legacy
            # shared /tmp. (tmp_path is itself under /tmp on Linux, so assert
            # the directory, not the prefix.)
            assert Path(srv.socket_path).parent == short, srv.socket_path
        finally:
            srv.stop()
            shutil.rmtree(short, ignore_errors=True)

    def test_server_disables_ipc_when_no_writable_dir(self, monkeypatch):
        import utils.runtime as rt
        monkeypatch.setattr(rt, "get_runtime_dir", lambda create=True: None)
        from tui.ipc_server import TUIIPCServer
        srv = TUIIPCServer(snapshot_fn=lambda: {})
        srv.start()  # must not raise, must not bind in /tmp
        assert srv.socket_path == ""

    def test_client_connects_through_new_path(self, tmp_path, monkeypatch):
        import json as _json
        import socket as _socket
        # Short base for the same AF_UNIX length reason as above.
        short = Path(tempfile.mkdtemp(prefix="lidra-sock-", dir="/tmp"))
        monkeypatch.setenv("LIDRA_RUNTIME_DIR", str(short))
        from tui.ipc_server import TUIIPCServer
        srv = TUIIPCServer(snapshot_fn=lambda: {"ok": True})
        srv.start()
        try:
            s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(srv.socket_path)
            s.sendall(b'{"command": "SNAPSHOT"}\n')
            data = s.recv(65535).decode()
            s.close()
            assert _json.loads(data)["data"] == {"ok": True}
        finally:
            srv.stop()
            shutil.rmtree(short, ignore_errors=True)


# --- 1.5: schema migration ---------------------------------------------------

class TestSchemaMigration:
    def _fresh_db(self, tmp_path):
        from database.db import LIDRADatabase
        return LIDRADatabase(str(tmp_path / "lidra.db"))

    def test_fresh_db_is_current_version(self, tmp_path):
        from database.migrations import SCHEMA_VERSION, current_version
        db = self._fresh_db(tmp_path)
        assert current_version(db._get_connection()) == SCHEMA_VERSION

    def test_old_db_migrates_with_data_preserved(self, tmp_path):
        """A v1 database (pre-migration era) upgrades without losing rows."""
        import sqlite3 as _s
        path = tmp_path / "lidra.db"
        con = _s.connect(str(path))
        con.executescript(
            "CREATE TABLE attackers (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " ip_address TEXT UNIQUE NOT NULL, first_seen TIMESTAMP DEFAULT"
            " CURRENT_TIMESTAMP, last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
            " attack_count INTEGER DEFAULT 1, threat_score INTEGER DEFAULT 0,"
            " country TEXT, org TEXT);"
            "PRAGMA user_version = 1;"
        )
        con.execute("INSERT INTO attackers (ip_address) VALUES ('203.0.113.9')")
        con.commit()
        con.close()

        from database.db import LIDRADatabase
        from database.migrations import SCHEMA_VERSION, current_version
        db = LIDRADatabase(str(path))
        assert current_version(db._get_connection()) == SCHEMA_VERSION
        row = db._get_connection().execute(
            "SELECT ip_address FROM attackers WHERE ip_address='203.0.113.9'"
        ).fetchone()
        assert row is not None, "pre-migration data lost"
        # v2/v3 tables must exist now
        tables = {r[0] for r in db._get_connection().execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"audit_log", "schema_meta"} <= tables
        # and a backup was taken before touching the original
        assert list(tmp_path.glob("lidra.db.pre-migration-*")), "no backup taken"

    def test_newer_db_refuses_to_open(self, tmp_path):
        import sqlite3 as _s
        from database.migrations import SCHEMA_VERSION
        path = tmp_path / "lidra.db"
        con = _s.connect(str(path))
        con.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 99}")
        con.commit()
        con.close()

        from database.db import LIDRADatabase
        from database.migrations import SchemaTooNewError
        with pytest.raises(SchemaTooNewError):
            LIDRADatabase(str(path))

    def test_migration_is_repeatable(self, tmp_path):
        from database.db import LIDRADatabase
        from database.migrations import SCHEMA_VERSION, current_version
        for _ in range(3):
            db = self._fresh_db(tmp_path)
            assert current_version(db._get_connection()) == SCHEMA_VERSION


# --- 4.5: one version string --------------------------------------------------

class TestVersionConsistency:
    def test_everything_reads_the_same_version(self):
        from utils import version
        from output.formatters import JSONFormatter, CEFFormatter
        import json as _json
        from cli import __version__ as cli_v
        from tui.widgets.ascii_logo import VERSION as logo_v

        emitted = _json.loads(JSONFormatter().format(
            {"attack_type": "t", "severity": "high"}))["observer"]["version"]
        assert emitted == version.__version__, (emitted, version.__version__)
        assert CEFFormatter.DEVICE_VERSION == version.__version__
        assert cli_v == version.__version__
        assert logo_v == f"v{version.__version__}", logo_v


# --- 4.5 (ratchet): a version literal may not reappear anywhere ---------------

_VERSION_SHAPED = re.compile(r"^v?\d+\.\d+\.\d+$")

# Modules are allowed a fallback constant for the case where src/ is not on
# sys.path. Anything else must read utils/version.py.
_ALLOWED_FALLBACKS = {"0.0.0", "v0.0.0"}

# The one place a product version may be written down.
_VERSION_HOME = Path("utils/version.py")


def _version_claims(path: Path):
    """(line_number, literal) for string literals that read as a version.

    A bare ``"3.0.0"`` is syntactically identical to an IP fragment —
    ``tui/demo_mode.py`` documents the RFC-5737 ranges 203.0.113 / 198.51.100 /
    192.0.2 — so a literal only counts as a version claim if it carries a ``v``
    prefix or sits on a line that names a version. Every surface that displays
    one does at least one of the two.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    claims = []
    for node in ast.walk(ast.parse("\n".join(lines))):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        value = node.value
        if not _VERSION_SHAPED.match(value):
            continue
        line = lines[node.lineno - 1] if 0 < node.lineno <= len(lines) else ""
        if value.startswith("v") or "version" in line.lower():
            claims.append((node.lineno, value))
    return claims


class TestNoHardcodedVersionStrings:
    def test_only_version_module_defines_a_version_literal(self):
        offenders = []
        for path in sorted(SRC.rglob("*.py")):
            rel = path.relative_to(SRC)
            if rel == _VERSION_HOME:
                continue
            for lineno, value in _version_claims(path):
                if value in _ALLOWED_FALLBACKS:
                    continue
                offenders.append(f"{rel}:{lineno}: {value!r}")
        assert not offenders, (
            "version literal(s) outside utils/version.py — read version_string() "
            "instead, or use the 0.0.0 import-failure fallback: " + "; ".join(offenders)
        )

    def test_every_version_display_reads_the_one_source(self):
        from utils import version
        from tui.widgets.status_bar import VERSION as status_bar_v
        from tui.widgets.ascii_logo import VERSION as logo_v
        from dashboard.cli import VERSION as dashboard_v
        from cli.main import VERSION as cli_main_v
        from cli.commands import VERSION as cli_commands_v

        expected = version.version_string()
        for name, got in (
            ("status_bar", status_bar_v),
            ("ascii_logo", logo_v),
            ("dashboard.cli", dashboard_v),
            ("cli.main", cli_main_v),
            ("cli.commands", cli_commands_v),
        ):
            assert got == expected, f"{name} advertises {got}, expected {expected}"


# --- 4.5: the TUI logo renders the live version ------------------------------

class TestLogoVersionCaption:
    def test_caption_is_generated_not_baked_into_the_art(self):
        from tui.widgets.ascii_logo import LOGO, _VERSION_LABEL_SLOT

        assert _VERSION_LABEL_SLOT in LOGO, "art lost its version placeholder"

    def test_rendered_caption_shows_the_current_version(self):
        from utils.version import version_string
        from tui.widgets.ascii_logo import _build_logo_text

        plain = _build_logo_text().plain
        expected = "L I D R A   " + " ".join(version_string())
        assert expected in plain, plain
        assert "{version_label}" not in plain

    def test_bumping_the_version_does_not_break_the_caption_width(self):
        """A longer version must not push the right border out of line."""
        from tui.widgets import ascii_logo

        original = ascii_logo.VERSION
        try:
            ascii_logo.VERSION = "v10.20.30"
            line = [
                ln for ln in ascii_logo._build_logo_text().plain.splitlines()
                if "L I D R A" in ln
            ][0]
            assert len(line) == 64, len(line)
            assert line.endswith("\u2502")
        finally:
            ascii_logo.VERSION = original


# --- 1.4: no advertisement for an unwired mechanism --------------------------

# Phrases that describe capability, not intent. "eBPF-Powered" was on the
# agent, the CLI banner and the dashboard while eBPF needs `bcc` and otherwise
# falls back to log monitoring; the LLM triage path (soar/) is not wired in.
_BANNED_CLAIMS = ("eBPF-Powered", "LLM-powered")


def _code_text(path: Path) -> str:
    """Module text with whole-line comments removed (they may cite history)."""
    return "\n".join(
        line for line in path.read_text(encoding="utf-8").splitlines()
        if not line.strip().startswith("#")
    )


# --- 1.4: help and banners must actually render ------------------------------

class TestHelpAndBannerRender:
    """`lidra help` crashed on a mismatched Rich tag — ``[yellow]Actions:[/green]``
    raises MarkupError — because nothing ever rendered the help text. These
    tests are the reason that cannot come back silently.
    """

    def test_cmd_help_renders(self, capsys):
        from cli.commands import cmd_help
        assert cmd_help([]) is True
        out = capsys.readouterr().out
        assert "LIDRA Commands" in out
        assert "Block Management" in out

    def test_cli_banner_renders_and_shows_the_version(self, capsys):
        from cli.main import LIDRACli, VERSION
        LIDRACli().print_banner()
        out = capsys.readouterr().out
        assert "Security CLI" in out
        assert VERSION in out

    def test_dashboard_welcome_renders_without_the_ebpf_claim(self, capsys):
        from dashboard.cli import CLIDashboard
        CLIDashboard(None).print_welcome()
        out = capsys.readouterr().out
        assert "LIDRA" in out
        assert "eBPF" not in out


class TestNoUndemonstrableClaims:
    def test_no_banner_claims_an_unwired_mechanism(self):
        offenders = []
        for path in sorted(SRC.rglob("*.py")):
            text = _code_text(path)
            for claim in _BANNED_CLAIMS:
                if claim in text:
                    offenders.append(f"{path.relative_to(SRC)}: {claim}")
        assert not offenders, "undemonstrable capability claim(s): " + "; ".join(offenders)

    def test_readme_does_not_claim_an_unwired_mechanism(self):
        readme = Path(__file__).resolve().parent.parent / "README.md"
        text = readme.read_text(encoding="utf-8")
        for claim in _BANNED_CLAIMS:
            assert claim not in text, f"README still claims {claim!r}"

    def test_agent_docstring_is_honest_about_what_is_unwired(self):
        text = (SRC / "lidra_agent_v3.py").read_text(encoding="utf-8")
        assert "not wired into this agent" in text


    def test_matches_pyproject(self):
        from utils import version
        declared = version.package_version_from_pyproject()
        if declared:  # source tree present
            assert declared == version.__version__, (declared, version.__version__)