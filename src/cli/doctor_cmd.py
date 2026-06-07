"""`lidra doctor` — read-only environment diagnostics."""

from __future__ import annotations

import logging
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

from rich.box import ROUNDED, SIMPLE
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

logger = logging.getLogger(__name__)

console = Console()


_LEVEL_STYLE = {
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "ok": "green",
}


def _styled(level: str, text: str) -> str:
    style = _LEVEL_STYLE.get(level, "white")
    return f"[{style}]{text}[/{style}]"


def _yes(b: bool) -> str:
    return "[green]\u2713[/green]" if b else "[red]\u2717[/red]"


def _resolve_db_path() -> Path:
    try:
        from utils.config_loader import get_cfg
        rel = get_cfg("database.path")
        if rel:
            return Path(rel).expanduser().resolve()
    except Exception as e:
        logger.debug(f"[doctor] get_cfg database.path failed: {e}")
    try:
        from utils.paths import get_data_dir
        return get_data_dir() / "lidra.db"
    except Exception:
        return Path("data") / "lidra.db"


def _inspect_database(db_path: Path) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "path": str(db_path),
        "exists": db_path.exists(),
        "size_bytes": 0,
        "size_human": "n/a",
        "tables": [],
        "last_attack": None,
        "last_alert": None,
        "attackers": 0,
        "blocks": 0,
    }
    if not db_path.exists():
        return info

    try:
        info["size_bytes"] = db_path.stat().st_size
        size = info["size_bytes"]
        for unit in ("B", "K", "M", "G"):
            if size < 1024:
                info["size_human"] = f"{size:.1f}{unit}"
                break
            size /= 1024
        else:
            info["size_human"] = f"{size:.1f}T"
    except OSError as e:
        logger.debug(f"[doctor] stat db failed: {e}")

    def _table_columns(cur: sqlite3.Cursor, table: str) -> List[str]:
        try:
            return [
                r[1]
                for r in cur.execute(f"PRAGMA table_info({table})").fetchall()
            ]
        except sqlite3.Error:
            return []

    conn = None
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        tables = [
            r[0]
            for r in c.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        ]
        info["tables"] = tables
        if "attacks" in tables:
            cols = _table_columns(c, "attacks")
            select_cols = [c_ for c_ in ("id", "attack_type", "source_log", "timestamp", "ip_address") if c_ in cols]
            if select_cols:
                try:
                    row = c.execute(
                        f"SELECT {', '.join(select_cols)} FROM attacks ORDER BY id DESC LIMIT 1"
                    ).fetchone()
                    if row:
                        info["last_attack"] = dict(row)
                except sqlite3.Error:
                    pass
            try:
                row = c.execute("SELECT COUNT(*) FROM attackers").fetchone()
                info["attackers"] = row[0] if row else 0
            except sqlite3.Error:
                pass
        if "alerts" in tables:
            cols = _table_columns(c, "alerts")
            select_cols = [c_ for c_ in ("id", "alert_type", "severity", "ip_address", "created_at") if c_ in cols]
            if select_cols:
                try:
                    row = c.execute(
                        f"SELECT {', '.join(select_cols)} FROM alerts ORDER BY id DESC LIMIT 1"
                    ).fetchone()
                    if row:
                        info["last_alert"] = dict(row)
                except sqlite3.Error:
                    pass
        if "blocks" in tables:
            try:
                row = c.execute("SELECT COUNT(*) FROM blocks").fetchone()
                info["blocks"] = row[0] if row else 0
            except sqlite3.Error:
                pass
    except sqlite3.Error as e:
        logger.debug(f"[doctor] sqlite inspect failed: {e}")
        info["error"] = str(e)
    finally:
        if conn is not None:
            conn.close()
    return info


def _table_system(report: Dict[str, Any]) -> Table:
    t = Table(title="System", box=SIMPLE, show_header=True, header_style="bold cyan")
    t.add_column("Key", style="cyan", width=18)
    t.add_column("Value", style="white")
    sys_info = report.get("system", {})
    distro = report.get("distro", {})
    t.add_row("Hostname", sys_info.get("hostname", "-"))
    t.add_row("Kernel", sys_info.get("kernel", "-"))
    t.add_row("Arch", sys_info.get("arch", "-"))
    t.add_row("Python", f"{sys_info.get('python', '-')}  ({sys_info.get('python_path', '-')})")
    t.add_row("User", f"{sys_info.get('user', '-')} (uid={sys_info.get('uid', '-')})")
    t.add_row("Distro", distro.get("pretty_name") or f"{distro.get('name', '-')} {distro.get('version', '')}".strip())
    t.add_row("Family", distro.get("family", "-"))
    t.add_row("Init", distro.get("init", "-"))
    t.add_row("Pkg manager", distro.get("pkg_manager", "-"))
    return t


def _table_network(report: Dict[str, Any]) -> Table:
    t = Table(title="Network", box=SIMPLE, show_header=True, header_style="bold cyan")
    t.add_column("Key", style="cyan", width=18)
    t.add_column("Value", style="white")
    net = report.get("network", {})
    t.add_row("Interface", net.get("interface") or _styled("error", "NONE"))
    t.add_row("IP", net.get("ip") or "-")
    t.add_row("MAC", net.get("mac") or "-")
    t.add_row("Netmask", net.get("netmask") or "-")
    t.add_row("Gateway", net.get("gateway") or "-")
    return t


def _table_logs(report: Dict[str, Any]) -> Table:
    t = Table(title="Logs", box=SIMPLE, show_header=True, header_style="bold cyan")
    t.add_column("Source", style="cyan")
    t.add_column("Status", style="white")
    logs = report.get("logs", {})
    preferred = logs.get("preferred", [])
    files = logs.get("files", [])
    jc = logs.get("journalctl", False)
    t.add_row("journalctl", _yes(jc) + (" (preferred)" if preferred and preferred[0] == "journalctl" else ""))
    for path in [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/messages",
        "/var/log/syslog",
        "/var/log/kern.log",
    ]:
        present = path in files
        t.add_row(path, _yes(present) + (" (will monitor)" if present else ""))
    if not files and not jc:
        t.add_row("(none)", _styled("error", "No log sources available"))
    return t


def _table_capabilities(report: Dict[str, Any]) -> Table:
    t = Table(title="Capabilities", box=SIMPLE, show_header=True, header_style="bold cyan")
    t.add_column("Tool", style="cyan", width=18)
    t.add_column("Available", style="white")
    caps = report.get("capabilities", {})
    for key in ("iptables", "nftables", "bcc", "docker", "systemctl", "journalctl", "ethtool", "libpcap"):
        t.add_row(key, _yes(caps.get(key, False)))
    return t


def _table_lidra_config() -> Table:
    t = Table(title="LIDRA Config", box=SIMPLE, show_header=True, header_style="bold cyan")
    t.add_column("Key", style="cyan", width=18)
    t.add_column("Value", style="white")
    try:
        from utils.config_loader import get_cfg
        from utils.paths import get_config_path
        cfg_path = str(get_config_path())
    except Exception as e:
        logger.debug(f"[doctor] config_loader import failed: {e}")
        get_cfg = None
        cfg_path = "(unknown)"

    t.add_row("Config path", cfg_path)
    t.add_row("Config exists", _yes(Path(cfg_path).exists() if cfg_path != "(unknown)" else False))

    if get_cfg is None:
        t.add_row("(skipped)", "config_loader unavailable")
        return t

    mode = get_cfg("mode", "(unset)")
    dry_run = get_cfg("dry_run", "(unset)")
    iface = get_cfg("collectors.network.interface") or get_cfg("local.interface") or "(auto)"
    bridge_wan = get_cfg("bridge.interfaces.wan") or "(auto)"
    bridge_lan = get_cfg("bridge.interfaces.lan") or "(auto)"
    log_dir = get_cfg("log_dir", "(unset)")
    state_dir = get_cfg("state_dir", "(unset)")

    t.add_row("mode", str(mode))
    t.add_row("dry_run", str(dry_run))
    t.add_row("interface (local)", str(iface))
    t.add_row("bridge.wan / bridge.lan", f"{bridge_wan} / {bridge_lan}")
    t.add_row("log_dir", str(log_dir))
    t.add_row("state_dir", str(state_dir))
    return t


def _database_health() -> Dict[str, Any]:
    """Return database health as a dict (for JSON output)."""
    db_path = _resolve_db_path()
    info = _inspect_database(db_path)
    return {
        "path": info["path"],
        "exists": info["exists"],
        "size_human": info["size_human"],
        "tables": info["tables"],
        "attackers": info.get("attackers", 0),
        "blocks": info.get("blocks", 0),
        "last_attack": info.get("last_attack"),
        "last_alert": info.get("last_alert"),
        "error": info.get("error"),
    }


def _lidra_config_summary() -> Dict[str, Any]:
    """Return LIDRA config summary as a dict (for JSON output)."""
    out: Dict[str, Any] = {}
    try:
        from utils.config_loader import get_cfg
        from utils.paths import get_config_path
        out["config_path"] = str(get_config_path())
    except Exception as e:
        out["config_path"] = None
        out["error"] = f"config_loader unavailable: {e}"
        return out
    out["config_exists"] = Path(out["config_path"]).exists()
    out["mode"] = get_cfg("mode", "(unset)")
    out["dry_run"] = get_cfg("dry_run", "(unset)")
    out["interface"] = (
        get_cfg("collectors.network.interface")
        or get_cfg("local.interface")
        or "(auto)"
    )
    out["bridge_wan"] = get_cfg("bridge.interfaces.wan") or "(auto)"
    out["bridge_lan"] = get_cfg("bridge.interfaces.lan") or "(auto)"
    out["main_loop_cycle_seconds"] = get_cfg("main_loop.cycle_seconds", 60)
    out["threat_intel_cache_ttl_seconds"] = get_cfg("threat_intel.cache_ttl_seconds", 3600)
    return out


def _table_database() -> Table:
    t = Table(title="Database", box=SIMPLE, show_header=True, header_style="bold cyan")
    t.add_column("Key", style="cyan", width=18)
    t.add_column("Value", style="white")
    info = _database_health()

    t.add_row("Path", str(info["path"]))
    t.add_row("Exists", _yes(bool(info["exists"])))
    t.add_row("Size", str(info["size_human"]))
    t.add_row("Tables", ", ".join(info["tables"]) if info["tables"] else "-")
    t.add_row("Attackers", str(info.get("attackers", 0)))
    t.add_row("Active blocks", str(info.get("blocks", 0)))
    last_atk = info.get("last_attack")
    if last_atk:
        ts = str(last_atk.get("timestamp", "-"))
        atype = last_atk.get("attack_type", "-")
        t.add_row("Last attack", f"{atype} @ {ts}")
    else:
        t.add_row("Last attack", "-")
    last_al = info.get("last_alert")
    if last_al:
        sev = last_al.get("severity", "-")
        ip = last_al.get("ip_address", "-")
        ts = str(last_al.get("created_at", "-"))
        sev_rendered = f"[{sev}]" if sev and sev != "-" else ""
        t.add_row("Last alert", escape(f"{sev_rendered} {ip} @ {ts}".strip()))
    else:
        t.add_row("Last alert", "-")
    if info.get("error"):
        t.add_row("Error", _styled("error", info["error"]))
    return t


def _table_issues(report: Dict[str, Any]) -> Table:
    t = Table(title="Issues", box=SIMPLE, show_header=True, header_style="bold cyan")
    t.add_column("Level", style="white", width=10)
    t.add_column("Code", style="cyan", width=18)
    t.add_column("Message", style="white")
    issues = report.get("issues", []) or []
    if not issues:
        t.add_row(_styled("ok", "OK"), "-", "No issues detected")
    for issue in issues:
        level = issue.get("level", "info")
        t.add_row(_styled(level, level.upper()), issue.get("code", "-"), issue.get("message", "-"))
    return t


def _exit_code_for(issues: List[Dict[str, str]]) -> int:
    if any(i.get("level") == "error" for i in issues):
        return 2
    if any(i.get("level") == "warning" for i in issues):
        return 1
    return 0


def cmd_doctor(args: List[str]) -> int:
    """Run the diagnostic and return an exit code (0/1/2)."""
    as_json = "--json" in args
    try:
        from utils.distro_detect import detect_all
    except Exception as e:
        if as_json:
            import json
            print(json.dumps({"ok": False, "error": f"distro_detect import failed: {e}"}))
        else:
            console.print(Panel(
                f"[bold red]distro_detect import failed[/bold red]\n{e}",
                title="[bold]LIDRA Doctor[/bold]",
                border_style="red",
            ))
        return 2

    report = detect_all()
    report["database"] = _database_health()
    report["lidra_config"] = _lidra_config_summary()
    report["exit_code"] = _exit_code_for(report.get("issues", []))
    report["ok"] = report["exit_code"] == 0

    if as_json:
        import json
        print(json.dumps(report, indent=2, default=str))
        return report["exit_code"]

    console.print(Panel(
        f"[bold cyan]LIDRA Doctor[/bold cyan]  "
        f"[dim]read-only environment check[/dim]\n"
        f"[dim]{report.get('system', {}).get('hostname', '?')} \u00b7 "
        f"{report.get('distro', {}).get('pretty_name') or report.get('distro', {}).get('name', '?')}[/dim]",
        border_style="cyan",
    ))

    console.print(_table_system(report))
    console.print(_table_network(report))
    console.print(_table_logs(report))
    console.print(_table_capabilities(report))
    console.print(_table_lidra_config())
    console.print(_table_database())
    console.print(_table_issues(report))

    code = report["exit_code"]
    if code == 0:
        console.print("\n[bold green]\u2713 All checks passed[/bold green]")
    elif code == 1:
        console.print("\n[bold yellow]! Warnings present — review above[/bold yellow]")
    else:
        console.print("\n[bold red]\u2717 Errors detected — LIDRA may not function correctly[/bold red]")
    return code


if __name__ == "__main__":
    sys.exit(cmd_doctor(sys.argv[1:]))
