# src/cli/commands.py
"""LIDRA CLI Commands - local-first: reads the agent's SQLite DB, enforces via firewall.

There is no REST API (metrics are Prometheus text on :8080); every command
below works against the local database / firewall directly.
"""

import ipaddress
import logging
import os
import subprocess
from pathlib import Path
from typing import List

import psutil
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

logger = logging.getLogger(__name__)
console = Console()

# Single source of truth: utils/version.py.
try:
    from utils.version import version_string as _version_string
    VERSION: str = _version_string()
except Exception:  # pragma: no cover - CLI can load without src/ on sys.path
    VERSION = "v0.0.0"

BASE_DIR = Path(__file__).parent.parent.parent
LOG_FILE = BASE_DIR / "logs" / "lidra_v3.log"


def _actor() -> str:
    """Who is running this command — the human behind sudo, not "root"."""
    from utils.actor import current_actor
    return current_actor()


def _audit(action: str, target: str, detail: str = "", source: str = "cli") -> None:
    """Best-effort audit write — never fails the command that triggered it.

    Goes through ``_open_db`` (quietly) so there is exactly one place that
    decides which database this process talks to, and returns silently when
    there is no database yet.
    """
    try:
        db = _open_db(quiet=True)
        if db is not None:
            db.log_audit(_actor(), action, target, detail, source)
    except Exception as e:
        logger.warning("[CLI] audit write failed for %s %s: %s", action, target, e)


def _open_db(quiet: bool = False):
    """Open the agent's SQLite DB, or None if unavailable.

    ``quiet`` suppresses the console hint — used by the audit writer, which
    must never add output to the command it is recording.
    """
    try:
        from cli.doctor_cmd import _resolve_db_path
        from database.db import LIDRADatabase
    except ImportError as e:
        if not quiet:
            console.print(f"[red]Cannot load DB layer: {e}[/red]")
        return None
    try:
        db_path = _resolve_db_path()
        if not db_path.exists():
            if not quiet:
                console.print(f"[yellow]No database yet at {db_path} (agent hasn't run?)[/yellow]")
            return None
        return LIDRADatabase(str(db_path))
    except Exception as e:
        if not quiet:
            console.print(f"[red]Cannot open database: {e}[/red]")
        return None


def _firewall():
    """FirewallManager honoring config backend + LIDRA_DRY_RUN."""
    from response.firewall import FirewallManager
    from utils.config_loader import get_cfg
    backend = get_cfg("response.firewall", "auto") or "auto"
    dry_run = os.environ.get("LIDRA_DRY_RUN") == "1" \
        or get_cfg("response.dry_run", False) is True
    return FirewallManager(backend=backend, dry_run=dry_run)


def check_docker():
    """Check if running in docker."""
    try:
        result = subprocess.run(['docker', 'ps'], capture_output=True, text=True, timeout=5)
        return 'lidra-agent' in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return False


def _active_blocks(db) -> list:
    """Active (unexpired, applied) blocks from the DB."""
    from response.blocklist import Blocklist
    bl = Blocklist(db)
    bl.sync_from_db()
    return bl.get_all()


def cmd_status(args: List[str]) -> bool:
    """Single health answer: version, agent, queue rule, DB.

    This is the one command support asks for first, so it reads everything:
    binary version, IPC socket (daemon alive?), the kernel queue rule state,
    DB size and the last alert. Anything wrong makes the verdict DEGRADED.
    """
    from utils.version import __version__
    db = _open_db()
    try:
        from utils.runtime import find_socket
        socket_path = find_socket()
    except Exception:
        socket_path = None

    lines = [f"[bold]LIDRA {__version__}[/bold]"]
    degraded = []

    if socket_path:
        lines.append(f"[green]agent:[/green] live (ipc: {socket_path})")
    else:
        lines.append("[yellow]agent:[/yellow] not running, or no IPC socket - "
                     "the TUI would show mock data. Start the agent first.")
        degraded.append("agent down")

    queue_state = _queue_rule_state()
    lines.append(f"queue rule: {queue_state}")
    if "WITHOUT bypass" in queue_state:
        degraded.append("queue rule without bypass")

    if db is not None:
        try:
            stats = db.get_attacker_stats()
            alerts = db.get_recent_alerts(1)
            last = alerts[0] if alerts else None
            n_blocks = len(_active_blocks(db))
            size = _db_size_mb(db)
            lines.append(
                f"[cyan]attackers:[/cyan] {stats.get('total_attackers', 0)}  |  "
                f"[orange]attacks (24h):[/orange] {stats.get('attacks_24h', 0)}  |  "
                f"[red]active blocks:[/red] {n_blocks}  |  "
                f"[dim]db: {size}[/dim]"
            )
            if last:
                lines.append(
                    f"last alert: {last.get('severity', '?')} "
                    f"{last.get('alert_type', '?')} from {last.get('ip_address', '?')} "
                    f"at {str(last.get('created_at', '-'))[:19]}"
                )
            else:
                lines.append("last alert: none recorded")
        except Exception as e:
            lines.append(f"[red]db error:[/red] {e}")
            degraded.append("db unreadable")
    else:
        degraded.append("no database")

    cpu = psutil.cpu_percent(interval=0.5)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    lines.append(
        f"[blue]CPU:[/blue] {cpu:.1f}%  |  "
        f"[green]Memory:[/green] {memory.percent:.1f}%  |  "
        f"[yellow]Disk:[/yellow] {disk.percent:.1f}%"
    )

    verdict = "[green]OK[/green]" if not degraded else "[red]DEGRADED:[/red] " + ", ".join(degraded)
    console.print(Panel(
        "\n".join(lines),
        title=f"[bold]System Status - {verdict}[/bold]",
        box=box.DOUBLE
    ))
    return not degraded


def _queue_rule_state() -> str:
    """Describe LIDRA's kernel queue rule the way the operator needs it."""
    try:
        result = subprocess.run(
            ["nft", "list", "tables"], capture_output=True, text=True, timeout=5,
        )
        tables = (result.stdout or "")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown (nft not available)"
    if "lidra_nfqueue" not in tables:
        return "no inline rule (monitor mode)"
    try:
        rules = subprocess.run(
            ["nft", "list", "table", "inet", "lidra_nfqueue"],
            capture_output=True, text=True, timeout=5,
        ).stdout or ""
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "lidra_nfqueue table present (detail unavailable)"
    if "bypass" in rules:
        return "[green]inline rule present, fail-open (bypass)[/green]"
    return "[red]inline rule present WITHOUT bypass - connectivity at risk[/red]"


def _db_size_mb(db) -> str:
    try:
        path = getattr(db, "db_path", None)
        if path and Path(path).exists():
            return f"{Path(path).stat().st_size / 1_048_576:.1f} MB"
    except OSError:
        pass
    return "?"


def cmd_alerts(args: List[str]) -> bool:
    """Show recent alerts from the local DB."""
    db = _open_db()
    if db is None:
        return False
    alerts = db.get_recent_alerts(15)

    if not alerts:
        console.print("[yellow]No alerts found.[/yellow]")
        return True

    table = Table(title="Recent Alerts", box=box.SIMPLE)
    table.add_column("Severity", style="red", width=10)
    table.add_column("Type", style="yellow", width=20)
    table.add_column("IP", style="cyan", width=18)
    table.add_column("Time", style="dim", width=12)

    for alert in alerts[:15]:
        sev = alert.get("severity", "low")
        sev_style = "bold red" if sev == "critical" else "red" if sev == "high" else "yellow"
        table.add_row(
            Text(sev.upper(), style=sev_style),
            alert.get("alert_type", "-"),
            alert.get("ip_address", "-"),
            str(alert.get("created_at", "-"))[:10]
        )

    console.print(table)
    return True


def cmd_blocks(args: List[str]) -> bool:
    """Show active blocks from the local DB."""
    db = _open_db()
    if db is None:
        return False
    blocks = _active_blocks(db)

    if not blocks:
        console.print("[yellow]No active blocks.[/yellow]")
        return True

    table = Table(title="Active Blocks", box=box.SIMPLE)
    table.add_column("IP Address", style="red", width=20)
    table.add_column("Reason", style="yellow", width=35)
    table.add_column("Until", style="dim", width=18)

    for block in blocks:
        table.add_row(
            block.get("ip", "-"),
            (block.get("reason") or "-")[:33],
            str(block.get("expires_at", "-"))[:16]
        )

    console.print(table)
    return True


def cmd_block_ip(args: List[str]) -> bool:
    """Block an IP address via the firewall + record it in the DB."""
    if not args:
        console.print("[red]Usage: block <ip_address>[/red]")
        return False

    ip = args[0]
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        console.print(f"[red]Refusing to block invalid IP: {ip}[/red]")
        return False
    reason = " ".join(args[1:]) if len(args) > 1 else "Manual block"

    # F4: blocking this host's own address, its gateway or its resolver takes
    # the operator off the network LIDRA is defending. Say so explicitly
    # instead of letting it surface as a generic firewall failure.
    from response.firewall import is_protected
    if is_protected(ip):
        console.print(
            f"[red]Refusing to block {ip}[/red] — it is this host's own address, "
            "default gateway or DNS resolver."
        )
        console.print("[dim]Blocking it would take this host off the network.[/dim]")
        _audit("block_refused", ip, "protected address (own/gateway/resolver)")
        return False

    try:
        fw = _firewall()
    except Exception as e:
        console.print(f"[red]Cannot init firewall: {e}[/red]")
        return False
    if not fw.block_ip(ip, ttl_seconds=3600):
        console.print(f"[red]Failed to block {ip} (need root?)[/red]")
        return False
    # Dry-run is the default (`response.dry_run: true`) and means "log every
    # detection, never block". The firewall returns success without writing a
    # rule, so the row must stay applied=0 or `lidra status` reports an active
    # block that does not exist in the kernel.
    dry_run = bool(getattr(fw, "dry_run", False))
    db = _open_db()
    if db is not None:
        try:
            block_id = db.add_block(ip, reason)
            if dry_run:
                logger.info("[CLI] dry-run: recorded block for %s without applying it", ip)
            else:
                db.mark_block_applied(block_id)
            db.log_audit(
                _actor(), "block", ip,
                f"{reason} (dry-run: not applied)" if dry_run else reason,
                "cli",
            )
        except Exception as e:
            logger.warning(f"[CLI] Block applied but DB record failed: {e}")
    if dry_run:
        console.print(
            f"[yellow]DRY-RUN: would block {ip}[/yellow] "
            f"[dim](reason: {reason} — recorded, no kernel rule written)[/dim]"
        )
    else:
        console.print(f"[green]Blocked {ip} (reason: {reason})[/green]")
    return True


def cmd_unblock_ip(args: List[str]) -> bool:
    """Unblock an IP address via the firewall + clear it in the DB."""
    if not args:
        console.print("[red]Usage: unblock <ip_address>[/red]")
        return False
    ip = args[0]
    try:
        fw = _firewall()
    except Exception as e:
        console.print(f"[red]Cannot init firewall: {e}[/red]")
        return False
    if not fw.unblock_ip(ip):
        console.print(f"[red]Failed to unblock {ip} (need root?)[/red]")
        return False
    db = _open_db()
    if db is not None:
        try:
            from response.blocklist import Blocklist
            Blocklist(db).unblock(ip)
        except Exception as e:
            logger.warning(f"[CLI] Unblocked but DB clear failed: {e}")
    _audit("unblock", ip, "removed by operator")
    console.print(f"[green]Unblocked {ip}[/green]")
    return True


def cmd_audit(args: List[str]) -> bool:
    """Show the operator audit trail (who blocked/unblocked what, and when)."""
    limit = 50
    if args:
        try:
            limit = max(1, int(args[0]))
        except ValueError:
            console.print(f"[red]Usage: audit [count]  (got {args[0]!r})[/red]")
            return False

    db = _open_db()
    if db is None:
        return False

    entries = db.get_audit_log(limit)
    if not entries:
        console.print("[dim]No operator actions recorded yet.[/dim]")
        return True

    table = Table(title=f"Audit log (last {len(entries)})", box=box.SIMPLE,
                  show_lines=False)
    table.add_column("When", style="dim", no_wrap=True)
    table.add_column("Actor", style="cyan")
    table.add_column("Action", style="yellow")
    table.add_column("Target", style="white")
    table.add_column("Detail")
    table.add_column("Source", style="dim")

    styles = {"block": "red", "unblock": "green", "block_refused": "orange3"}
    for entry in entries:
        action = entry.get("action", "?")
        table.add_row(
            str(entry.get("created_at", ""))[:19],
            entry.get("actor", "?"),
            f"[{styles.get(action, 'white')}]{action}[/]",
            entry.get("target", "") or "-",
            entry.get("detail", "") or "-",
            entry.get("source", "") or "-",
        )
    console.print(table)
    return True


def cmd_mitre(args: List[str]) -> bool:
    """Show MITRE ATT&CK coverage (computed locally)."""
    from detection.mitre import MITREMapper
    data = MITREMapper().get_coverage_report()

    console.print(Panel(
        f"[cyan]Techniques:[/cyan] {data.get('total_techniques', 0)}  |  "
        f"[orange]Tactics:[/orange] {data.get('total_tactics', 0)}  |  "
        f"[green]Coverage:[/green] {data.get('coverage_percentage', 0)}%",
        title="[bold]MITRE ATT&CK Coverage[/bold]",
        box=box.DOUBLE
    ))

    console.print("\n[cyan]Tactics:[/cyan]")
    for tactic in sorted(data.get('tactics', [])):
        console.print(f"  • {tactic}")

    return True


def cmd_logs(args: List[str]) -> bool:
    """Show recent logs."""
    log_path = Path("/opt/lidra/logs/lidra_v3.log")
    if not log_path.exists():
        log_path = BASE_DIR / "logs" / "lidra_v3.log"

    lines = 20
    if args and args[0].isdigit():
        lines = int(args[0])

    if log_path.exists():
        with open(log_path) as f:
            recent = f.readlines()[-lines:]
        for line in recent:
            if "[WARNING]" in line or "[ERROR]" in line:
                console.print(f"[red]{line.strip()}[/red]")
            else:
                console.print(f"[dim]{line.strip()}[/dim]")
    else:
        console.print("[yellow]No logs found.[/yellow]")
    return True


def cmd_test(args: List[str]) -> bool:
    """Insert a synthetic test attacker/alert into the local DB."""
    db = _open_db()
    if db is None:
        return False
    try:
        attacker_id = db.add_attacker("192.168.99.99", "XX", "Test")
        db.record_attack(attacker_id, "test_attack", source_log="cli",
                         raw_line="Test from CLI", dedupe=False)
        db.add_alert("test_attack", "low", "192.168.99.99", "Test alert")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return False
    console.print("[green]Test data added![/green]")
    return cmd_status([])


def cmd_dashboard(args: List[str]) -> bool:
    """Run the terminal dashboard via API."""
    return cmd_full_dashboard(args)


def cmd_full_dashboard(args: List[str]) -> bool:
    """Show full dashboard (all data) - compact one-screen view."""
    from collections import Counter
    from detection.mitre import MITREMapper
    db = _open_db()
    if db is None:
        return False
    stats = db.get_attacker_stats()
    blocks = _active_blocks(db)
    alerts = db.get_recent_alerts(4)
    type_counts = Counter(
        a.get("attack_type", "?") for a in db.get_recent_attacks(100))
    sessions = db.get_honeypot_sessions(1)
    mitre = MITREMapper().get_coverage_report()

    cpu = psutil.cpu_percent(interval=0.3)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    console.print("\n" + "="*50)
    console.print("  LIDRA - SECURITY MONITOR")
    console.print("="*50)

    # ALL IN ONE LINE - Key stats
    console.print(f"\n[ATTACKS] Total: {stats.get('total_attackers', 0)} | 24h: {stats.get('attacks_24h', 0)} | Blocks: {len(blocks)} | Alerts: {len(alerts)}")

    # System in one line
    console.print(f"[SYSTEM] CPU: {cpu:.0f}% | Mem: {memory.percent:.0f}% | Disk: {disk.percent:.0f}%")

    # Attack Types - compact
    if type_counts:
        at_str = " | ".join(f"{t[:12]}:{c}" for t, c in type_counts.most_common(6))
        console.print(f"[TYPES] {at_str}")

    # Honeypot & MITRE - compact
    console.print(f"[HONEYPOT] Sessions:{len(sessions)} | [MITRE] Tech:{mitre.get('total_techniques', 0)} Cov:{mitre.get('coverage_percentage', 0)}%")

    # Recent alerts - compact
    if alerts:
        alerts_str = " | ".join(f"{(a.get('severity') or '?')[0].upper()}:{(a.get('ip_address') or '-')[:12]}" for a in alerts)
        console.print(f"[ALERTS] {alerts_str}")

    console.print("\n" + "="*50)
    console.print(" Commands: lidra status | lidra alerts | lidra web")
    console.print("="*50 + "\n")

    return True


def cmd_honeypot(args: List[str]) -> bool:
    """Start honeypot service (container) or show the local equivalent."""
    if check_docker():
        console.print("[yellow]Starting honeypot in container...[/yellow]")
        try:
            subprocess.run(
                ['docker', 'exec', '-d', 'lidra-agent', 'python3', '/opt/lidra/src/core/start_honeypot.py'],
                timeout=10
            )
            console.print("[green]Honeypot started![/green]")
            return True
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return False
    console.print("[yellow]No lidra-agent container. Run locally:[/yellow]")
    console.print("  sudo -E python3 src/lidra_agent_v3.py --tui")
    return True


def cmd_agent(args: List[str]) -> bool:
    """Show how to start the detection agent."""
    if check_docker():
        console.print("[yellow]Agent runs in container. Use:[/yellow]")
        console.print("  docker exec lidra-agent python3 /opt/lidra/src/lidra_agent_v3.py")
    else:
        console.print("[yellow]Start the agent locally:[/yellow]")
        console.print("  sudo -E python3 src/lidra_agent_v3.py --tui")
    return True


def cmd_doctor(args: List[str]) -> bool:
    """Run system health check."""
    # ponytail: doctor_cmd returns an exit CODE (0/1/2) but every caller
    # speaks bool — returning it raw inverted single-shot exit codes
    # (healthy exited 1) and quit the interactive loop on a clean bill.
    from cli.doctor_cmd import cmd_doctor as _doctor
    return _doctor(args) == 0


def cmd_install(args: List[str]) -> bool:
    """Show install instructions or run installer."""
    prefix = args[0] if args else "/opt/lidra"
    user = "root"
    src_dir = str(BASE_DIR)

    console.print(Panel(
        f"[bold]LIDRA Installation Plan[/bold]\n\n"
        f"Prefix: [cyan]{prefix}[/cyan]\n"
        f"User:   [cyan]{user}[/cyan]\n"
        f"Source: [cyan]{src_dir}[/cyan]\n\n"
        f"To install, run the post-install script:\n"
        f"  [green]sudo LIDRA_PREFIX={prefix} bash install/post_install.sh[/green]\n\n"
        f"Or run manually:\n"
        f"  1. Install system packages (python3-pip, iptables, libpcap-dev, ethtool)\n"
        f"  2. Create venv: [cyan]python3 -m venv {prefix}/venv[/cyan]\n"
        f"  3. Install deps: [cyan]{prefix}/venv/bin/pip install -r requirements.txt[/cyan]\n"
        f"  4. Copy source: [cyan]rsync -a --delete --exclude=venv {src_dir}/ {prefix}/[/cyan]\n"
        f"  5. Install systemd unit: [cyan]cp install/systemd/lidra.service /etc/systemd/system/[/cyan]\n"
        f"  6. Enable: [cyan]systemctl enable --now lidra.service[/cyan]\n"
        f"  7. Verify: [cyan]lidra doctor[/cyan]",
        title="[bold green]LIDRA Install[/bold green]",
        border_style="green",
    ))
    return True


def cmd_help(args: List[str]) -> bool:
    """Show help."""
    console.print("""
[bold cyan]LIDRA Commands:[/bold cyan]

[green]Status & Info:[/green]
  lidra           - Full dashboard (all stats) [DEFAULT]
  lidra status    - Quick system status
  lidra alerts    - Show recent alerts
  lidra blocks    - Show active blocks
  lidra mitre     - Show MITRE ATT&CK coverage
  lidra logs      - Show logs
  lidra doctor    - System health check (read-only)

[yellow]Actions:[/yellow]
  lidra honeypot  - Start honeypot service
  lidra test      - Add test attack data
  lidra install   - Show install instructions

[red]Block Management:[/red]
  lidra block <ip>   - Block an IP
  lidra unblock <ip> - Unblock an IP
  lidra audit        - Operator audit trail (who did what)

[blue]System:[/blue]
  lidra help      - Show this help

[dim]Note: Commands read the local agent database directly[/dim]
""")
    return True


COMMANDS = {
    'status': (cmd_status, 'Quick system status'),
    'alerts': (cmd_alerts, 'Show recent alerts'),
    'blocks': (cmd_blocks, 'Show active blocks'),
    'block': (cmd_block_ip, 'Block an IP'),
    'unblock': (cmd_unblock_ip, 'Unblock an IP'),
    'audit': (cmd_audit, 'Show who blocked/unblocked what'),
    'mitre': (cmd_mitre, 'Show MITRE coverage'),
    'logs': (cmd_logs, 'Show logs'),
    'test': (cmd_test, 'Add test data'),
    'doctor': (cmd_doctor, 'Run system health check'),
    'install': (cmd_install, 'Show install instructions'),
    'web': (cmd_dashboard, 'Show terminal dashboard'),
    'dashboard': (cmd_dashboard, 'Run terminal dashboard'),
    'full_dashboard': (cmd_full_dashboard, 'Full dashboard'),
    'honeypot': (cmd_honeypot, 'Start honeypot'),
    'agent': (cmd_agent, 'Start detection agent'),
    'help': (cmd_help, 'Show help'),
}