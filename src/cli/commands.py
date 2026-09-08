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

BASE_DIR = Path(__file__).parent.parent.parent
LOG_FILE = BASE_DIR / "logs" / "lidra_v3.log"


def _open_db():
    """Open the agent's SQLite DB, or None (with a message) if unavailable."""
    try:
        from cli.doctor_cmd import _resolve_db_path
        from database.db import LIDRADatabase
    except ImportError as e:
        console.print(f"[red]Cannot load DB layer: {e}[/red]")
        return None
    try:
        db_path = _resolve_db_path()
        if not db_path.exists():
            console.print(f"[yellow]No database yet at {db_path} (agent hasn't run?)[/yellow]")
            return None
        return LIDRADatabase(str(db_path))
    except Exception as e:
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
    """Show quick system status from the local DB."""
    db = _open_db()
    if db is None:
        return False
    stats = db.get_attacker_stats()
    n_blocks = len(_active_blocks(db))

    cpu = psutil.cpu_percent(interval=0.5)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    console.print(Panel(
        f"[cyan]Attackers:[/cyan] {stats.get('total_attackers', 0)}  |  "
        f"[orange]Attacks (24h):[/orange] {stats.get('attacks_24h', 0)}  |  "
        f"[red]Active Blocks:[/red] {n_blocks}\n"
        f"[blue]CPU:[/blue] {cpu:.1f}%  |  "
        f"[green]Memory:[/green] {memory.percent:.1f}%  |  "
        f"[yellow]Disk:[/yellow] {disk.percent:.1f}%",
        title="[bold]System Status[/bold]",
        box=box.DOUBLE
    ))
    return True


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

    try:
        fw = _firewall()
    except Exception as e:
        console.print(f"[red]Cannot init firewall: {e}[/red]")
        return False
    if not fw.block_ip(ip, ttl_seconds=3600):
        console.print(f"[red]Failed to block {ip} (need root?)[/red]")
        return False
    db = _open_db()
    if db is not None:
        try:
            db.mark_block_applied(db.add_block(ip, reason))
        except Exception as e:
            logger.warning(f"[CLI] Block applied but DB record failed: {e}")
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
    console.print(f"[green]Unblocked {ip}[/green]")
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
    console.print("  LIDRA v3 - SECURITY MONITOR")
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
[bold cyan]LIDRA v3 Commands:[/bold cyan]

[green]Status & Info:[/green]
  lidra           - Full dashboard (all stats) [DEFAULT]
  lidra status    - Quick system status
  lidra alerts    - Show recent alerts
  lidra blocks    - Show active blocks
  lidra mitre     - Show MITRE ATT&CK coverage
  lidra logs      - Show logs
  lidra doctor    - System health check (read-only)

[yellow]Actions:[/green]
  lidra honeypot  - Start honeypot service
  lidra test      - Add test attack data
  lidra install   - Show install instructions

[red]Block Management:[/red]
  lidra block <ip>   - Block an IP

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