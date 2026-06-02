# src/cli/commands.py
"""LIDRA CLI Commands - All command implementations via Web API."""

import os
import sys
import time
import subprocess
import psutil
import requests
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

BASE_DIR = Path(__file__).parent.parent.parent
LOG_FILE = BASE_DIR / "logs" / "lidra_v3.log"

API_BASE = "http://localhost:8080/api"

USE_DOCKER = False


def check_docker():
    """Check if running in docker."""
    try:
        result = subprocess.run(['docker', 'ps'], capture_output=True, text=True, timeout=5)
        return 'lidra-core' in result.stdout
    except:
        return False


def api_get(endpoint: str) -> dict:
    """Make API request."""
    url = "http://localhost:8080/api" + endpoint
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        pass
    return {}


def cmd_status(args: List[str]) -> bool:
    """Show quick system status via API."""
    stats = api_get("/stats")
    if not stats:
        console.print("[red]Cannot connect to LIDRA. Is container running?[/red]")
        console.print("[yellow]Try: docker start lidra-core[/yellow]")
        return False

    cpu = psutil.cpu_percent(interval=0.5)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    console.print(Panel(
        f"[cyan]Attackers:[/cyan] {stats.get('total_attackers', 0)}  |  "
        f"[orange]Attacks (24h):[/orange] {stats.get('attacks_24h', 0)}  |  "
        f"[red]Active Blocks:[/red] {len(stats.get('blocks', []))}\n"
        f"[blue]CPU:[/blue] {cpu:.1f}%  |  "
        f"[green]Memory:[/green] {memory.percent:.1f}%  |  "
        f"[yellow]Disk:[/yellow] {disk.percent:.1f}%",
        title="[bold]System Status[/bold]",
        box=box.DOUBLE
    ))
    return True


def cmd_alerts(args: List[str]) -> bool:
    """Show recent alerts via API."""
    data = api_get("/alerts")
    alerts = data.get("alerts", [])

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
    """Show active blocks via API."""
    data = api_get("/blocks")
    blocks = data.get("blocks", [])

    if not blocks:
        console.print("[yellow]No active blocks.[/yellow]")
        return True

    table = Table(title="Active Blocks", box=box.SIMPLE)
    table.add_column("IP Address", style="red", width=20)
    table.add_column("Reason", style="yellow", width=35)
    table.add_column("Until", style="dim", width=18)

    for block in blocks:
        table.add_row(
            block.get("ip_address", "-"),
            block.get("reason", "-")[:33],
            str(block.get("block_until", "-"))[:16]
        )

    console.print(table)
    return True


def cmd_block_ip(args: List[str]) -> bool:
    """Block an IP address via API."""
    if not args:
        console.print("[red]Usage: block <ip_address>[/red]")
        return False

    ip = args[0]
    reason = " ".join(args[1:]) if len(args) > 1 else "Manual block"

    try:
        resp = requests.post("http://localhost:8080/api/block",
                            json={"ip": ip, "reason": reason, "ttl_seconds": 3600},
                            timeout=5)
        if resp.status_code == 200:
            console.print(f"[green]Blocked {ip} (reason: {reason})[/green]")
            return True
        else:
            console.print(f"[red]Failed to block: {resp.text}[/red]")
            return False
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return False


def cmd_unblock_ip(args: List[str]) -> bool:
    """Unblock an IP address."""
    if not args:
        console.print("[red]Usage: unblock <ip_address>[/red]")
        return False
    console.print("[yellow]Use 'sudo iptables -D INPUT -s <ip> -j DROP' to manually unblock[/yellow]")
    return True


def cmd_mitre(args: List[str]) -> bool:
    """Show MITRE ATT&CK coverage via API."""
    data = api_get("/mitre-coverage")
    if not data:
        console.print("[red]Cannot connect to LIDRA.[/red]")
        return False

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
    """Test detection with sample data."""
    console.print("[yellow]Adding test data to container...[/yellow]")
    try:
        docker_exec = subprocess.run(
            ['docker', 'exec', 'lidra-core', 'python3', '-c', '''
import sqlite3
conn = sqlite3.connect("/opt/lidra/data/lidra.db")
c = conn.cursor()
c.execute("INSERT INTO attackers (ip_address, country, org) VALUES (?, ?, ?)", ("192.168.99.99", "XX", "Test"))
attacker_id = c.lastrowid
c.execute("INSERT INTO attacks (attacker_id, attack_type, source_log, raw_line) VALUES (?, ?, ?, ?)",
          (attacker_id, "test_attack", "cli", "Test from CLI"))
c.execute("INSERT INTO alerts (alert_type, severity, ip_address, message) VALUES (?, ?, ?, ?)",
          ("test_attack", "low", "192.168.99.99", "Test alert"))
conn.commit()
conn.close()
print("OK")
'''],
            capture_output=True, text=True, timeout=10
        )
        if docker_exec.returncode == 0:
            console.print("[green]Test data added![/green]")
            cmd_status([])
            return True
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
    return False


def cmd_web(args: List[str]) -> bool:
    """Show web dashboard URL."""
    console.print(Panel(
        "[cyan]Web Dashboard:[/cyan] [bold]http://localhost:8080[/bold]\n\n"
        "[dim]Endpoints:[/dim]\n"
        "  • /               - Main dashboard\n"
        "  • /api/stats      - System stats\n"
        "  • /api/attack-types - Attack types\n"
        "  • /api/alerts     - Alerts\n"
        "  • /api/honeypot-stats - Honeypot data\n"
        "  • /api/mitre-coverage - MITRE",
        title="[bold]Web Dashboard[/bold]",
        box=box.DOUBLE
    ))
    return True


def cmd_dashboard(args: List[str]) -> bool:
    """Run the terminal dashboard via API."""
    return cmd_full_dashboard(args)


def cmd_full_dashboard(args: List[str]) -> bool:
    """Show full dashboard (all data) - compact one-screen view."""
    # Get all data from APIs
    stats = api_get("/stats")
    attack_types = api_get("/attack-types")
    honeypot = api_get("/honeypot-stats")
    mitre = api_get("/mitre-coverage")
    blocks = api_get("/blocks")
    alerts = api_get("/alerts")

    if not stats:
        console.print("[red]Cannot connect to LIDRA service![/red]")
        console.print("[yellow]Make sure container is running:[/yellow]")
        console.print("  docker start lidra-core")
        console.print("  docker ps")
        return False

    cpu = psutil.cpu_percent(interval=0.3)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    # Get system info from API if available
    sys_data = stats.get("system", {})
    api_cpu = sys_data.get("cpu_percent", 0)
    api_mem = sys_data.get("memory_percent", 0)

    console.print("\n" + "="*50)
    console.print("  LIDRA v3 - SECURITY MONITOR")
    console.print("="*50)

    # ALL IN ONE LINE - Key stats
    console.print(f"\n[ATTACKS] Total: {stats.get('total_attackers', 0)} | 24h: {stats.get('attacks_24h', 0)} | Blocks: {len(blocks.get('blocks', []))} | Alerts: {len(alerts.get('alerts', []))}")

    # System in one line
    console.print(f"[SYSTEM] CPU: {api_cpu:.0f}% | Mem: {api_mem:.0f}% | Disk: {disk.percent:.0f}%")

    # Attack Types - compact
    at_data = attack_types.get("types", [])
    if at_data:
        at_str = " | ".join([f"{a.get('type', '?')[:12]}:{a.get('count', 0)}" for a in at_data[:6]])
        console.print(f"[TYPES] {at_str}")

    # Honeypot & MITRE - compact
    hp = honeypot.get("honeypot_connections", 0)
    hf = honeypot.get("honeyfile_accesses", 0)
    techniques = mitre.get("total_techniques", 0) if mitre else 0
    coverage = mitre.get("coverage_percentage", 0) if mitre else 0
    console.print(f"[HONEYPOT] HP:{hp} HF:{hf} | [MITRE] Tech:{techniques} Cov:{coverage}%")

    # Recent alerts - compact
    alert_list = alerts.get("alerts", [])
    if alert_list:
        alerts_str = " | ".join([f"{a.get('severity', '?')[0].upper()}:{a.get('ip_address', '-')[:12]}" for a in alert_list[:4]])
        console.print(f"[ALERTS] {alerts_str}")

    console.print("\n" + "="*50)
    console.print(" Commands: lidra status | lidra alerts | lidra web")
    console.print("="*50 + "\n")

    return True


def cmd_honeypot(args: List[str]) -> bool:
    """Start honeypot service."""
    console.print("[yellow]Starting honeypot in container...[/yellow]")
    try:
        subprocess.run(
            ['docker', 'exec', '-d', 'lidra-core', 'python3', '/opt/lidra/src/core/start_honeypot.py'],
            timeout=10
        )
        console.print("[green]Honeypot started![/green]")
        return True
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return False


def cmd_agent(args: List[str]) -> bool:
    """Start detection agent."""
    console.print("[yellow]Agent runs in container. Use:[/yellow]")
    console.print("  docker exec lidra-core python3 /opt/lidra/src/lidra_agent_v3.py")
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
  lidra web       - Show web dashboard URL
  lidra logs      - Show logs

[yellow]Actions:[/green]
  lidra honeypot  - Start honeypot service
  lidra test      - Add test attack data

[red]Block Management:[/red]
  lidra block <ip>   - Block an IP

[blue]System:[/blue]
  lidra help      - Show this help

[dim]Note: All commands connect to running container for live data[/dim]
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
    'web': (cmd_web, 'Show web dashboard'),
    'dashboard': (cmd_dashboard, 'Run terminal dashboard'),
    'full_dashboard': (cmd_full_dashboard, 'Full dashboard'),
    'honeypot': (cmd_honeypot, 'Start honeypot'),
    'agent': (cmd_agent, 'Start detection agent'),
    'help': (cmd_help, 'Show help'),
}