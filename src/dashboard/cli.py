# src/dashboard/cli.py
"""LIDRA v3 CLI Dashboard - Rich terminal interface."""

import time
import threading
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich import box
import psutil


console = Console()


class CLIDashboard:
    def __init__(self, db):
        self.db = db
        self.running = False
        self._thread = None
        self._last_stats = {}
        self._lock = threading.Lock()

    def start(self):
        """Start the CLI dashboard in background thread."""
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._run_dashboard, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the CLI dashboard."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)

    def update_stats(self, stats: dict):
        """Update stats from external source (called by agent)."""
        with self._lock:
            self._last_stats = stats

    def _get_stats(self):
        """Fetch current stats from database."""
        stats = self.db.get_attacker_stats()

        try:
            cpu = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            network = psutil.net_io_counters()
            disk = psutil.disk_usage('/')
        except:
            cpu = memory = network = disk = None

        conn = self.db._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM attacks
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT 10
        """)
        attack_types = cursor.fetchall()

        cursor.execute("""
            SELECT a.attack_type, at.ip_address, at.country, at.org, a.timestamp
            FROM attacks a
            JOIN attackers at ON a.attacker_id = at.id
            ORDER BY a.timestamp DESC
            LIMIT 10
        """)
        recent_attacks = cursor.fetchall()

        cursor.execute("""
            SELECT ip_address, reason, block_until
            FROM blocks
            WHERE block_until > datetime('now')
            ORDER BY created_at DESC
            LIMIT 10
        """)
        active_blocks = cursor.fetchall()

        cursor.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM attacks
            WHERE attack_type IN ('honeypot_connection', 'honeyfile_access')
            GROUP BY attack_type
        """)
        honeypot_hits = cursor.fetchall()

        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE created_at > datetime('now', '-1 hour')
            GROUP BY severity
        """)
        severity_breakdown = cursor.fetchall()

        # Get MITRE data
        try:
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from detection.mitre import MITREMapper
            mitre_mapper = MITREMapper()
            mitre_report = mitre_mapper.get_coverage_report()
            mitre_data = {
                "techniques": mitre_report.get("total_techniques", 0),
                "tactics": mitre_report.get("total_tactics", 0),
                "coverage": mitre_report.get("coverage_percentage", 0),
            }
        except:
            mitre_data = {"techniques": 0, "tactics": 0, "coverage": 0}

        return {
            "stats": stats,
            "system": {
                "cpu": cpu,
                "memory": memory,
                "network": network,
                "disk": disk,
            },
            "attack_types": attack_types,
            "recent_attacks": recent_attacks,
            "active_blocks": active_blocks,
            "honeypot_hits": honeypot_hits,
            "severity_breakdown": severity_breakdown,
            "mitre": mitre_data,
        }

    def _format_uptime(self, seconds):
        """Format uptime in human readable form."""
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"

    def _render(self):
        """Render the dashboard."""
        data = self._get_stats()
        stats = data.get("stats", {})
        system = data.get("system", {})

        cpu = system.get("cpu", 0)
        memory = system.get("memory")
        network = system.get("network")
        disk = system.get("disk")

        lines = []

        title = Text("LIDRA v3 - Advanced Detection System", style="bold cyan")
        title.append(" | ", style="dim")
        title.append("eBPF-Powered Security Monitor", style="dim green")
        lines.append(Panel(title, box=box.DOUBLE))

        metrics_table = Table(box=box.SIMPLE)
        metrics_table.add_column("Metric", style="cyan", width=20)
        metrics_table.add_column("Value", style="white")

        metrics_table.add_row("Attackers", str(stats.get("total_attackers", 0)))
        metrics_table.add_row("Attacks (24h)", f"[orange]{stats.get('attacks_24h', 0)}[/]")
        metrics_table.add_row("Active Blocks", str(len(data.get("active_blocks", []))))
        metrics_table.add_row("CPU", f"{cpu:.1f}%")
        if memory:
            metrics_table.add_row("Memory", f"{memory.percent:.1f}%")
        if disk:
            metrics_table.add_row("Disk", f"{disk.percent:.1f}%")
        if network:
            rx_mb = network.bytes_recv / 1024 / 1024
            tx_mb = network.bytes_sent / 1024 / 1024
            metrics_table.add_row("Network", f"↓{rx_mb:.1f}MB ↑{tx_mb:.1f}MB")

        lines.append(Panel(metrics_table, title="[cyan]System Metrics[/]", box=box.SIMPLE))

        if data.get("attack_types"):
            attack_table = Table(box=box.SIMPLE)
            attack_table.add_column("Attack Type", style="red", width=30)
            attack_table.add_column("Count", style="yellow", width=10)
            for at, count in data["attack_types"]:
                severity_style = self._get_severity_style(at)
                attack_table.add_row(
                    Text(at, style=severity_style),
                    str(count)
                )
            lines.append(Panel(attack_table, title="[red]Attack Types[/]", box=box.SIMPLE))

        if data.get("recent_attacks"):
            recent_table = Table(box=box.SIMPLE)
            recent_table.add_column("IP Address", style="orange", width=20)
            recent_table.add_column("Type", style="red", width=25)
            recent_table.add_column("Country", style="blue", width=10)
            recent_table.add_column("Time", style="dim", width=10)
            for at_type, ip, country, org, ts in data["recent_attacks"][:7]:
                time_str = str(ts)[-8:] if ts else ""
                recent_table.add_row(ip or "unknown", at_type, country or "-", time_str)
            lines.append(Panel(recent_table, title="[orange]Recent Attacks[/]", box=box.SIMPLE))

        if data.get("honeypot_hits"):
            hp_table = Table(box=box.SIMPLE)
            hp_table.add_column("Deception Type", style="magenta", width=25)
            hp_table.add_column("Count", style="yellow", width=10)
            for at, count in data["honeypot_hits"]:
                hp_table.add_row(at, str(count))
            lines.append(Panel(hp_table, title="[magenta]Honeypot/Honeyfile[/]", box=box.SIMPLE))

        if data.get("active_blocks"):
            blocks_table = Table(box=box.SIMPLE)
            blocks_table.add_column("IP Address", style="red", width=20)
            blocks_table.add_column("Reason", style="yellow", width=30)
            blocks_table.add_column("Until", style="dim", width=15)
            for ip, reason, until in data["active_blocks"][:5]:
                until_str = str(until)[:16] if until else ""
                blocks_table.add_row(ip, reason[:28], until_str)
            lines.append(Panel(blocks_table, title="[red]Active Blocks[/]", box=box.SIMPLE))

        if data.get("severity_breakdown"):
            sev_table = Table(box=box.SIMPLE)
            sev_table.add_column("Severity", style="white", width=15)
            sev_table.add_column("Count (1h)", style="yellow", width=15)
            for sev, count in data["severity_breakdown"]:
                sev_style = self._get_severity_style(sev)
                sev_table.add_row(Text(sev.upper(), style=sev_style), str(count))
            lines.append(Panel(sev_table, title="[yellow]Alert Severity[/]", box=box.SIMPLE))

        # MITRE Coverage
        mitre = data.get("mitre", {})
        if mitre.get("techniques"):
            lines.append(Panel(
                f"[cyan]Techniques:[/cyan] {mitre.get('techniques', 0)}  |  "
                f"[orange]Tactics:[/orange] {mitre.get('tactics', 0)}  |  "
                f"[green]Coverage:[/green] {mitre.get('coverage', 0)}%",
                title="[bold]MITRE ATT&CK[/bold]",
                box=box.SIMPLE
            ))

        return Layout(
            Panel(
                "\n".join([str(line) for line in lines]),
                padding=0
            )
        )

    def _get_severity_style(self, name):
        """Get color style based on severity or attack type."""
        name_lower = str(name).lower()
        if "critical" in name_lower:
            return "bold red"
        elif "high" in name_lower:
            return "red"
        elif "medium" in name_lower:
            return "yellow"
        elif "low" in name_lower:
            return "green"
        elif "honeypot" in name_lower or "honeyfile" in name_lower:
            return "magenta"
        elif "sql" in name_lower or "injection" in name_lower:
            return "bold red"
        elif "xss" in name_lower:
            return "orange"
        return "white"

    def _run_dashboard(self):
        """Run the dashboard in live mode."""
        with Live(screen=True, refresh_per_second=2) as live:
            while self.running:
                try:
                    renderable = self._render()
                    live.update(renderable)
                except Exception as e:
                    pass
                time.sleep(0.5)

    def print_welcome(self):
        """Print welcome message with stats."""
        console.clear()
        console.print(Panel(
            "[bold cyan]LIDRA v3[/bold cyan] - [green]eBPF-Powered Detection System[/green]\n"
            "[dim]Advanced intrusion detection with real-time monitoring[/dim]",
            box=box.DOUBLE
        ))

    def print_dashboard(self):
        """Print dashboard once (works without TTY)."""
        try:
            # Get all data
            data = self._get_stats()
            stats = data.get("stats", {})
            system = data.get("system", {})
            mitre = data.get("mitre", {})

            console.print("\n" + "="*60)
            console.print("  LIDRA v3 - SECURITY DASHBOARD")
            console.print("="*60 + "\n")

            # System Stats
            cpu = system.get("cpu", 0)
            memory = system.get("memory")
            disk = system.get("disk")

            console.print("[cyan]SYSTEM METRICS[cyan]")
            console.print(f"  Attackers: {stats.get('total_attackers', 0)}")
            console.print(f"  Attacks (24h): {stats.get('attacks_24h', 0)}")
            console.print(f"  Active Blocks: {len(data.get('active_blocks', []))}")
            console.print(f"  CPU: {cpu:.1f}%")
            if memory:
                console.print(f"  Memory: {memory.percent:.1f}%")
            if disk:
                console.print(f"  Disk: {disk.percent:.1f}%")
            console.print("")

            # Attack Types
            if data.get("attack_types"):
                console.print("[red]ATTACK TYPES[red]")
                for at, count in data["attack_types"][:8]:
                    console.print(f"  {at}: {count}")
                console.print("")

            # Honeypot
            if data.get("honeypot_hits"):
                console.print("[magenta]HONEYPOT/HONEYFILE[magenta]")
                for at, count in data["honeypot_hits"]:
                    console.print(f"  {at}: {count}")
                console.print("")

            # Blocks
            if data.get("active_blocks"):
                console.print("[red]ACTIVE BLOCKS[red]")
                for ip, reason, until in data["active_blocks"][:5]:
                    console.print(f"  {ip} - {reason[:30]}")
                console.print("")

            # MITRE
            if mitre.get("techniques"):
                console.print("[yellow]MITRE ATT&CK[yellow]")
                console.print(f"  Techniques: {mitre.get('techniques', 0)}")
                console.print(f"  Tactics: {mitre.get('tactics', 0)}")
                console.print(f"  Coverage: {mitre.get('coverage', 0)}%")
                console.print("")

            console.print("="*60)
            console.print("  Run 'lidra dashboard live' for live dashboard")
            console.print("  Run 'lidra web' for web dashboard")
            console.print("="*60 + "\n")

        except Exception as e:
            console.print(f"[red]Error displaying dashboard: {e}[/red]")
            console.print("[yellow]Try: lidra status[/yellow]")

    def print_status(self):
        """Print current status summary."""
        data = self._get_stats()
        stats = data.get("stats", {})

        console.print(f"\n[cyan]Status:[/cyan] Running")
        console.print(f"[cyan]Total Attackers:[/cyan] {stats.get('total_attackers', 0)}")
        console.print(f"[cyan]Attacks (24h):[/cyan] {stats.get('attacks_24h', 0)}")
        console.print(f"[cyan]Active Blocks:[/cyan] {len(data.get('active_blocks', []))}")

        if data.get("honeypot_hits"):
            console.print(f"[magenta]Honeypot Hits:[/magenta] {sum(c for _, c in data['honeypot_hits'])}")


def create_cli_dashboard(db) -> CLIDashboard:
    """Factory function to create CLI dashboard."""
    return CLIDashboard(db)