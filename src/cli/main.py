# src/cli/main.py
"""LIDRA CLI Main - Interactive shell and entry point."""

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import argparse
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import readline

from .commands import COMMANDS

console = Console()


class LIDRACli:
    """LIDRA Interactive CLI."""

    def __init__(self):
        self.running = True
        self.prompt = " lidra > "

    def print_banner(self):
        """Print CLI banner."""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                     LIDRA v3 - Security CLI                   ║
║            Advanced Intrusion Detection System                ║
╚═══════════════════════════════════════════════════════════════╝

Type 'help' for available commands, 'exit' to quit
"""
        console.print(Panel(
            Text(banner, style="cyan"),
            border_style="cyan",
            title="[bold green]LIDRA v3[/bold green]",
            subtitle="[dim]Type 'help' for commands[/dim]"
        ))

    def parse_input(self, line: str):
        """Parse user input into command and args."""
        parts = line.strip().split()
        if not parts:
            return None, []

        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []

        return cmd, args

    def run_command(self, cmd: str, args: list) -> bool:
        """Run a command."""
        if cmd == 'exit' or cmd == 'quit':
            console.print("[yellow]Goodbye![/yellow]")
            return False

        if cmd == 'clear':
            os.system('clear' if os.name == 'posix' else 'cls')
            return True

        if cmd not in COMMANDS:
            console.print(f"[red]Unknown command: {cmd}[/red]")
            console.print("[dim]Type 'help' for available commands[/dim]")
            return True

        func, _ = COMMANDS[cmd]
        try:
            result = func(args)
            return result if result is not None else True
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return True

    def interactive_loop(self):
        """Main interactive loop."""
        self.print_banner()

        while self.running:
            try:
                line = input(self.prompt)
                if not line.strip():
                    continue

                cmd, args = self.parse_input(line)

                if cmd is None:
                    continue

                if cmd in ['exit', 'quit']:
                    self.running = False
                    console.print("[yellow]Goodbye![/yellow]")
                    break

                if not self.run_command(cmd, args):
                    self.running = False
                    break

            except KeyboardInterrupt:
                console.print("\n[yellow]Use 'exit' to quit[/yellow]")
            except EOFError:
                console.print("\n[yellow]Goodbye![/yellow]")
                break
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

    def run_single(self, cmd: str, args: list):
        """Run single command and exit."""
        if cmd in ['help', '--help', '-h']:
            func, _ = COMMANDS['help']
            func([])
            return

        if cmd == 'interactive':
            self.interactive_loop()
            return

        if cmd not in COMMANDS:
            console.print(f"[red]Unknown command: {cmd}[/red]")
            console.print("[dim]Use 'lidra --help' for help[/dim]")
            sys.exit(1)

        func, _ = COMMANDS[cmd]
        try:
            result = func(args)
            sys.exit(0 if result else 1)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            sys.exit(1)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog='lidra',
        description='LIDRA v3 - Advanced Intrusion Detection System',
        add_help=False
    )

    parser.add_argument(
        'command',
        nargs='?',
        default='full_dashboard',
        help='Command to run (default: full dashboard)'
    )

    parser.add_argument(
        'args',
        nargs='*',
        help='Arguments for the command'
    )

    parser.add_argument(
        '--help', '-h',
        action='store_true',
        help='Show this help'
    )

    args = parser.parse_args()

    if args.help and args.command == 'dashboard':
        console.print(Panel("""
[bold]LIDRA v3 - Security CLI[/bold]

[cyan]Usage:[/cyan]
  lidra [command] [arguments]

[cyan]Commands:[/cyan]
  lidra         - Full live dashboard (all stats)
  dashboard     - Terminal dashboard (live stats)
  agent         - Run detection agent
  honeypot      - Start honeypot service
  status        - Quick system status
  alerts        - Show recent alerts
  blocks        - Show active blocks
  mitre         - Show MITRE coverage
  web           - Show web dashboard URL
  block <ip>    - Block an IP
  unblock <ip>  - Unblock an IP

[cyan]Examples:[/cyan]
  lidra              - Full live dashboard (DEFAULT)
  lidra status       - Quick status
  lidra web          - Show web dashboard
  lidra block 1.2.3.4 - Block IP

[dim]Run 'lidra' for full live dashboard[/dim]
""", title="LIDRA Help"))
        return

    cli = LIDRACli()

    if args.command == 'interactive':
        cli.interactive_loop()
    else:
        cli.run_single(args.command, args.args)


if __name__ == '__main__':
    main()