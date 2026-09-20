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
readline.parse_and_bind("tab: complete")  # arrow-history + tab completion for input()

from .commands import COMMANDS

# Single source of truth: utils/version.py. Displayed in the banner title and
# the --help description; the fixed-width ASCII box deliberately carries no
# version, so a release cannot misalign it.
try:
    from utils.version import version_string as _version_string
    VERSION: str = _version_string()
except Exception:  # pragma: no cover - CLI can load without src/ on sys.path
    VERSION = "v0.0.0"

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
║                      LIDRA - Security CLI                     ║
║            Advanced Intrusion Detection System                ║
╚═══════════════════════════════════════════════════════════════╝

Type 'help' for available commands, 'exit' to quit
"""
        console.print(Panel(
            Text(banner, style="cyan"),
            border_style="cyan",
            title=f"[bold green]LIDRA {VERSION}[/bold green]",
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
        description=f'LIDRA {VERSION} - Advanced Intrusion Detection System',
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

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Log all detections, never block'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable DEBUG-level logging'
    )

    parser.add_argument(
        '--interface', '-i',
        type=str,
        default=None,
        help='Override auto-detected network interface'
    )

    args = parser.parse_args()

    if args.dry_run:
        os.environ["LIDRA_DRY_RUN"] = "1"
    if args.verbose:
        os.environ["LIDRA_LOG_LEVEL"] = "DEBUG"
    if args.interface:
        os.environ["LIDRA_INTERFACE"] = args.interface

    if args.help:
        console.print(Panel("""
[bold]LIDRA - Security CLI[/bold]

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
  web           - Alias for dashboard (terminal UI)
  block <ip>    - Block an IP
  unblock <ip>  - Unblock an IP

[cyan]Examples:[/cyan]
  lidra              - Full live dashboard (DEFAULT)
  lidra status       - Quick status
  lidra web          - Alias for the terminal dashboard
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