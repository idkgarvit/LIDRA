#!/usr/bin/env python3
"""LIDRA CLI Dashboard - Run standalone terminal dashboard."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from database.db import LIDRADatabase
from dashboard.cli import create_cli_dashboard


def main():
    print("Starting LIDRA CLI Dashboard...")
    print()

    db_path = Path(__file__).parent / "data" / "lidra.db"
    db = LIDRADatabase(str(db_path))

    dashboard = create_cli_dashboard(db)
    dashboard.print_welcome()
    dashboard.start()

    try:
        import time
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
        dashboard.stop()


if __name__ == "__main__":
    main()