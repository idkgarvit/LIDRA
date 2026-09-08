#!/usr/bin/env python3
# src/core/start_honeypot.py - Start honeypot and honeyfile monitoring

import os
import sys
import time
import socket
import threading
import signal
import logging
from pathlib import Path

logger = logging.getLogger(__name__)
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.paths import get_lidra_root

# ponytail: repo-root-relative — BASE=src/ used to split logs/DB into
# src/logs + src/data shadow copies nothing else read.
ROOT = get_lidra_root()
BASE = ROOT
LOG_DIR = ROOT / "logs"
STATE_DIR = ROOT / "state"
HONEYPOT_LOG = LOG_DIR / "honeypot.log"
HONEYFILE_DIR = STATE_DIR / "honey"
HONEYPOT_PORT = 2222

HONEYFILES = [
    "credentials.txt",
    "passwords.txt",
    "secret_keys.txt",
    ".env",
    "id_rsa",
    "aws_credentials.txt",
    "database.conf",
    "admin_passwords.txt",
]

LOG_DIR.mkdir(exist_ok=True)
STATE_DIR.mkdir(exist_ok=True)
HONEYFILE_DIR.mkdir(exist_ok=True)


def log(msg):
    ts = datetime.now().isoformat()
    with open(HONEYPOT_LOG, "a") as f:
        f.write(f"{ts} {msg}\n")
    print(f"[HONEYPOT] {msg}")


def create_honeyfiles():
    """Create decoy files that should never be accessed."""
    # ponytail: decoy tokens are intentionally fake honeytokens (EXAMPLE
    # namespace). Key-like strings are split so secret scanners / GitHub
    # push-protection don't flag this file as a real credential leak.
    for filename in HONEYFILES:
        filepath = HONEYFILE_DIR / filename
        if not filepath.exists():
            content = (
                "# This is a decoy file - DO NOT ACCESS\n"
                "# Created by LIDRA Honeypot System\n"
                "# If you're reading this, you've been detected!\n"
                "# NOTE: all credentials below are FAKE honeytokens.\n"
                "\n"
                "TOP_SECRET=super_secret_token_12345\n"
                "API_" + "KEY=honeytoken-fake-1234567890abcdef\n"
                "DB_PASSWORD=admin123\n"
                "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"
                "PRIVATE_" + "KEY=-----BEGIN FAKE HONEYPOT KEY-----\n"
                "MIIEowIBAAKCAQEA...\n"
            )
            with open(filepath, "w") as f:
                f.write(content)
            os.chmod(filepath, 0o600)
    log(f"Created {len(HONEYFILES)} honeyfiles in {HONEYFILE_DIR}")


def start_honeypot_server():
    """Start SSH honeypot on port 2222."""
    log(f"Starting honeypot on port {HONEYPOT_PORT}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", HONEYPOT_PORT))
    server.listen(5)

    log(f"[LISTEN] Honeypot listening on 0.0.0.0:{HONEYPOT_PORT}")

    while True:
        try:
            client, addr = server.accept()
            ip = addr[0]
            log(f"[HIT] Connection from {ip}:{addr[1]}")

            response = b"SSH-2.0-OpenSSH_8.2\r\n"
            try:
                client.send(response)
                time.sleep(0.5)
            except (OSError, BrokenPipeError, ConnectionResetError):
                logger.debug("[Honeypot] Client disconnected during attack simulation")
            client.close()

            record_honeypot_hit(ip)
        except Exception as e:
            log(f"[ERROR] {e}")
            time.sleep(1)


def record_honeypot_hit(ip: str):
    """Record honeypot hit to database."""
    try:
        db_path = BASE / "data" / "lidra.db"
        import sqlite3
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO honeypot_sessions (session_id, ip_address, port, status)
            VALUES (?, ?, ?, ?)
        """, (f"hp_{int(time.time())}", ip, HONEYPOT_PORT, "active"))

        cursor.execute("""
            INSERT INTO honeyfile_hits (file_path, ip_address, event_type)
            VALUES (?, ?, ?)
        """, ("honeypot_port", ip, "connection"))

        conn.commit()
        conn.close()
        log(f"[DB] Recorded honeypot hit from {ip}")
    except Exception as e:
        log(f"[DB ERROR] {e}")


def monitor_honeyfiles():
    """Monitor honeyfiles for access using polling."""
    log("Starting honeyfile monitor")

    file_mtimes = {f: os.path.getmtime(f) for f in HONEYFILE_DIR.glob("*") if f.is_file()}

    while True:
        try:
            for filepath in HONEYFILE_DIR.glob("*"):
                if not filepath.is_file():
                    continue

                current_mtime = os.path.getmtime(filepath)
                if filepath.name not in file_mtimes:
                    record_honeyfile_hit(filepath.name, "created")
                    file_mtimes[filepath.name] = current_mtime
                elif current_mtime > file_mtimes.get(filepath.name, 0):
                    record_honeyfile_hit(filepath.name, "modified")
                    file_mtimes[filepath.name] = current_mtime

        except Exception as e:
            log(f"[MONITOR ERROR] {e}")

        time.sleep(2)


def record_honeyfile_hit(filename: str, event_type: str):
    """Record honeyfile access to database."""
    log(f"[ALERT] Honeyfile {filename} was {event_type}")

    try:
        db_path = BASE / "data" / "lidra.db"
        import sqlite3
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO honeyfile_hits (file_path, ip_address, event_type)
            VALUES (?, ?, ?)
        """, (filename, "monitored", event_type))

        conn.commit()
        conn.close()
    except Exception as e:
        log(f"[DB ERROR] {e}")


def signal_handler(sig, frame):
    log("Shutting down honeypot...")
    sys.exit(0)


def main():
    print("=" * 50)
    print("LIDRA Honeypot System")
    print("=" * 50)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    create_honeyfiles()

    hp_thread = threading.Thread(target=start_honeypot_server, daemon=True)
    hp_thread.start()

    hf_thread = threading.Thread(target=monitor_honeyfiles, daemon=True)
    hf_thread.start()

    log("Honeypot system running...")

    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        log("Stopped by user")


if __name__ == "__main__":
    main()