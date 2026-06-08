# src/collectors/syslog/server.py
"""
LIDRA Syslog Server
Receives and parses syslog messages from network devices.

Supports:
- UDP syslog reception (RFC 5424, RFC 3164)
- Common syslog formats (Linux, network devices)
- Attack detection from logs (auth failures, suspicious patterns)
- Integration with LIDRA detection engine
"""

import socket
import threading
import logging
import re
import os
import time
from datetime import datetime
from typing import Optional, Callable, Dict, List
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger("lidra.syslog.server")

# Syslog facilities
SYSLOG_FACILITIES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth",
    5: "syslog", 6: "lpr", 7: "news", 8: "uucp", 9: "cron",
    10: "authpriv", 11: "ftp", 12: "ntp", 13: "audit", 14: "alert"
}

# Syslog severities
SYSLOG_SEVERITIES = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "info", 7: "debug"
}

# Attack keywords in syslog
ATTACK_PATTERNS = [
    (r"Failed password|Authentication failure|Invalid user", "bruteforce"),
    (r"BREAK IN|successful logout", "intrusion"),
    (r"denied|rejected|blocked|firewall", "firewall_block"),
    (r"POSSIBLE BREAK-IN|Buffer overflow|SQL injection|XSS", "attack"),
    (r"scan|nmap|masscan|port.*探测", "port_scan"),
    (r"DDoS|distributed.*denial|flood", "dos"),
    (r"root.*login|su:|sudo:", "privilege_escalation"),
    (r"malware|trojan|ransomware|backdoor", "malware"),
    (r"unauthorized|access.*denied|forbidden", "unauthorized_access"),
    (r"kernel.*panic|out.*of.*memory|OOM", "system_compromise")
]


@dataclass
class SyslogMessage:
    """Parsed syslog message."""
    timestamp: datetime
    hostname: str
    facility: str
    severity: str
    app_name: str
    pid: Optional[str]
    message: str
    raw: str
    source_ip: str


class SyslogServer:
    """
    Syslog server for receiving logs from network devices.
    Listens on UDP port 514 by default.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 514, callback: Optional[Callable] = None, config: dict = None):
        cfg = config or {}
        collectors = cfg.get("collectors", {}).get("syslog", {})
        self.host = collectors.get("bind", host)
        self.port = collectors.get("port", port)
        self.rate_limit = collectors.get("rate_limit", 100)
        self.callback = callback
        self.config = config or {}
        self.running = False
        self.thread = None
        self.socket = None
        self._lock = threading.Lock()

        self.stats = {
            "messages_received": 0,
            "messages_parsed": 0,
            "attacks_detected": 0,
            "by_facility": defaultdict(int),
            "by_severity": defaultdict(int)
        }

        self.message_buffer = []
        self.buffer_size = 100
        self._rate_windows: Dict[str, List[float]] = {}

    def start(self):
        """Start syslog server."""
        if self.running:
            logger.warning("Syslog server already running")
            return

        logger.info(f"Starting syslog server on {self.host}:{self.port}")

        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.settimeout(1.0)
        except Exception as e:
            logger.error(f"Failed to bind syslog socket: {e}")
            return

        self.running = True
        self.thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.thread.start()
        logger.info(f"Syslog server listening on {self.host}:{self.port}")

    def stop(self):
        """Stop syslog server."""
        self.running = False
        if self.socket:
            self.socket.close()
        if self.thread:
            self.thread.join(timeout=2)
        logger.info(f"Syslog server stopped. Stats: {self.stats}")

    def _rate_limited(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            times = self._rate_windows.get(ip, [])
            times = [t for t in times if now - t < 1.0]
            if len(times) >= self.rate_limit:
                return True
            times.append(now)
            self._rate_windows[ip] = times

    def _receive_loop(self):
        """Main receive loop."""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(4096)
                if data:
                    src_ip = addr[0]
                    if self._rate_limited(src_ip):
                        continue
                    with self._lock:
                        self.stats["messages_received"] += 1
                    msg = self._parse_message(data.decode('utf-8', errors='ignore'), src_ip)
                    if msg:
                        with self._lock:
                            self.stats["messages_parsed"] += 1
                            self.stats["by_facility"][msg.facility] += 1
                            self.stats["by_severity"][msg.severity] += 1

                        attack = self._analyze_message(msg)
                        if attack:
                            with self._lock:
                                self.stats["attacks_detected"] += 1
                            if self.callback:
                                self.callback(attack)
                        elif self.callback:
                            self.callback({"type": "log", "message": msg})

            except socket.timeout:
                continue
            except Exception as e:
                logger.debug(f"Syslog receive error: {e}")

    def _parse_message(self, raw: str, source_ip: str) -> Optional[SyslogMessage]:
        """Parse syslog message."""
        try:
            # Try RFC 5424 format first
            if raw.startswith("<"):
                msg = self._parse_rfc5424(raw)
            else:
                # Fall back to RFC 3164 (BSD style)
                msg = self._parse_rfc3164(raw)

            if msg:
                msg.source_ip = source_ip
                msg.raw = raw
            return msg

        except Exception as e:
            logger.debug(f"Parse error: {e}")
            return None

    def _parse_rfc5424(self, raw: str) -> Optional[SyslogMessage]:
        """Parse RFC 5424 syslog format."""
        try:
            match = re.match(r'<(\d+)>(\d+) (\S+) (\S+) (\S+) (\S+) (\S+) (.*)', raw)
            if not match:
                return self._parse_rfc3164(raw)

            pri, version, timestamp, hostname, app, pid, msgid, structured = match.groups()

            facility = int(pri) >> 3
            severity = int(pri) & 7

            return SyslogMessage(
                timestamp=datetime.now(),
                hostname=hostname,
                facility=SYSLOG_FACILITIES.get(facility, f"local{facility}"),
                severity=SYSLOG_SEVERITIES.get(severity, "unknown"),
                app_name=app,
                pid=pid if pid != "-" else None,
                message=msgid + " " + structured,
                source_ip=""
            )
        except (ValueError, AttributeError):
            return self._parse_rfc3164(raw)

    def _parse_rfc3164(self, raw: str) -> Optional[SyslogMessage]:
        """Parse RFC 3164 (BSD) syslog format."""
        try:
            # Example: "Jan  1 12:00:00 hostname app[pid]: message"
            match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)', raw)
            if not match:
                return None

            timestamp_str, hostname, app, pid, message = match.groups()

            # Assume current year
            year = datetime.now().year
            try:
                timestamp = datetime.strptime(f"{year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            except ValueError:
                timestamp = datetime.now()

            return SyslogMessage(
                timestamp=timestamp,
                hostname=hostname,
                facility="user",
                severity="info",
                app_name=app,
                pid=pid,
                message=message,
                source_ip=""
            )
        except (ValueError, AttributeError, IndexError):
            return None

    def _analyze_message(self, msg: SyslogMessage) -> Optional[Dict]:
        """Analyze syslog message for attack patterns."""
        message_lower = msg.message.lower()

        for pattern, attack_type in ATTACK_PATTERNS:
            if re.search(pattern, message_lower, re.IGNORECASE):
                severity = "high"
                if attack_type in ["bruteforce", "intrusion", "malware"]:
                    severity = "critical"

                return {
                    "attack_type": f"syslog_{attack_type}",
                    "severity": severity,
                    "source_ip": msg.source_ip,
                    "hostname": msg.hostname,
                    "app": msg.app_name,
                    "message": msg.message,
                    "raw": msg.raw,
                    "source": "syslog"
                }

        # Check for high severity
        if msg.severity in ["emergency", "alert", "critical"]:
            return {
                "attack_type": "syslog_critical",
                "severity": "high",
                "source_ip": msg.source_ip,
                "hostname": msg.hostname,
                "message": msg.message,
                "source": "syslog"
            }

        return None

    def get_stats(self) -> Dict:
        """Get syslog server statistics."""
        with self._lock:
            stats = self.stats.copy()
            stats["by_facility"] = dict(self.stats["by_facility"])
            stats["by_severity"] = dict(self.stats["by_severity"])
        return stats


def create_syslog_server(host: str = "127.0.0.1", port: int = 514, callback: Optional[Callable] = None, config: dict = None) -> SyslogServer:
    """Factory function to create syslog server."""
    return SyslogServer(host=host, port=port, callback=callback, config=config)


# Standalone test
if __name__ == "__main__":
    print("LIDRA Syslog Server")
    print("=" * 40)

    def on_event(event):
        if "attack_type" in event:
            print(f"[ALERT] {event['attack_type']} from {event.get('source_ip', 'unknown')}")
        else:
            print(f"[LOG] {event.get('message', {}).message[:80]}")

    server = create_syslog_server(callback=on_event)
    server.start()

    try:
        while True:
            import time
            time.sleep(10)
            stats = server.get_stats()
            print(f"Messages: {stats['messages_received']}, Attacks: {stats['attacks_detected']}")
    except KeyboardInterrupt:
        server.stop()
        print("Stopped")