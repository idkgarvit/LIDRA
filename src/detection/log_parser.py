# src/detection/log_parser.py
"""Multi-source log parser for LIDRA - detects all server attack types."""

import re
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Iterator
from dataclasses import dataclass
from urllib.parse import unquote_plus

logger = logging.getLogger(__name__)


@dataclass
class LogEvent:
    """Parsed log event."""
    timestamp: datetime
    source: str
    log_type: str
    raw_line: str
    ip_address: Optional[str] = None
    username: Optional[str] = None
    port: Optional[int] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    extra: Dict = None


class LogParser:
    """Parses multiple log formats and sources."""

    # Regex patterns for different log types
    PATTERNS = {
        # SSH authentication
        'ssh_failed': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)'
        ),
        'ssh_accepted': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Accepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)'
        ),
        'ssh_invalid_user': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)'
        ),
        'ssh_connection_closed': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Connection\s+closed\s+by\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)'
        ),

        # Web server attacks (Apache/Nginx combined format)
        'web_access': re.compile(
            r'(?P<ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>\S+)\s+[^"]+"\s+(?P<status>\d+)\s+\d+\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
        ),

        # MySQL/MariaDB
        'mysql_failed': re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+[\d:]+)\s+\d+\s+\[Warning\]\s+Access\s+denied\s+for\s+user\s+\'(?P<user>\S+)\'@\'(?P<ip>[\d.]+)\'',
            re.IGNORECASE
        ),
        'mysql_failed2': re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+[\d:]+)\s+\d+\s+\[Warning\]\s+Access\s+denied\s+for\s+user\s+(?P<user>\S+)@(?P<ip>[\d.]+)',
            re.IGNORECASE
        ),

        'postgres_failed': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+postgres\[\d+\]:\s+.*FATAL:\s+password\s+authentication\s+failed\s+for\s+user\s+"(?P<user>\S+)".*\s+host=(?P<ip>[\d.]+)'
        ),

        # Postfix (SMTP)
        'postfix_sasl': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+postfix/smtpd\[\d+\]:\s+warning:\s+\S+\[(?P<ip>[\d.]+)\]:\s+SASL\s+\S+\s+authentication\s+failed'
        ),

        # Dovecot (IMAP/POP3)
        'dovecot_failed': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+dovecot:\s+auth:\s+Error:\s+Password\s+verification\s+failed\s+for\s+user\s+(?P<user>\S+):\s+.*\s+rip=(?P<ip>[\d.]+)'
        ),

        'pop3_failed': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+dovecot:\s+(?:pop3|pop3-login):\s+.*Password\s+verification\s+failed\s+for\s+user\s+(?P<user>\S+).*\s+rip=(?P<ip>[\d.]+)'
        ),

        # vsftpd/proftpd (FTP)
        'ftp_failed': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+\S+ftp[d]?\[\d+\]:\s+\S+\s+FAIL\s+Login\s+from\s+(?P<ip>[\d.]+)\s+for\s+\'(?P<user>\S+)\''
        ),

        'ftp_anonymous': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+\S+ftp[d]?\[\d+\]:\s+.*ANONYMOUS\s+LOGIN.*\s+(?P<ip>[\d.]+)'
        ),

        # MongoDB unauthorized
        'mongo_unauthorized': re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}T[\d:.]+)\s+.*\s+Authentication\s+failed.*\s+client=(?P<ip>[\d.]+)'
        ),

        # Redis unauthorized
        'redis_unauthorized': re.compile(
            r'(?P<timestamp>\d+\s+\w+\s+[\d:]+)\s+\S+\s+redis-server.*\s+Authentication\s+failed.*\s+client=(?P<ip>[\d.]+)'
        ),

        # Kubernetes audit
        'k8s_forbidden': re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}T[\d:.]+).*\s+"verb":"\S+".*"responseCode":(403|401).*\s+"sourceIPs":\["(?P<ip>[\d.]+)"\]'
        ),

        # sudo failures
        'sudo_failed': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+sudo:\s+(?P<user>\S+)\s+:\s+.*\s+COMMAND=.*\s+USER=\S+\s+TTY=\S+\s+PWD=\S+\s+WORKDIR=\S+'
        ),
        
        # sudo usage (for tracking)
        'sudo_used': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+sudo:\s+(?P<user>\S+)\s+:\s+TTY=\S+\s+PWD=\S+\s+USER=\S+\s+COMMAND=(?P<cmd>.+)'
        ),
        
        # Auth failures (generic)
        'auth_failure': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+(?:sshd|login|pam)\[\d+\]:\s+FAILED\s+(?:login|authentication)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)'
        ),
        
        # Service failures
        'service_failure': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+systemd\[\d+\]:\s+(?P<service>\S+).*failed'
        ),
        
        # Disk errors (potential ransomware)
        'disk_error': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+(?:kernel|ext4|xfs).*:\s+(?:I/O|read|write)\s+error'
        ),
        
        # Network anomalies
        'network_anomaly': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+kernel:.*:\s+.*(drop|block|reject|deny).*\s+(?P<ip>[\d.]+)'
        ),
    }

    # Attack signatures in web requests
    WEB_ATTACK_PATTERNS = {
        # OWASP Top 10
        'sql_injection': re.compile(
            r"(union[\s/*]+select|select[\s/*]+.*[\s/*]+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+table|;\s*--|'\s*--|\"\s*--|'\s*#|\"\s*#|'\s*or\s*'|\"\s*or\s*\"|'\s*and\s*'|1\s*=\s*1|1\s*=\s*2|0x[0-9a-f]+)",
            re.IGNORECASE
        ),
        'xss': re.compile(
            r"(<script|javascript:|on\w+\s*=|<iframe|<svg|<body|<img.*onerror|alert\(|eval\(|innerHTML)",
            re.IGNORECASE
        ),
        'path_traversal': re.compile(
            r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c|%252e%252e%252f|%c0%ae%c0%ae|%252e%252e/)",
            re.IGNORECASE
        ),
        'lfi_attempt': re.compile(
            r"(etc/passwd|etc/shadow|etc/group|proc/self/environ|proc/self/cmdline|proc/self/status)",
            re.IGNORECASE
        ),
        'rfi_attempt': re.compile(
            r"(php://|file://|data://|expect://|ftp://|http://|https://)",
            re.IGNORECASE
        ),
        'command_injection': re.compile(
            r"(;\s*\w+|&&\s*\w+|\|\s*\w+|`[^`]+`|\$\([^)]+\)|\|/bin/|/usr/bin/)",
            re.IGNORECASE
        ),
        
        # Advanced Web Attacks
        'ssrf_attempt': re.compile(
            r"(127\.0\.0\.1|localhost|169\.254\.169\.254|metadata\.google|metadata\.aws|internal|localhos)",
            re.IGNORECASE
        ),
        'xxe_attempt': re.compile(
            r"(<!DOCTYPE|<!ENTITY|SYSTEM|PUBLIC\s+\"-//|DATA\s+TYPE)",
            re.IGNORECASE
        ),
        'ssti_attempt': re.compile(
            r"(\{\{|\{\%|{{=|__|jinja|twig|smarty|blade)",
            re.IGNORECASE
        ),
        'deserialization': re.compile(
            r"(base64_decode|unserialize|ObjectInputStream|__destruct|__construct|pyimport)",
            re.IGNORECASE
        ),
        'ldap_injection': re.compile(
            r"(\*\)|\)\(|\(\||\*\(|\(\&\(|admin\*)",
            re.IGNORECASE
        ),
        
        # Reconnaissance
        'scanner_signature': re.compile(
            r"(nikto|nmap|sqlmap|dirbuster|gobuster|wpscan|nuclei|masscan|zgrab|burp|acunetix|netsparker|appscan)",
            re.IGNORECASE
        ),
        'admin_probe': re.compile(
            r"(/admin|/wp-admin|/wp-login|/phpmyadmin|/phpMyAdmin|/manager|/console|/solr|/actuator|/\.env|/\.git|/config\.php|/wp-config|/xmlrpc\.php|/graphql|/api)",
            re.IGNORECASE
        ),
        'sensitive_file': re.compile(
            r"(\.env|\.git/config|\.htaccess|\.DS_Store|package\.json|composer\.json|\.sql|\.bak|\.log|\.tar)",
            re.IGNORECASE
        ),
        'api_enumeration': re.compile(
            r"(/api/v|/api/|\.json|\.xml|/swagger|/openapi|/docs)",
            re.IGNORECASE
        ),
        
        # Exploit Signatures
        'shellshock': re.compile(
            r"\(\)\s*\{|\}\s*\(\)|/bin/bash|/bin/sh.*-i",
            re.IGNORECASE
        ),
        'log4j': re.compile(
            r"\$\{jndi:|\$\{lower:|\$\{env:|\$\{sys:",
            re.IGNORECASE
        ),
        'heartbleed': re.compile(
            r"\x17\x03\x03",
            re.IGNORECASE
        ),
        'eternalblue': re.compile(
            r'\x00\x00\x00\x31\xff\x53\x4d\x42|\x00\x00\x00\x63\xff\x53\x4d\x42',
            re.IGNORECASE
        ),
        'spectre_meltdown': re.compile(
            r'(spectre|meltdown|CVE-2017-5753|CVE-2017-5715|CVE-2017-5754)',
            re.IGNORECASE
        ),
        
        # Malware Indicators
        'webshell_pattern': re.compile(
            r"(eval\(|base64_decode|shell_exec|system\(|passthru|exec\(|assert\(|preg_replace.*\/e)",
            re.IGNORECASE
        ),
        'reverse_shell': re.compile(
            r"(bash\s+-i|sh\s+-i|/dev/tcp|nc\s+-e|ncat\s+-e|python.*socket|mkfifo)",
            re.IGNORECASE
        ),
        'crypto_miner': re.compile(
            r"(stratum\+tcp|xmrig|coinhive|cryptonight|monero)",
            re.IGNORECASE
        ),
    }

    def __init__(self, log_sources: List[str]):
        """Initialize parser with log sources."""
        self.log_sources = [Path(p) for p in log_sources]
        self.file_positions = {}  # Track read positions

    def parse_line(self, line: str, source: str = 'unknown') -> Optional[LogEvent]:
        """Parse a single log line."""
        line = line.strip()
        if not line:
            return None

        # Try each pattern
        for pattern_name, pattern in self.PATTERNS.items():
            match = pattern.search(line)
            if match:
                groups = match.groupdict()

                # Parse timestamp
                ts = self._parse_timestamp(groups.get('timestamp', ''))

                # Only check web attacks if the matched pattern is web-related
                if pattern_name in ('web_access',) or 'http' in str(line).lower():
                    attack_info = self._check_web_attack(line)
                    log_type = attack_info['attack_type'] if attack_info else pattern_name
                else:
                    log_type = pattern_name

                return LogEvent(
                    timestamp=ts or datetime.now(),
                    source=source,
                    log_type=log_type,
                    raw_line=line,
                    ip_address=groups.get('ip'),
                    username=groups.get('user'),
                    port=int(groups['port']) if groups.get('port') else None,
                    method=groups.get('method'),
                    path=groups.get('path'),
                    status_code=int(groups['status']) if groups.get('status') else None,
                    user_agent=groups.get('ua'),
                    extra=groups
                )

        # Check for web attacks even if not standard format
        if 'http' in line.lower() or 'get' in line.lower() or 'post' in line.lower():
            attack_info = self._check_web_attack(line)
            if attack_info:
                return LogEvent(
                    timestamp=datetime.now(),
                    source=source,
                    log_type=attack_info['attack_type'],
                    raw_line=line,
                    ip_address=attack_info.get('ip'),
                    path=attack_info.get('path'),
                    method=attack_info.get('method'),
                    extra=attack_info
                )

        return None

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse various timestamp formats."""
        t = ts_str.strip()
        try:
            if 'T' in t:
                return datetime.strptime(t[:19], '%Y-%m-%dT%H:%M:%S')
            if '/' in t:
                return datetime.strptime(t, '%d/%b/%Y:%H:%M:%S %z')
            if t[:1].isdigit() and '-' in t[:5]:
                return datetime.strptime(t, '%Y-%m-%d %H:%M:%S')
            year = datetime.now().year
            return datetime.strptime(f'{year} {t}', '%Y %b %d %H:%M:%S')
        except (ValueError, IndexError):
            pass
        return None

    def _check_web_attack(self, line: str) -> Optional[Dict]:
        """Check if line contains web attack signatures."""
        attack_type_map = {
            'sql_injection': 'web_sql_injection',
            'xss': 'web_xss_attempt',
            'path_traversal': 'web_path_traversal',
            'lfi_attempt': 'web_lfi_attempt',
            'rfi_attempt': 'web_rfi_attempt',
            'command_injection': 'web_command_injection',
            'ssrf_attempt': 'web_ssrf_attempt',
            'xxe_attempt': 'web_xxe_attempt',
            'ssti_attempt': 'web_ssti_attempt',
            'deserialization': 'web_deserialization_attack',
            'ldap_injection': 'web_ldap_injection',
            'scanner_signature': 'web_scanner_detected',
            'admin_probe': 'web_admin_probe',
            'sensitive_file': 'web_sensitive_file_access',
            'api_enumeration': 'web_api_enumeration',
            'shellshock': 'shellshock_attempt',
            'log4j': 'log4j_attempt',
            'webshell_pattern': 'webshell_upload',
            'reverse_shell': 'reverse_shell',
            'crypto_miner': 'crypto_miner',
            'heartbleed': 'heartbleed_attempt',
            'eternalblue': 'eternalblue_attempt',
            'spectre_meltdown': 'spectre_meltdown',
        }
        
        decoded = unquote_plus(line)
        for pattern_name, pattern in self.WEB_ATTACK_PATTERNS.items():
            if pattern.search(line) or pattern.search(decoded):
                attack_type = attack_type_map.get(pattern_name, pattern_name)
                web_match = self.PATTERNS['web_access'].search(line)
                return {
                    'attack_type': attack_type,
                    'ip': web_match.group('ip') if web_match else None,
                    'path': web_match.group('path') if web_match else None,
                    'method': web_match.group('method') if web_match else None,
                    'attack_signature': pattern_name,
                }
        return None

    def parse_file(self, log_path: Path) -> Iterator[LogEvent]:
        """Parse entire log file, yielding events."""
        if not log_path.exists():
            logger.warning(f"Log file not found: {log_path}")
            return

        try:
            with open(log_path, 'r', errors='ignore') as f:
                # Start from last position if tracked
                if log_path in self.file_positions:
                    f.seek(self.file_positions[log_path])

                for line in f:
                    event = self.parse_line(line, str(log_path))
                    if event:
                        yield event

                # Save position
                self.file_positions[log_path] = f.tell()

        except PermissionError:
            logger.error(f"Permission denied reading: {log_path}")
        except Exception as e:
            logger.error(f"Error reading {log_path}: {e}")

    def get_live_events(self, log_path) -> Iterator[LogEvent]:
        """Monitor log file for new events (like tail -f)."""
        import time
        from pathlib import Path

        log_path = Path(log_path)
        if not log_path.exists():
            return

        with open(log_path, 'r', errors='ignore') as f:
            f.seek(0, 2)

            while True:
                line = f.readline()
                if line:
                    event = self.parse_line(line, str(log_path))
                    if event:
                        yield event
                else:
                    time.sleep(1)
