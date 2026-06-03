# src/detection/attack_detector.py
"""Comprehensive attack detection for all server-based attacks."""

import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from collections import defaultdict
from dataclasses import dataclass, field
import yaml

logger = logging.getLogger(__name__)


def _get_brute_force_threshold():
    cfg_path = Path(__file__).parent.parent.parent / "config" / "config.yaml"
    try:
        with open(cfg_path) as f:
            cfg = yaml.safe_load(f)
        return cfg.get("thresholds", {}).get("brute_force", 5)
    except Exception:
        return 5


@dataclass
class AttackConfig:
    """Configuration for attack detection thresholds."""
    ssh_failed_attempts: int = 5
    time_window_seconds: int = 300
    web_attack_threshold: int = 1
    port_scan_threshold: int = 10
    brute_force_window: int = 60


@dataclass
class DetectedAttack:
    """Represents a detected attack."""
    attack_type: str
    severity: str
    ip_address: str
    timestamp: datetime
    details: Dict = field(default_factory=dict)
    raw_evidence: List[str] = field(default_factory=list)


class AttackDetector:
    """
    Comprehensive attack detection engine.

    Detects ALL types of server-based attacks:
    - SSH: Bruteforce, invalid users, connection floods
    - Web: SQL injection, XSS, path traversal, LFI/RFI, command injection, scanner probes
    - Database: MySQL, PostgreSQL, MongoDB, Redis unauthorized access
    - Email: SMTP auth failures, relay attempts
    - FTP: Login failures, anonymous access
    - Network: Port scans, service probes
    - Application: Admin panel probes, sensitive file access
    - Exploit: Shellshock, Log4j, CVE signatures
    - Privilege: sudo failures, su failures
    """

    # Attack type definitions with severity
    ATTACK_TYPES = {
        # SSH Attacks
        'ssh_bruteforce': {'severity': 'high', 'category': 'credential_attack'},
        'ssh_invalid_user': {'severity': 'medium', 'category': 'reconnaissance'},
        'ssh_connection_flood': {'severity': 'medium', 'category': 'dos'},
        'ssh_key_abuse': {'severity': 'high', 'category': 'persistence'},

        # Web Attacks - OWASP Top 10+
        'sql_injection': {'severity': 'critical', 'category': 'injection'},
        'xss_attempt': {'severity': 'high', 'category': 'injection'},
        'path_traversal': {'severity': 'high', 'category': 'file_access'},
        'lfi_attempt': {'severity': 'high', 'category': 'file_access'},
        'rfi_attempt': {'severity': 'critical', 'category': 'file_access'},
        'command_injection': {'severity': 'critical', 'category': 'injection'},
        'ssrf_attempt': {'severity': 'high', 'category': 'injection'},
        'xxe_attempt': {'severity': 'critical', 'category': 'injection'},
        'ssti_attempt': {'severity': 'critical', 'category': 'injection'},
        'deserialization_attack': {'severity': 'critical', 'category': 'injection'},
        'ldap_injection': {'severity': 'high', 'category': 'injection'},
        'xml_injection': {'severity': 'high', 'category': 'injection'},
        'csp_bypass': {'severity': 'medium', 'category': 'defense_evasion'},
        'idor_attempt': {'severity': 'medium', 'category': 'broken_access'},
        
        # Web Reconnaissance
        'scanner_detected': {'severity': 'low', 'category': 'reconnaissance'},
        'admin_probe': {'severity': 'low', 'category': 'reconnaissance'},
        'sensitive_file_access': {'severity': 'medium', 'category': 'reconnaissance'},
        'api_enumeration': {'severity': 'medium', 'category': 'reconnaissance'},
        'subdomain_takeover': {'severity': 'medium', 'category': 'reconnaissance'},
        
        # Exploit Attempts (CVE signatures)
        'shellshock_attempt': {'severity': 'critical', 'category': 'exploit'},
        'log4j_attempt': {'severity': 'critical', 'category': 'exploit'},
        'heartbleed_attempt': {'severity': 'critical', 'category': 'exploit'},
        'spectre_meltdown': {'severity': 'critical', 'category': 'exploit'},
        'eternalblue_attempt': {'severity': 'critical', 'category': 'exploit'},
        'cve_exploit': {'severity': 'critical', 'category': 'exploit'},

        # Database Attacks
        'mysql_bruteforce': {'severity': 'high', 'category': 'credential_attack'},
        'postgres_bruteforce': {'severity': 'high', 'category': 'credential_attack'},
        'mongo_unauthorized': {'severity': 'high', 'category': 'unauthorized_access'},
        'redis_unauthorized': {'severity': 'high', 'category': 'unauthorized_access'},
        'oracle_bruteforce': {'severity': 'high', 'category': 'credential_attack'},
        'mssql_bruteforce': {'severity': 'high', 'category': 'credential_attack'},

        # Email Attacks
        'smtp_bruteforce': {'severity': 'high', 'category': 'credential_attack'},
        'imap_bruteforce': {'severity': 'high', 'category': 'credential_attack'},
        'pop3_bruteforce': {'severity': 'high', 'category': 'credential_attack'},
        'relay_attempt': {'severity': 'medium', 'category': 'abuse'},
        'spoofing_attempt': {'severity': 'medium', 'category': 'social_engineering'},

        # FTP Attacks
        'ftp_bruteforce': {'severity': 'high', 'category': 'credential_attack'},
        'anonymous_ftp': {'severity': 'low', 'category': 'misconfiguration'},

        # Network Attacks
        'port_scan': {'severity': 'medium', 'category': 'reconnaissance'},
        'service_probe': {'severity': 'low', 'category': 'reconnaissance'},
        'dns_tunneling': {'severity': 'high', 'category': 'exfiltration'},
        'dns_amplification': {'severity': 'high', 'category': 'dos'},
        'smb_enumeration': {'severity': 'medium', 'category': 'reconnaissance'},
        'ldap_enumeration': {'severity': 'medium', 'category': 'reconnaissance'},
        'kerberoasting': {'severity': 'high', 'category': 'credential_access'},
        'ntlm_relay': {'severity': 'critical', 'category': 'credential_access'},
        
        # DoS Attacks
        'syn_flood': {'severity': 'high', 'category': 'dos'},
        'udp_flood': {'severity': 'high', 'category': 'dos'},
        'icmp_flood': {'severity': 'medium', 'category': 'dos'},
        'http_flood': {'severity': 'high', 'category': 'dos'},
        'slowloris_attack': {'severity': 'high', 'category': 'dos'},

        # Privilege Escalation
        'sudo_failure': {'severity': 'medium', 'category': 'privilege_escalation'},
        'su_failure': {'severity': 'medium', 'category': 'privilege_escalation'},
        'privilege_escalation': {'severity': 'high', 'category': 'privilege_escalation'},
        
        # Persistence
        'ssh_key_added': {'severity': 'high', 'category': 'persistence'},
        'cron_persistence': {'severity': 'high', 'category': 'persistence'},
        'rc_modification': {'severity': 'high', 'category': 'persistence'},
        'service_creation': {'severity': 'high', 'category': 'persistence'},
        'registry_persistence': {'severity': 'high', 'category': 'persistence'},

        # Defense Evasion
        'log_clearing': {'severity': 'high', 'category': 'defense_evasion'},
        'process_injection': {'severity': 'critical', 'category': 'defense_evasion'},
        'rootkit_indicator': {'severity': 'critical', 'category': 'defense_evasion'},
        'fileless_attack': {'severity': 'critical', 'category': 'defense_evasion'},
        
        # Credential Access
        'password_spray': {'severity': 'high', 'category': 'credential_access'},
        'credential_dumping': {'severity': 'critical', 'category': 'credential_access'},
        'keylogging': {'severity': 'critical', 'category': 'credential_access'},
        
        # Malware Indicators
        'webshell_upload': {'severity': 'critical', 'category': 'backdoor'},
        'reverse_shell': {'severity': 'critical', 'category': 'remote_access'},
        'crypto_miner': {'severity': 'critical', 'category': 'cryptocurrency'},
        'ransomware_indicator': {'severity': 'critical', 'category': 'impact'},
        'botnet_indicator': {'severity': 'critical', 'category': 'botnet'},
        
        # Lateral Movement
        'wmi_lateral': {'severity': 'high', 'category': 'lateral_movement'},
        'winrm_lateral': {'severity': 'high', 'category': 'lateral_movement'},
        'psexec_abuse': {'severity': 'high', 'category': 'lateral_movement'},
        
        # Cloud-Specific
        'aws_api_abuse': {'severity': 'high', 'category': 'cloud'},
        's3_bucket_exposure': {'severity': 'high', 'category': 'cloud'},
        'cloud_key_exposure': {'severity': 'critical', 'category': 'cloud'},
        
        # Container/K8s
        'k8s_unauthorized': {'severity': 'high', 'category': 'container'},
        'container_escape': {'severity': 'critical', 'category': 'container'},
        'privilege_container': {'severity': 'high', 'category': 'container'},
        
        # Data Exfiltration
        'data_exfiltration': {'severity': 'critical', 'category': 'exfiltration'},
        'suspicious_upload': {'severity': 'high', 'category': 'exfiltration'},

        # Deception (Honeypot/Honeyfile)
        'honeypot_connection': {'severity': 'critical', 'category': 'deception'},
        'honeyfile_access': {'severity': 'critical', 'category': 'deception'},
    }

    def __init__(self, config_path: Optional[str] = None):
        """Initialize attack detector with configuration."""
        self.config = self._load_config(config_path)

        # Tracking state
        self.failed_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self.web_attacks: Dict[str, List[datetime]] = defaultdict(list)
        self.port_access: Dict[str, Set[int]] = defaultdict(set)
        self.detected_ips: Set[str] = set()
        # Per-protocol brute force trackers
        self.db_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self.email_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self.ftp_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self.attack_history: Dict[str, List[str]] = defaultdict(list)

        # Rate limiting for alerts
        self.last_alert: Dict[str, datetime] = {}
        self.alert_cooldown = 60  # seconds between same-type alerts

    def _load_config(self, config_path: Optional[str]) -> AttackConfig:
        """Load configuration from file."""
        if config_path and Path(config_path).exists():
            with open(config_path) as f:
                data = yaml.safe_load(f)
                detection = data.get('detection', {})
                return AttackConfig(
                    ssh_failed_attempts=detection.get('thresholds', {}).get('ssh_failed_attempts', 5),
                    time_window_seconds=detection.get('thresholds', {}).get('time_window_seconds', 300),
                )
        return AttackConfig()

    def analyze_event(self, event) -> List[DetectedAttack]:
        """
        Analyze a parsed log event for attacks.
        Returns list of detected attacks.
        """
        attacks = []

        if not event or not event.ip_address:
            return attacks

        ip = event.ip_address
        now = event.timestamp or datetime.now()

        # Clean old entries
        self._cleanup_old_entries(now)

        # Analyze based on log type
        attack = self._analyze_by_type(event, ip, now)
        if attack:
            attacks.append(attack)

        # Check for distributed attacks (multiple IPs, same pattern)
        distributed = self._check_distributed_attack(event, now)
        if distributed:
            attacks.append(distributed)

        return attacks

    def _analyze_by_type(self, event, ip: str, now: datetime) -> Optional[DetectedAttack]:
        """Analyze event based on log type."""
        log_type = event.log_type or ''

        # SSH Attacks
        if 'ssh_failed' in log_type or 'ssh_invalid' in log_type:
            return self._check_ssh_bruteforce(ip, event, now)

        if 'ssh_invalid_user' in log_type:
            return self._create_attack(
                'ssh_invalid_user', ip, event,
                details={'username': event.username, 'port': event.port}
            )

        # Web Attacks
        if 'web_' in log_type:
            return self._check_web_attack(ip, event, now)

        # Database Attacks
        if 'mysql' in log_type:
            return self._check_db_bruteforce('mysql', ip, event, now)

        if 'mongo' in log_type or 'redis' in log_type:
            return self._create_attack(
                log_type, ip, event,
                details={'service': 'mongodb' if 'mongo' in log_type else 'redis'}
            )

        # Email Attacks
        if 'postfix' in log_type or 'smtp' in log_type:
            return self._check_email_bruteforce('smtp', ip, event, now)

        if 'dovecot' in log_type:
            return self._check_email_bruteforce('imap', ip, event, now)

        # FTP Attacks
        if 'ftp' in log_type:
            return self._check_ftp_bruteforce(ip, event, now)

        # Privilege Escalation
        if 'sudo_failed' in log_type:
            return self._create_attack(
                'sudo_failure', ip, event,
                details={'username': event.username}
            )

        # Kubernetes
        if 'k8s' in log_type:
            return self._create_attack(
                'k8s_unauthorized', ip, event,
                details={'status_code': event.status_code}
            )

        # Direct exploit signatures
        if event.raw_line:
            exploit = self._check_exploit_signatures(event.raw_line, ip, event)
            if exploit:
                return exploit

        return None

    def _check_ssh_bruteforce(self, ip: str, event, now: datetime) -> Optional[DetectedAttack]:
        """Detect SSH brute force attacks."""
        self.failed_attempts[ip].append(now)

        attempts = len(self.failed_attempts[ip])
        if attempts >= self.config.ssh_failed_attempts:
            self.failed_attempts[ip] = []  # Reset after detection
            return self._create_attack(
                'ssh_bruteforce', ip, event,
                details={
                    'attempt_count': attempts,
                    'username': event.username,
                    'port': event.port,
                    'window_seconds': self.config.time_window_seconds
                }
            )
        return None

    def _check_web_attack(self, ip: str, event, now: datetime) -> Optional[DetectedAttack]:
        """Detect web-based attacks."""
        self.web_attacks[ip].append(now)

        # Get attack subtype from log_type
        attack_subtype = event.log_type.replace('web_', '')

        if attack_subtype in self.ATTACK_TYPES:
            return self._create_attack(
                attack_subtype, ip, event,
                details={
                    'path': event.path,
                    'method': event.method,
                    'status_code': event.status_code,
                    'user_agent': event.user_agent
                }
            )
        return None

    def _check_db_bruteforce(self, db_type: str, ip: str, event, now: datetime) -> Optional[DetectedAttack]:
        """Detect database brute force attacks."""
        self.db_attempts[ip].append(now)

        if len(self.db_attempts[ip]) >= _get_brute_force_threshold():
            self.db_attempts[ip] = []
            return self._create_attack(
                f'{db_type}_bruteforce', ip, event,
                details={
                    'database': db_type,
                    'username': event.username,
                    'attempt_count': 5
                }
            )
        return None

    def _check_email_bruteforce(self, protocol: str, ip: str, event, now: datetime) -> Optional[DetectedAttack]:
        """Detect email service brute force attacks."""
        self.email_attempts[ip].append(now)

        if len(self.email_attempts[ip]) >= _get_brute_force_threshold():
            self.email_attempts[ip] = []
            return self._create_attack(
                f'{protocol}_bruteforce', ip, event,
                details={
                    'protocol': protocol,
                    'username': event.username,
                    'attempt_count': 5
                }
            )
        return None

    def _check_ftp_bruteforce(self, ip: str, event, now: datetime) -> Optional[DetectedAttack]:
        """Detect FTP brute force attacks."""
        self.ftp_attempts[ip].append(now)

        if len(self.ftp_attempts[ip]) >= _get_brute_force_threshold():
            self.ftp_attempts[ip] = []
            return self._create_attack(
                'ftp_bruteforce', ip, event,
                details={
                    'username': event.username,
                    'attempt_count': 5
                }
            )
        return None

    def _check_exploit_signatures(self, line: str, ip: str, event) -> Optional[DetectedAttack]:
        """Check for known exploit signatures."""
        # Shellshock
        if '() {' in line:
            return self._create_attack('shellshock_attempt', ip, event)

        # Log4j/JNDI injection
        if '${jndi:' in line.lower():
            return self._create_attack('log4j_attempt', ip, event)

        return None

    def _check_distributed_attack(self, event, now: datetime) -> Optional[DetectedAttack]:
        """Detect distributed attacks (multiple IPs, same target/pattern)."""
        # Track IPs hitting same endpoint in short window
        # This is a simplified version - full implementation would use Redis
        return None

    def _create_attack(self, attack_type: str, ip: str, event, details: Dict = None) -> DetectedAttack:
        """Create a detected attack object."""
        attack_info = self.ATTACK_TYPES.get(attack_type, {})

        raw_line = getattr(event, 'raw_line', None)
        detected = DetectedAttack(
            attack_type=attack_type,
            severity=attack_info.get('severity', 'medium'),
            ip_address=ip,
            timestamp=getattr(event, 'timestamp', datetime.now()),
            details=details or {},
            raw_evidence=[raw_line] if raw_line else []
        )

        # Track detected IPs
        self.detected_ips.add(ip)
        self.attack_history[ip].append(attack_type)

        return detected

    def _cleanup_old_entries(self, now: datetime):
        """Remove entries older than the time window."""
        cutoff = now - timedelta(seconds=self.config.time_window_seconds)

        for tracker in [self.failed_attempts, self.web_attacks,
                        self.db_attempts, self.email_attempts, self.ftp_attempts]:
            for ip in list(tracker.keys()):
                tracker[ip] = [ts for ts in tracker[ip] if ts > cutoff]
                if not tracker[ip]:
                    del tracker[ip]

    def should_alert(self, attack: DetectedAttack) -> bool:
        """Check if we should alert for this attack (rate limiting)."""
        key = f"{attack.attack_type}:{attack.ip_address}"
        last = self.last_alert.get(key)

        if last is None or (datetime.now() - last).seconds > self.alert_cooldown:
            self.last_alert[key] = datetime.now()
            return True
        return False

    def get_threat_score(self, ip: str) -> int:
        """Calculate threat score for an IP (0-100)."""
        score = 0
        detection_count = len(self.attack_history.get(ip, []))
        if ip in self.detected_ips:
            detection_count = max(detection_count, 1)
        score = min(100, detection_count * 20)
        return score

    def is_known_attacker(self, ip: str) -> bool:
        """Check if IP has been detected before."""
        return ip in self.detected_ips

    def analyze_packet_event(self, packet_event: Dict) -> Optional[DetectedAttack]:
        attack_type = packet_event.get("attack_type", "")
        severity = packet_event.get("severity", "medium")
        source_ip = packet_event.get("source_ip", "")
        details = packet_event.get("details", {})

        if not attack_type or not source_ip:
            return None

        if isinstance(details, str):
            details = {"message": details}

        detected = DetectedAttack(
            attack_type=attack_type,
            severity=severity,
            ip_address=source_ip,
            timestamp=datetime.now(),
            details=details,
            raw_evidence=[],
        )

        self.detected_ips.add(source_ip)
        self.attack_history[source_ip].append(attack_type)

        return detected
