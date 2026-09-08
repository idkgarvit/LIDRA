"""Attack-type to protocol bucketing for the TUI protocol split.

The dashboard buckets by attack type (via classify_attack_type), not by
port — DPI owns per-flow inspection for detection.
"""

from __future__ import annotations

from typing import Dict


ATTACK_TYPE_TO_PROTOCOL: Dict[str, str] = {
    "ssh_bruteforce": "SSH",
    "ssh_invalid_user": "SSH",
    "ssh_connection_flood": "SSH",
    "ssh_login_success_after_failures": "SSH",
    "mysql_bruteforce": "MYSQL",
    "postgres_bruteforce": "POSTGRES",
    "mssql_bruteforce": "MSSQL",
    "oracle_bruteforce": "ORACLE",
    "mongodb_bruteforce": "MONGODB",
    "redis_bruteforce": "REDIS",
    "ftp_bruteforce": "FTP",
    "ftp_anonymous": "FTP",
    "pop3_bruteforce": "POP3",
    "imap_bruteforce": "IMAP",
    "smtp_bruteforce": "SMTP",
    "snmp_bruteforce": "SNMP",
    "telnet_bruteforce": "TELNET",
    "rdp_bruteforce": "RDP",
    "sql_injection": "HTTP",
    "xss_attempt": "HTTP",
    "xss": "HTTP",
    "path_traversal": "HTTP",
    "lfi_attempt": "HTTP",
    "rfi_attempt": "HTTP",
    "command_injection": "HTTP",
    "ssrf_attempt": "HTTP",
    "xxe_attempt": "HTTP",
    "ssti_attempt": "HTTP",
    "deserialization_attack": "HTTP",
    "ldap_injection": "LDAP",
    "scanner_detected": "HTTP",
    "admin_probe": "HTTP",
    "sensitive_file_access": "HTTP",
    "api_enumeration": "HTTP",
    "shellshock_attempt": "HTTP",
    "log4j_attempt": "HTTP",
    "heartbleed_attempt": "HTTPS",
    "eternalblue_attempt": "SMB",
    "spectre_attempt": "HTTP",
    "dns_tunneling": "DNS",
    "port_scan": "OTHER",
    "port_hopping": "OTHER",
    "broadcast_storm": "OTHER",
    "timing_evasion": "OTHER",
    "ipv6_tunnel": "OTHER",
    "covert_channel": "OTHER",
    "session_correlated_sql_attack": "HTTP",
    "session_correlated_cmd_attack": "HTTP",
    "session_correlated_traversal_attack": "HTTP",
    "reverse_shell": "OTHER",
    "privilege_escalation_attempt": "OTHER",
    "webshell_creation": "HTTP",
    "credential_access": "OTHER",
    "log_tampering": "OTHER",
}


def classify_attack_type(attack_type: str) -> str:
    if not attack_type:
        return "OTHER"
    return ATTACK_TYPE_TO_PROTOCOL.get(attack_type, "OTHER")
