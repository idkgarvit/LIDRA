"""Port-based protocol classification for the TUI.

Maps well-known port numbers to human-readable protocol names.
Used by the protocol distribution bar in the dashboard.

Production note: Suricata, ntopng, Wireshark all use port-based
classification for live protocol stats. DPI is reserved for deep
per-flow inspection (handled by the DPI engine for attack detection).
"""

from __future__ import annotations

from typing import Dict, List, Set, Tuple


PROTOCOL_MAP: Dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    139: "SMB",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-TRAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "SYSLOG",
    587: "SMTP-SUB",
    636: "LDAPS",
    873: "RSYNC",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OPENVPN",
    1433: "MSSQL",
    1521: "ORACLE",
    1812: "RADIUS",
    1900: "SSDP",
    2049: "NFS",
    2375: "DOCKER",
    2376: "DOCKER-TLS",
    3000: "HTTP-ALT",
    3306: "MYSQL",
    3389: "RDP",
    4369: "ERLANG",
    5000: "HTTP-ALT",
    5060: "SIP",
    5061: "SIPS",
    5222: "XMPP",
    5432: "POSTGRES",
    5601: "KIBANA",
    5672: "AMQP",
    5900: "VNC",
    5984: "COUCHDB",
    6379: "REDIS",
    6443: "K8S-API",
    6660: "IRC",
    6661: "IRC",
    6662: "IRC",
    6663: "IRC",
    6664: "IRC",
    6665: "IRC",
    6666: "IRC",
    6667: "IRC",
    6668: "IRC",
    6669: "IRC",
    6697: "IRC-TLS",
    7474: "NEO4J",
    8000: "HTTP-ALT",
    8080: "HTTP-ALT",
    8081: "HTTP-ALT",
    8443: "HTTPS-ALT",
    8500: "CONSUL",
    8888: "HTTP-ALT",
    9000: "HTTP-ALT",
    9090: "PROMETHEUS",
    9092: "KAFKA",
    9200: "ELASTIC",
    9300: "ELASTIC",
    9418: "GIT",
    11211: "MEMCACHED",
    15672: "RABBITMQ",
    27017: "MONGODB",
    27018: "MONGODB",
    27019: "MONGODB",
}

WELL_KNOWN_PORTS: Set[int] = set(PROTOCOL_MAP.keys())


def classify_port(port: int) -> str:
    if port in PROTOCOL_MAP:
        return PROTOCOL_MAP[port]
    if port < 1024:
        return f"PORT-{port}"
    if 1024 <= port <= 49151:
        return "REGISTERED"
    return "EPHEMERAL"


def classify_packet(src_port: int, dst_port: int) -> str:
    for p in (dst_port, src_port):
        if p in WELL_KNOWN_PORTS:
            return PROTOCOL_MAP[p]
    return classify_port(dst_port) if dst_port > src_port else classify_port(src_port)


def known_protocols() -> List[str]:
    return sorted(set(PROTOCOL_MAP.values()))


def group_by_protocol(ports: List[int]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for p in ports:
        proto = classify_port(p)
        out[proto] = out.get(proto, 0) + 1
    return out


def aggregate_protocol_counts(protocols: List[str], top_n: int = 5) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for p in protocols:
        counts[p] = counts.get(p, 0) + 1
    sorted_items = sorted(counts.items(), key=lambda x: -x[1])
    if len(sorted_items) <= top_n:
        return dict(sorted_items)
    top = dict(sorted_items[:top_n])
    other_count = sum(c for _, c in sorted_items[top_n:])
    if other_count > 0:
        top["OTHER"] = other_count
    return top


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
