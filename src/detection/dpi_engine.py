import logging
import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from urllib.parse import unquote

logger = logging.getLogger(__name__)


@dataclass
class DPIResult:
    attack_type: str
    severity: str
    details: str
    confidence: float
    mitre: List[str]


class DPIEngine:
    def __init__(self, rules_loader=None, log_parser=None):
        self._rules_loader = rules_loader
        self._log_parser = log_parser
        self._attack_patterns = {}
        if log_parser and hasattr(log_parser, "WEB_ATTACK_PATTERNS"):
            self._attack_patterns = log_parser.WEB_ATTACK_PATTERNS

    def inspect_stream(self, stream_data: bytes, protocol: str) -> Optional[DPIResult]:
        if not stream_data:
            return None
        if protocol == "http":
            parsed = self._parse_http(stream_data)
            if parsed:
                result = self._check_web_attack(parsed)
                if result:
                    return result
        elif protocol == "dns":
            parsed = self._parse_dns(stream_data)
            if parsed:
                return DPIResult(
                    attack_type="dns_anomaly",
                    severity="low",
                    details=f"DNS query: {parsed.get('query', 'unknown')}",
                    confidence=0.5,
                    mitre=["T1572"],
                )
        elif protocol == "tls":
            parsed = self._parse_tls(stream_data)
            if parsed:
                sni = parsed.get("sni", "")
                if self._is_suspicious_sni(sni):
                    return DPIResult(
                        attack_type="suspicious_tls",
                        severity="medium",
                        details=f"Suspicious SNI: {sni}",
                        confidence=0.6,
                        mitre=["T1572"],
                    )
        return None

    def inspect_packet(self, payload: bytes, protocol: str) -> Optional[DPIResult]:
        if not payload:
            return None
        body = unquote(payload.decode("utf-8", errors="replace"))
        if self._detect_sqli(body):
            return DPIResult("sql_injection", "critical", f"SQLi detected: {body[:200]}", 0.9, ["T1190"])
        if self._detect_xss(body):
            return DPIResult("xss_attempt", "high", f"XSS detected: {body[:200]}", 0.85, ["T1190"])
        if self._detect_cmd_injection(body):
            return DPIResult("command_injection", "critical", f"CMD injection: {body[:200]}", 0.9, ["T1190"])
        return None

    def _parse_http(self, data: bytes) -> Optional[Dict]:
        try:
            text = data.decode("utf-8", errors="replace")
            lines = text.split("\r\n")
            if not lines:
                return None
            request_line = lines[0]
            parts = request_line.split(" ")
            if len(parts) < 3:
                return None
            method = parts[0]
            uri = parts[1]
            headers = {}
            body = ""
            in_body = False
            body_lines = []
            for line in lines[1:]:
                if in_body:
                    body_lines.append(line)
                    continue
                if line == "":
                    in_body = True
                    continue
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            if body_lines:
                body = "\r\n".join(body_lines)
            return {"method": method, "uri": uri, "headers": headers, "body": body}
        except Exception:
            return None

    def _parse_dns(self, data: bytes) -> Optional[Dict]:
        try:
            import dns.message
            msg = dns.message.from_wire(data)
            if msg.question:
                return {"query": str(msg.question[0].name), "type": str(msg.question[0].rdtype)}
        except ImportError:
            l = len(data)
            if l > 12:
                qname_start = 12
                qname_parts = []
                while qname_start < l:
                    label_len = data[qname_start]
                    if label_len == 0:
                        break
                    qname_start += 1
                    if qname_start + label_len <= l:
                        qname_parts.append(data[qname_start:qname_start + label_len].decode("ascii", errors="replace"))
                        qname_start += label_len
                    else:
                        break
                if qname_parts:
                    return {"query": ".".join(qname_parts)}
        except Exception:
            pass
        return None

    def _parse_tls(self, data: bytes) -> Optional[Dict]:
        if len(data) < 5:
            return None
        content_type = data[0]
        if content_type != 0x16:
            return None
        handshake_type = data[5]
        if handshake_type != 0x01:
            return None
        offset = 11
        sid_len = data[offset] if offset < len(data) else 0
        offset += 1 + sid_len
        if offset + 2 > len(data):
            return None
        cipher_suites_len = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2 + cipher_suites_len
        if offset + 1 > len(data):
            return None
        comp_methods_len = data[offset]
        offset += 1 + comp_methods_len
        if offset + 2 > len(data):
            return None
        ext_len = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        end = offset + ext_len
        sni = ""
        while offset + 4 <= end:
            ext_type = int.from_bytes(data[offset:offset + 2], "big")
            ext_len = int.from_bytes(data[offset + 2:offset + 4], "big")
            offset += 4
            if ext_type == 0x00 and offset + 5 <= offset + ext_len:
                sni_len = int.from_bytes(data[offset + 2:offset + 4], "big")
                offset_sni = offset + 4
                sni = data[offset_sni:offset_sni + sni_len].decode("ascii", errors="replace")
                break
            offset += ext_len
        return {"sni": sni} if sni else None

    def _is_suspicious_sni(self, sni: str) -> bool:
        suspicious = _get_suspicious_sni_patterns()
        return any(s in sni.lower() for s in suspicious)


_SUSPICIOUS_SNI_PATTERNS = None


def _get_suspicious_sni_patterns():
    global _SUSPICIOUS_SNI_PATTERNS
    if _SUSPICIOUS_SNI_PATTERNS is not None:
        return _SUSPICIOUS_SNI_PATTERNS
    import yaml
    from pathlib import Path
    cfg_path = Path(__file__).parent.parent.parent / "config" / "config.yaml"
    default = [".xyz", ".tk", ".ml", ".ga", ".cf", "malware", "phish", "c2", "botnet",
               "reverse", "shell", "ransom", "crypt", "exploit"]
    if cfg_path.exists():
        with open(cfg_path) as f:
            cfg = yaml.safe_load(f)
        patterns = cfg.get("suspicious_sni_patterns", [])
        if patterns:
            _SUSPICIOUS_SNI_PATTERNS = patterns
    if _SUSPICIOUS_SNI_PATTERNS is None:
        _SUSPICIOUS_SNI_PATTERNS = default
    return _SUSPICIOUS_SNI_PATTERNS

    def _check_web_attack(self, parsed: Dict) -> Optional[DPIResult]:
        uri = parsed.get("uri", "")
        body = parsed.get("body", "")
        ua = parsed.get("headers", {}).get("user-agent", "")
        decoded_uri = unquote(uri)
        decoded_body = unquote(body)

        if self._detect_sqli(decoded_body) or self._detect_sqli(decoded_uri):
            return DPIResult("sql_injection", "critical", f"SQLi in {uri}", 0.9, ["T1190"])
        if self._detect_xss(decoded_body) or self._detect_xss(decoded_uri):
            return DPIResult("xss_attempt", "high", f"XSS in {uri}", 0.85, ["T1190"])
        if self._detect_cmd_injection(decoded_body) or self._detect_cmd_injection(decoded_uri):
            return DPIResult("command_injection", "critical", f"CMD injection in {uri}", 0.9, ["T1190"])
        if self._detect_path_traversal(decoded_uri):
            return DPIResult("path_traversal", "high", f"Path traversal: {uri}", 0.85, ["T1190"])
        if self._detect_scanner(ua, decoded_uri):
            return DPIResult("scanner_detected", "low", f"Scanner: {ua}", 0.7, ["T1046"])

        return None

    def _detect_sqli(self, text: str) -> bool:
        patterns = self._attack_patterns
        if "sql_injection" in patterns:
            return bool(patterns["sql_injection"].search(text))
        return bool(re.search(
            r"(union\s+select|select\s+.*\s+from|insert\s+into|"
            r"drop\s+table|;\s*--|'\s*or\s*'|1\s*=\s*1)",
            text, re.IGNORECASE))

    def _detect_xss(self, text: str) -> bool:
        patterns = self._attack_patterns
        if "xss" in patterns:
            return bool(patterns["xss"].search(text))
        return bool(re.search(r"(<script|javascript:|on\w+\s*=|<iframe|alert\(|eval\()",
                              text, re.IGNORECASE))

    def _detect_cmd_injection(self, text: str) -> bool:
        patterns = self._attack_patterns
        if "command_injection" in patterns:
            return bool(patterns["command_injection"].search(text))
        return bool(re.search(r"(;\s*\w+|&&\s*\w+|\|\s*\w+|`[^`]+`|\$\([^)]+\))",
                              text, re.IGNORECASE))

    def _detect_path_traversal(self, uri: str) -> bool:
        patterns = self._attack_patterns
        if "path_traversal" in patterns:
            return bool(patterns["path_traversal"].search(uri))
        return bool(re.search(r"(\.\./|\.\.\\|%2e%2e)", uri, re.IGNORECASE))

    def _detect_scanner(self, ua: str, uri: str) -> bool:
        patterns = self._attack_patterns
        if "scanner_signature" in patterns:
            return bool(patterns["scanner_signature"].search(ua) or
                        patterns["scanner_signature"].search(uri))
        scanner_agents = _get_scanner_agents()
        return any(s in ua.lower() for s in scanner_agents)


_SCANNER_AGENTS = None


def _get_scanner_agents():
    global _SCANNER_AGENTS
    if _SCANNER_AGENTS is not None:
        return _SCANNER_AGENTS
    import yaml
    from pathlib import Path
    cfg_path = Path(__file__).parent.parent.parent / "config" / "config.yaml"
    default = ["nikto", "nmap", "sqlmap", "dirbuster", "gobuster",
               "wpscan", "nuclei", "masscan", "zgrab", "burp", "acunetix"]
    if cfg_path.exists():
        with open(cfg_path) as f:
            cfg = yaml.safe_load(f)
        agents = cfg.get("scanner_agents", [])
        if agents:
            _SCANNER_AGENTS = agents
    if _SCANNER_AGENTS is None:
        _SCANNER_AGENTS = default
    return _SCANNER_AGENTS
