import functools
import json
import logging
import os
import subprocess
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

_MITRE_TACTICS = {
    "T1190": "Initial Access",
    "T1046": "Reconnaissance",
    "T1572": "C2",
    "T1021": "Lateral Movement",
    "T1498": "DDoS",
    "T1203": "Execution",
    "T1059": "Command & Scripting",
    "T1505": "Persistence",
    "T1071": "Application Layer Protocol",
}

_MITRE_SEVERITY = {
    "T1190": 9.0, "T1046": 4.0, "T1572": 8.0, "T1021": 7.0,
    "T1498": 9.0, "T1203": 6.0, "T1059": 7.0, "T1505": 7.5,
    "T1071": 5.0,
}


def playbook(name: str):
    def decorator(func):
        func._playbook_name = name
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapper
    return decorator


def action(name: str):
    def decorator(func):
        func._action_name = name
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapper
    return decorator


class EnrichmentEngine:
    def __init__(self):
        self._cache: Dict[str, Dict] = {}
        self._cache_ttl = 3600

    def enrich(self, ip: str) -> Dict:
        now = time.time()
        cached = self._cache.get(ip)
        if cached and now - cached["_ts"] < self._cache_ttl:
            return cached

        result = {"ip": ip, "sources": {}, "score": 0.0}

        abuseipdb_key = os.environ.get("ABUSEIPDB_KEY", "")
        if abuseipdb_key:
            try:
                import urllib.request
                url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
                req = urllib.request.Request(url, headers={"Key": abuseipdb_key, "Accept": "application/json"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read())
                    result["sources"]["abuseipdb"] = data.get("data", {})
                    result["score"] = max(result["score"], data.get("data", {}).get("abuseConfidenceScore", 0) / 100)
            except Exception as e:
                logger.debug(f"[Enrich] AbuseIPDB failed for {ip}: {e}")

        vt_key = os.environ.get("VIRUSTOTAL_KEY", "")
        if vt_key:
            try:
                import urllib.request
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                req = urllib.request.Request(url, headers={"x-apikey": vt_key})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read())
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    result["sources"]["virustotal"] = stats
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) if sum(stats.values()) > 0 else 1
                    result["score"] = max(result["score"], malicious / total)
            except Exception as e:
                logger.debug(f"[Enrich] VirusTotal failed for {ip}: {e}")

        result["_ts"] = now
        self._cache[ip] = result
        return result


class Incident:
    def __init__(self, alert: Dict):
        self.id = int(time.time() * 1000) % 1000000
        self.alert = alert
        self.timestamp = time.time()
        self.source_ip = alert.get("source_ip", "")
        self.attack_type = alert.get("attack_type", "unknown")
        self.severity = alert.get("severity", "low")
        self.mitre = alert.get("mitre", [])
        self.resolved = False
        self.actions_taken: List[str] = []
        self.pcap_path: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "source_ip": self.source_ip,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "mitre": self.mitre,
            "resolved": self.resolved,
            "actions_taken": self.actions_taken,
            "pcap": self.pcap_path,
        }


class IncidentResponder:
    def __init__(self, config: dict = None):
        self._config = config or {}
        self._incidents: List[Incident] = []
        self._playbooks: Dict[str, List[Callable]] = {}
        self._pcap_dir = Path(self._config.get("pcap_dir", "./state/pcaps"))
        self._pcap_dir.mkdir(parents=True, exist_ok=True)
        self._enrichment = EnrichmentEngine()
        self._dedup_window = self._config.get("dedup_window_seconds", 300)
        self._recent_alerts: Dict[str, float] = {}
        self._sla = {"critical": 300, "high": 600, "medium": 1800, "low": 3600}
        self._register_default_playbooks()

    def _register_default_playbooks(self):
        self.register_playbook("block_ip", [self._action_block_ip])
        self.register_playbook("capture_pcap", [self._action_capture_pcap])
        self.register_playbook("full_response", [
            self._action_enrich,
            self._action_triage_llm,
            self._action_block_ip,
            self._action_capture_pcap,
            self._action_log_incident,
        ])

    def register_playbook(self, name: str, actions: List[Callable]):
        self._playbooks[name] = actions
        logger.info(f"[IR] Registered playbook: {name} ({len(actions)} actions)")

    def _is_duplicate(self, alert: Dict) -> bool:
        key = (alert.get("source_ip", ""), alert.get("attack_type", ""))
        now = time.time()
        last = self._recent_alerts.get(key)
        if last and now - last < self._dedup_window:
            return True
        self._recent_alerts[key] = now
        return False

    def _check_sla(self, incident: Incident) -> Optional[str]:
        elapsed = time.time() - incident.timestamp
        threshold = self._sla.get(incident.severity, 3600)
        if elapsed > threshold:
            return f"SLA breached: {incident.severity} incident {incident.id} unhandled for {elapsed:.0f}s"
        return None

    def handle_alert(self, alert: Dict) -> Optional[Incident]:
        if self._is_duplicate(alert):
            logger.debug(f"[IR] Suppressed duplicate alert: {alert.get('attack_type')} from {alert.get('source_ip')}")
            return None

        incident = Incident(alert)
        self._incidents.append(incident)

        sla_breach = self._check_sla(incident)
        if sla_breach:
            logger.warning(f"[IR] {sla_breach}")

        severity = alert.get("severity", "low")
        if severity in ("critical", "high"):
            playbook = self._config.get("playbooks", {}).get(severity, "full_response")
        else:
            playbook = self._config.get("playbooks", {}).get("default", "log_only")
            self._action_log_incident(incident)
            self._incidents[-1] = incident
            return incident

        actions = self._playbooks.get(playbook, [])
        for action in actions:
            try:
                action(incident)
            except Exception as e:
                logger.error(f"[IR] Action failed for {incident.id}: {e}")

        self._incidents[-1] = incident
        return incident

    def _action_enrich(self, incident: Incident):
        ip = incident.source_ip
        if not ip:
            return
        try:
            enrichment = self._enrichment.enrich(ip)
            incident.actions_taken.append(f"enriched {ip} (score={enrichment['score']:.2f})")
        except Exception as e:
            logger.debug(f"[IR] Enrich failed for {ip}: {e}")

    def _action_triage_llm(self, incident: Incident):
        try:
            ollama_model = os.environ.get("OLLAMA_MODEL", "")
            if ollama_model:
                import urllib.request
                prompt = f"Triage this security alert:\nType: {incident.attack_type}\nSeverity: {incident.severity}\nSource: {incident.source_ip}\nMITRE: {incident.mitre}\n\nProvide a one-paragraph summary."
                body = json.dumps({"model": ollama_model, "prompt": prompt, "stream": False}).encode()
                req = urllib.request.Request("http://localhost:11434/api/generate", data=body, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    result = json.loads(resp.read())
                    summary = result.get("response", "").strip()
                    if summary:
                        incident.actions_taken.append(f"LLM triage: {summary[:200]}")
        except Exception as e:
            logger.debug(f"[IR] LLM triage failed: {e}")

    def _action_block_ip(self, incident: Incident):
        ip = incident.source_ip
        if not ip:
            return
        try:
            if subprocess.run(["which", "iptables"], capture_output=True, check=False).returncode == 0:
                subprocess.run(
                    ["iptables", "-A", "LIDRA_BLOCK", "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=5, check=False
                )
            elif subprocess.run(["which", "nft"], capture_output=True, check=False).returncode == 0:
                subprocess.run(
                    ["nft", "add", "rule", "inet", "filter", "LIDRA_BLOCK",
                     f"ip saddr {ip} drop"],
                    capture_output=True, timeout=5, check=False
                )
            incident.actions_taken.append(f"blocked {ip}")
            logger.info(f"[IR] Blocked {ip} (incident {incident.id})")
        except Exception as e:
            logger.warning(f"[IR] Block failed for {ip}: {e}")

    def _action_capture_pcap(self, incident: Incident):
        ip = incident.source_ip
        if not ip:
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = self._pcap_dir / f"incident_{incident.id}_{ts}.pcap"
        try:
            iface = "any"
            proc = subprocess.Popen(
                ["tcpdump", "-i", iface, "-c", "1000", "-w", str(pcap_file),
                 f"host {ip}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            proc.wait(timeout=30)
            if pcap_file.exists() and pcap_file.stat().st_size > 0:
                incident.pcap_path = str(pcap_file)
                incident.actions_taken.append(f"captured PCAP: {pcap_file} ({pcap_file.stat().st_size}B)")
                logger.info(f"[IR] Captured PCAP for {ip}: {pcap_file}")
        except Exception as e:
            logger.warning(f"[IR] PCAP capture failed: {e}")

    def _action_log_incident(self, incident: Incident):
        log_path = self._pcap_dir.parent / "incidents.jsonl"
        try:
            with open(log_path, "a") as f:
                f.write(json.dumps(incident.to_dict()) + "\n")
            incident.actions_taken.append("logged to incidents.jsonl")
        except Exception as e:
            logger.warning(f"[IR] Incident log failed: {e}")

    def generate_report(self) -> Dict:
        total = len(self._incidents)
        resolved = sum(1 for i in self._incidents if i.resolved)
        tactics_count: Dict[str, int] = {}
        severity_count: Dict[str, int] = {}
        for inc in self._incidents:
            for t in inc.mitre:
                tactic = _MITRE_TACTICS.get(t, t)
                tactics_count[tactic] = tactics_count.get(tactic, 0) + 1
            severity_count[inc.severity] = severity_count.get(inc.severity, 0) + 1

        return {
            "total_incidents": total,
            "resolved": resolved,
            "open": total - resolved,
            "severity_distribution": severity_count,
            "mitre_heatmap": tactics_count,
            "top_attackers": self._top_attackers(),
        }

    def _top_attackers(self, n: int = 10) -> List[Dict]:
        ip_counts: Dict[str, int] = {}
        ip_severity: Dict[str, List[str]] = {}
        for inc in self._incidents:
            ip = inc.source_ip
            if not ip:
                continue
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            ip_severity.setdefault(ip, []).append(inc.severity)
        sorted_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:n]
        result = []
        for ip, count in sorted_ips:
            sevs = ip_severity.get(ip, [])
            max_sev = "critical" if "critical" in sevs else "high" if "high" in sevs else "medium" if "medium" in sevs else "low"
            result.append({"ip": ip, "incidents": count, "max_severity": max_sev})
        return result

    def get_incidents(self, limit: int = 50) -> List[Dict]:
        return [i.to_dict() for i in self._incidents[-limit:]]
