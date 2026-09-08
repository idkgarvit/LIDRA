"""
LIDRA v3 Attack Explainer

Generates human-readable explanations for detected attacks.
Template-based (works offline) with optional LLM integration.

Includes:
- What happened
- Why it matters (risk)
- Recommended action
- MITRE mapping
- Confidence score
"""

import logging
from typing import Dict, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class Explanation:
    """Complete explanation of an attack."""
    title: str
    what_happened: str
    risk_level: str
    recommended_actions: List[str]
    mitre_techniques: List[str]
    confidence: int
    raw_explanation: str


class AttackExplainer:
    """
    Generates explainable alerts for security detections.
    
    Why this matters:
    - Analysts spend 30%+ time understanding why alert triggered
    - Current tools give raw data, not context
    - This makes LIDRA stand out
    """
    
    TEMPLATES = {
        # Execution-based attacks
        'reverse_shell': {
            'title': '🔴 Reverse Shell Detected',
            'what': 'An attacker established a reverse shell from {dst_ip}:{port}',
            'why': 'This allows the attacker to execute commands on your system remotely, effectively giving them full control',
            'risk': 'CRITICAL - Immediate remote code execution capability',
            'actions': [
                'Block the source IP immediately',
                'Isolate the affected system from network',
                'Check for other compromise indicators',
                'Review recent user sessions',
                'Preserve forensic evidence'
            ],
            'confidence': 90
        },
        
        'download_execute': {
            'title': '🔴 Download & Execute Attack',
            'what': 'System downloaded content and executed it: {filename}',
            'why': 'Attackers often download payloads (malware, scripts) to compromise systems',
            'risk': 'HIGH - Could install malware, backdoors, or ransomware',
            'actions': [
                'Identify what was downloaded and executed',
                'Check system for new files/processes',
                'Scan for known malware signatures',
                'Review network connections'
            ],
            'confidence': 75
        },
        
        'webshell': {
            'title': '🔴 Webshell Detected',
            'what': 'Suspicious file created in web directory: {filename}',
            'why': 'Webshells give attackers persistent remote access through web interface',
            'risk': 'CRITICAL - Persistent remote access via web',
            'actions': [
                'Delete the webshell immediately',
                'Check for other webshells',
                'Review web server access logs',
                'Check for privilege escalation'
            ],
            'confidence': 85
        },
        
        # Credential attacks
        'ssh_bruteforce': {
            'title': '🔴 SSH Brute Force Attack',
            'what': '{count} failed SSH login attempts from {dst_ip}',
            'why': 'Automated credential guessing, likely part of a broader attack campaign',
            'risk': 'HIGH - Successful compromise could give full system access',
            'actions': [
                'Block source IP if not whitelisted',
                'Review successful logins around same time',
                'Consider fail2ban or similar',
                'Enforce key-based auth'
            ],
            'confidence': 95
        },
        
        'sql_injection': {
            'title': '🔴 SQL Injection Attempt',
            'what': 'Malicious SQL pattern detected in {filename}',
            'why': 'SQL injection can extract/modify/destroy database contents',
            'risk': 'CRITICAL - Could lead to data breach or complete compromise',
            'actions': [
                'Review application logs for this IP',
                'Check if attack was successful',
                'Patch input validation',
                'Use parameterized queries'
            ],
            'confidence': 90
        },
        
        'credential_theft': {
            'title': '🟠 Credential Access Attempt',
            'what': 'Access to sensitive credential storage: {filename}',
            'why': 'Attackers target password files, keys, and tokens for lateral movement',
            'risk': 'HIGH - Could enable privilege escalation and lateral movement',
            'actions': [
                'Check for compromised credentials',
                'Rotate exposed credentials',
                'Review access logs'
            ],
            'confidence': 80
        },
        
        # Network-based attacks
        'suspicious_connection': {
            'title': '🟠 Suspicious Network Connection',
            'what': 'Connection to known malicious port {port} ({malware}) at {dst_ip}',
            'why': 'Common C2 (Command & Control) ports indicate compromised system',
            'risk': 'HIGH - Possible remote control by attacker',
            'actions': [
                'Block connection immediately',
                'Investigate the destination',
                'Check for other C2 indicators'
            ],
            'confidence': 70
        },
        
        'high_port_connection': {
            'title': '🟡 High Port Connection',
            'what': 'Connection to non-standard port {port} at {dst_ip}',
            'why': 'Attackers use high ports to evade basic firewall rules',
            'risk': 'MEDIUM - May be C2 or data exfiltration',
            'actions': [
                'Verify if this is legitimate business use',
                'Check connection frequency pattern'
            ],
            'confidence': 50
        },
        
        'port_scan': {
            'title': '🟡 Port Scan Detected',
            'what': 'Multiple ports scanned from {dst_ip}',
            'why': 'Reconnaissance phase - attacker mapping your attack surface',
            'risk': 'MEDIUM - Precedes actual attack',
            'actions': [
                'Block source IP',
                'Review which ports were probed',
                'Harden scanned services'
            ],
            'confidence': 75
        },
        
        # Persistence
        'ssh_key_added': {
            'title': '🔴 SSH Key Persistence',
            'what': 'New SSH authorized key added for user {username}',
            'why': 'Attackers add their own SSH keys for persistent access',
            'risk': 'HIGH - Provides long-term access',
            'actions': [
                'Verify the key is legitimate',
                'Remove unauthorized keys',
                'Investigate how key was added'
            ],
            'confidence': 85
        },
        
        'cron_persistence': {
            'title': '🔴 Cron Job Persistence',
            'what': 'New scheduled task created: {filename}',
            'why': 'Attackers use cron for persistent execution',
            'risk': 'HIGH - Provides persistent execution',
            'actions': [
                'Verify cron job is legitimate',
                'Remove malicious cron entries',
                'Check what the job executes'
            ],
            'confidence': 80
        },
        
        # Impact
        'process_termination': {
            'title': '🟠 Process Killed',
            'what': 'Process {pid} was terminated',
            'why': 'Could be attacker disabling security tools or malicious',
            'risk': 'MEDIUM - May disable defenses',
            'actions': [
                'Verify the process was legitimate',
                'Check for disabled security tools'
            ],
            'confidence': 40
        },
        
        'data_exfiltration': {
            'title': '🔴 Data Exfiltration Detected',
            'what': 'Large data transfer to {dst_ip}:{port}',
            'why': 'Data leaving the network - possible breach',
            'risk': 'CRITICAL - Data loss',
            'actions': [
                'Block destination IP',
                'Identify what data was transferred',
                'Preserve evidence'
            ],
            'confidence': 70
        },
        
        # Default
        'unknown': {
            'title': '🟡 Security Event',
            'what': 'Detected: {attack_type} from {dst_ip}',
            'why': 'Unknown security event requires investigation',
            'risk': 'MEDIUM - Requires analysis',
            'actions': [
                'Review event details',
                'Check for related events'
            ],
            'confidence': 50
        }
    }
    
    def __init__(self):
        pass
    
    def explain(self, detection: Dict, context: Dict = None) -> str:
        """
        Generate explanation for a detection.
        
        Args:
            detection: Detection info (attack_type, severity, details)
            context: Additional context (event, threat_intel)
            
        Returns:
            Human-readable explanation string
        """
        attack_type = detection.get('attack_type', 'unknown')
        
        template = self.TEMPLATES.get(attack_type, self.TEMPLATES['unknown'])
        
        # Build context variables
        details = detection.get('details', {})
        threat_intel = context.get('threat_intel', {}) if context else {}
        
        vars = {
            'attack_type': attack_type,
            'dst_ip': details.get('dst_ip') or details.get('ip') or 'unknown',
            'src_ip': details.get('src_ip') or 'unknown',
            'port': details.get('dst_port') or details.get('port') or 'unknown',
            'filename': details.get('filename') or details.get('path') or 'unknown',
            'username': details.get('username') or 'unknown',
            'count': details.get('attempt_count') or details.get('count') or 'multiple',
            'pid': details.get('pid') or 'unknown',
            'malware': details.get('malware_associated') or 'unknown',
            'severity': detection.get('severity', 'medium').upper(),
            'threat_score': threat_intel.get('threat_score', 0),
            'is_malicious': threat_intel.get('is_malicious', False)
        }
        
        # Build explanation
        lines = []
        
        # Title
        lines.append(f"## {template['title']}")
        lines.append("")
        
        # What happened
        lines.append(f"**What:** {template['what'].format(**vars)}")
        
        # Why it matters
        lines.append(f"**Why:** {template['why']}")
        
        # Risk level
        risk = template['risk'].format(**vars) if '{' in template['risk'] else template['risk']
        lines.append(f"**Risk:** {risk}")
        
        # MITRE techniques
        mitre = detection.get('mitre', [])
        if mitre:
            lines.append(f"**MITRE:** {', '.join(mitre)}")
        
        # Threat intel context
        if threat_intel.get('threat_score', 0) > 0:
            lines.append(f"**Threat Score:** {threat_intel['threat_score']}/100")
        
        # Recommended actions
        lines.append("")
        lines.append("**Recommended Actions:**")
        for action in template['actions']:
            lines.append(f"  - {action}")
        
        # Confidence
        lines.append("")
        lines.append(f"**Confidence:** {template['confidence']}%")
        
        return "\n".join(lines)
    
