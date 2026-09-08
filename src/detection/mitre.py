"""
LIDRA v3 MITRE ATT&CK Mapper

Maps detections to MITRE ATT&CK framework for enterprise compatibility.
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class MITRETactic:
    """MITRE ATT&CK tactic."""
    id: str
    name: str
    description: str


@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique."""
    id: str
    name: str
    tactic: str
    detection_sources: List[str]
    platforms: List[str]


class MITREMapper:
    """
    Maps LIDRA attack types to MITRE ATT&CK framework.
    
    Provides:
    - Technique lookup by attack type
    - Coverage reporting
    - Tactic hierarchy
    """
    
    # Attack type to MITRE technique mapping
    ATTACK_TO_MITRE = {
        # Initial Access
        'ssh_bruteforce': ['T1110', 'T1078'],
        'ssh_invalid_user': ['T1110', 'T1078'],
        'web_bruteforce': ['T1110'],
        'sql_injection': ['T1190', 'T1059'],
        'xss_attempt': ['T1189', 'T1059'],
        'path_traversal': ['T1190'],
        'lfi_attempt': ['T1190'],
        'rfi_attempt': ['T1190'],
        'command_injection': ['T1059', 'T1190'],
        
        # Execution
        'reverse_shell': ['T1059', 'T1053'],
        'webshell': ['T1505', 'T1059'],
        'download_execute': ['T1105', 'T1059'],
        'scheduled_task': ['T1053'],
        'cron_job': ['T1053'],
        
        # Persistence
        'ssh_key_added': ['T1098', 'T1543'],
        'cron_persistence': ['T1053'],
        'rc_modification': ['T1547'],
        'registry_persistence': ['T1547'],
        
        # Privilege Escalation
        'privilege_escalation_attempt': ['T1548'],
        'sudo_abuse': ['T1548'],
        'suid_abuse': ['T1068'],
        'kernel_exploit': ['T1068'],
        
        # Defense Evasion
        'log_clearing': ['T1070'],
        'process_hiding': ['T1562', 'T1036'],
        'rootkit_indicator': ['T1014', 'T1068'],
        
        # Credential Access
        'password_dump': ['T1003'],
        'keylogging': ['T1056'],
        'credential_theft': ['T1555', 'T1111'],
        '/etc/passwd_access': ['T1005'],
        '/etc/shadow_access': ['T1005'],
        
        # Discovery
        'port_scan': ['T1595', 'T1082'],
        'network_enum': ['T1595'],
        'user_enum': ['T1087'],
        'file_discovery': ['T1083'],
        'process_discovery': ['T1057'],

        # Deception (Honeypot/Honeyfile)
        'honeypot_connection': ['T1595', 'T1589'],
        'honeyfile_access': ['T1595', 'T1083'],

        # Lateral Movement
        'remote_service': ['T1021'],
        'ssh_lateral': ['T1021', 'T1078'],
        'smb_lateral': ['T1021'],
        
        # Collection
        'data_collection': ['T1560', 'T1119'],
        'screenshot': ['T1113'],
        'keylog_collection': ['T1056'],
        
        # Exfiltration
        'data_exfiltration': ['T1041', 'T1048'],
        'dns_exfiltration': ['T1041', 'T1573'],
        'high_port_exfil': ['T1041'],
        
        # Impact
        'process_termination': ['T1489'],
        'service_stop': ['T1489'],
        'ransomware_indicator': ['T1486'],
        'disk_wipe': ['T1485'],
        
        # Command & Control
        'suspicious_connection': ['T1071', 'T1573'],
        'high_port_connection': ['T1573'],
        'external_ssh': ['T1071'],
        'irc_c2': ['T1071'],
        
        # Impact - Resource Hijacking
        'crypto_miner': ['T1496'],
    }
    
    # Technique to tactic mapping. T1053/T1078 legitimately span tactics
    # (MITRE lists both under several); dict() keeps the LAST entry per
    # technique, i.e. 'persistence' — the single-tactic model is a known
    # simplification, get_tactic() returns one tactic per technique.
    TECHNIQUE_TO_TACTIC = dict([
        # Initial Access
        ('T1190', 'initial_access'),
        ('T1078', 'initial_access'),
        ('T1133', 'initial_access'),
        ('T1566', 'initial_access'),

        # Execution
        ('T1059', 'execution'),
        ('T1204', 'execution'),
        ('T1203', 'execution'),
        ('T1053', 'execution'),

        # Persistence
        ('T1547', 'persistence'),
        ('T1136', 'persistence'),
        ('T1543', 'persistence'),
        ('T1053', 'persistence'),
        ('T1078', 'persistence'),

        # Privilege Escalation
        ('T1548', 'privilege_escalation'),
        ('T1068', 'privilege_escalation'),

        # Defense Evasion
        ('T1562', 'defense_evasion'),
        ('T1070', 'defense_evasion'),
        ('T1036', 'defense_evasion'),
        ('T1014', 'defense_evasion'),

        # Credential Access
        ('T1110', 'credential_access'),
        ('T1003', 'credential_access'),
        ('T1555', 'credential_access'),
        ('T1056', 'credential_access'),

        # Discovery
        ('T1595', 'discovery'),
        ('T1082', 'discovery'),
        ('T1087', 'discovery'),
        ('T1083', 'discovery'),
        ('T1057', 'discovery'),

        # Lateral Movement
        ('T1021', 'lateral_movement'),
        ('T1210', 'lateral_movement'),

        # Collection
        ('T1560', 'collection'),
        ('T1119', 'collection'),
        ('T1113', 'collection'),

        # Exfiltration
        ('T1041', 'exfiltration'),
        ('T1048', 'exfiltration'),

        # Impact
        ('T1486', 'impact'),
        ('T1489', 'impact'),
        ('T1485', 'impact'),
        ('T1496', 'impact'),

        # Command & Control
        ('T1071', 'command_and_control'),
        ('T1573', 'command_and_control'),
    ])
    
    # Tactic definitions
    TACTICS = {
        'initial_access': MITRETactic(
            id='TA0001',
            name='Initial Access',
            description='Techniques that use an entry point to compromise a system'
        ),
        'execution': MITRETactic(
            id='TA0002',
            name='Execution',
            description='Techniques that run code on a system'
        ),
        'persistence': MITRETactic(
            id='TA0003',
            name='Persistence',
            description='Techniques that maintain access across restarts'
        ),
        'privilege_escalation': MITRETactic(
            id='TA0004',
            name='Privilege Escalation',
            description='Techniques that gain higher permissions'
        ),
        'defense_evasion': MITRETactic(
            id='TA0005',
            name='Defense Evasion',
            description='Techniques that avoid detection'
        ),
        'credential_access': MITRETactic(
            id='TA0006',
            name='Credential Access',
            description='Techniques that steal credentials'
        ),
        'discovery': MITRETactic(
            id='TA0007',
            name='Discovery',
            description='Techniques that explore the environment'
        ),
        'lateral_movement': MITRETactic(
            id='TA0008',
            name='Lateral Movement',
            description='Techniques that move through environment'
        ),
        'collection': MITRETactic(
            id='TA0009',
            name='Collection',
            description='Techniques that gather data'
        ),
        'command_and_control': MITRETactic(
            id='TA0011',
            name='Command and Control',
            description='Techniques that communicate with compromised systems'
        ),
        'exfiltration': MITRETactic(
            id='TA0010',
            name='Exfiltration',
            description='Techniques that steal data'
        ),
        'impact': MITRETactic(
            id='TA0040',
            name='Impact',
            description='Techniques that disrupt availability'
        ),
    }
    
    def __init__(self):
        self.detection_coverage: Dict[str, Set[str]] = defaultdict(set)
        self._build_detection_sources()
    
    def _build_detection_sources(self):
        """Build detection source mapping."""
        # Map techniques to detection sources
        # Sources: eBPF, log, network, cloud
        for attack_type, techniques in self.ATTACK_TO_MITRE.items():
            for technique in techniques:
                self.detection_coverage[technique].add(attack_type)
    
    def get_techniques(self, attack_type: str) -> List[str]:
        """Get MITRE techniques for an attack type."""
        return self.ATTACK_TO_MITRE.get(attack_type, [])
    
    def get_tactic(self, technique: str) -> Optional[str]:
        """Get tactic for a technique."""
        return self.TECHNIQUE_TO_TACTIC.get(technique)
    
    def get_tactic_info(self, tactic: str) -> Optional[MITRETactic]:
        """Get tactic information."""
        return self.TACTICS.get(tactic)
    
    def get_coverage_report(self) -> Dict:
        """Generate MITRE ATT&CK coverage report."""
        covered_techniques = set()
        covered_tactics = set()
        
        for attack_type, techniques in self.ATTACK_TO_MITRE.items():
            for technique in techniques:
                covered_techniques.add(technique)
                tactic = self.get_tactic(technique)
                if tactic:
                    covered_tactics.add(tactic)
        
        return {
            'total_techniques': len(covered_techniques),
            'total_tactics': len(covered_tactics),
            'techniques': sorted(covered_techniques),
            'tactics': sorted(covered_tactics),
            'coverage_percentage': round(len(covered_techniques) / max(len(covered_techniques), 1) * 100, 1)
        }
    
    def enrich_detection(self, attack_type: str, detection: Dict) -> Dict:
        """Enrich detection with MITRE information."""
        techniques = self.get_techniques(attack_type)
        
        detection['mitre_techniques'] = techniques
        detection['mitre_tactics'] = [
            self.get_tactic(t) for t in techniques if self.get_tactic(t)
        ]
        
        return detection
    
    def get_technique_details(self, technique_id: str) -> Optional[Dict]:
        """Get details for a specific technique."""
        tactic = self.get_tactic(technique_id)
        if not tactic:
            return None
        
        tactic_info = self.get_tactic_info(tactic)
        
        return {
            'technique_id': technique_id,
            'tactic': tactic,
            'tactic_name': tactic_info.name if tactic_info else 'Unknown',
            'tactic_description': tactic_info.description if tactic_info else '',
            'attack_types': list(self.detection_coverage.get(technique_id, []))
        }