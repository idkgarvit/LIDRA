"""
LIDRA v3 SIEM Output Formatters

Supports multiple output formats:
- JSON (Elastic, Splunk compatible)
- CEF (ArcSight, QRadar)
- Syslog (direct to SIEM)
- STIX (threat intel sharing)
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import asdict

logger = logging.getLogger(__name__)


class OutputFormatter:
    """Base class for output formatters."""
    
    def format(self, event: Dict) -> Any:
        """Format event to output format."""
        raise NotImplementedError


class JSONFormatter(OutputFormatter):
    """
    JSON format for Elastic, Splunk, custom SIEMs.
    ECS (Elastic Common Schema) compatible.
    """
    
    def __init__(self, include_raw: bool = True):
        self.include_raw = include_raw
    
    def format(self, event: Dict) -> str:
        """Format event as JSON."""
        
        output = {
            '@timestamp': event.get('timestamp', datetime.now().isoformat()),
            'event': {
                'kind': 'alert',
                'category': event.get('attack_type', 'unknown'),
                'type': event.get('severity', 'medium'),
                'action': 'detected',
                'dataset': 'lidra',
                'module': 'lidra-v3'
            },
            'source': {
                'ip': event.get('ip_address', event.get('dst_ip', '')),
                'port': event.get('dst_port', 0),
                'user': {
                    'name': event.get('username', '')
                }
            },
            'observer': {
                'vendor': 'LIDRA',
                'product': 'LIDRA IDS',
                'version': '3.0.0',
                'type': 'detection'
            },
            'rule': {
                'name': event.get('attack_type', ''),
                'id': event.get('rule_id', ''),
                'category': event.get('category', ''),
                'mitre': event.get('mitre', [])
            },
            'security': {
                'severity': self._map_severity(event.get('severity', 'medium')),
                'risk_score': event.get('threat_score', 0)
            },
            'lidra': {
                'detection_method': event.get('detection_method', 'unknown'),
                'confidence': event.get('confidence', 0)
            }
        }
        
        if self.include_raw and 'raw_line' in event:
            output['message'] = event['raw_line']
        
        return json.dumps(output)
    
    def _map_severity(self, severity: str) -> int:
        """Map severity to numeric."""
        mapping = {
            'critical': 100,
            'high': 80,
            'medium': 50,
            'low': 20,
            'informational': 10
        }
        return mapping.get(severity.lower(), 50)


class CEFFormatter(OutputFormatter):
    """
    Common Event Format (CEF) for ArcSight, QRadar.
    
    Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """
    
    DEVICE_VENDOR = "LIDRA"
    DEVICE_PRODUCT = "LIDRA IDS"
    DEVICE_VERSION = "3.0.0"
    
    SEVERITY_MAP = {
        'critical': 10,
        'high': 8,
        'medium': 5,
        'low': 3,
        'informational': 1
    }
    
    def format(self, event: Dict) -> str:
        """Format event as CEF."""
        
        severity = self.SEVERITY_MAP.get(event.get('severity', 'medium'), 5)
        
        # Build extension fields
        extensions = []
        
        # Required CEF fields
        extensions.append(f"src={event.get('ip_address', event.get('dst_ip', ''))}")
        extensions.append(f"spt={event.get('src_port', 0)}")
        extensions.append(f"dst={event.get('dst_ip', '')}")
        extensions.append(f"dpt={event.get('dst_port', 0)}")
        
        # Additional fields
        if event.get('username'):
            extensions.append(f"suser={event.get('username')}")
        
        if event.get('attack_type'):
            extensions.append(f"cat={event.get('attack_type')}")
        
        if event.get('filename'):
            extensions.append(f"fname={event.get('filename')}")
        
        if event.get('path'):
            extensions.append(f"filePath={event.get('path')}")
        
        if event.get('mitre'):
            extensions.append(f"rt={','.join(event.get('mitre', []))}")
        
        extensions.append(f"cn1={event.get('threat_score', 0)}")
        
        extension_str = ' '.join(extensions)
        
        # CEF header
        cef = (
            f"CEF:0|{self.DEVICE_VENDOR}|{self.DEVICE_PRODUCT}|{self.DEVICE_VERSION}|"
            f"{event.get('rule_id', '0')}|{event.get('attack_type', 'Unknown')}|"
            f"{severity}|{extension_str}"
        )
        
        return cef


class SyslogFormatter(OutputFormatter):
    """
    Syslog format for direct SIEM forwarding.
    RFC 3164/5424 compatible.
    """
    
    FACILITY = "local0"
    PRIORITY_MAP = {
        'critical': 0,
        'high': 1,
        'medium': 3,
        'low': 5,
        'informational': 6
    }
    
    def format(self, event: Dict) -> str:
        """Format event as syslog."""
        
        priority = self.PRIORITY_MAP.get(event.get('severity', 'medium'), 4)
        timestamp = event.get('timestamp', datetime.now().strftime('%b %d %H:%M:%S'))
        hostname = event.get('hostname', 'lidra')
        
        # Structured data
        sd = f"[lidra@32473 attack_type=\"{event.get('attack_type', 'unknown')}\" "
        sd += f"severity=\"{event.get('severity', 'medium')}\" "
        sd += f"ip=\"{event.get('ip_address', '')}\"]"
        
        message = event.get('raw_line', event.get('message', f"Detection: {event.get('attack_type', 'unknown')}"))
        
        return f"<{priority}>{timestamp} {hostname} {sd} {message}"


class STIXFormatter(OutputFormatter):
    """
    STIX 2.1 format for threat intelligence sharing.
    """
    
    def format(self, event: Dict) -> Dict:
        """Format event as STIX bundle."""
        
        # Build STIX indicator
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{self._generate_id()}",
            "created": event.get('timestamp', datetime.now().isoformat()),
            "modified": datetime.now().isoformat(),
            "pattern": f"[ipv4-addr:value = '{event.get('ip_address', '')}']",
            "pattern_type": "stix",
            "valid_from": datetime.now().isoformat(),
            "indicator_types": ["malicious-activity"],
            "labels": ["lidra-detected"],
            "name": f"LIDRA Detection: {event.get('attack_type', 'unknown')}",
            "description": event.get('description', f"Detected {event.get('attack_type', 'attack')} by LIDRA"),
            "pattern": f"[ipv4-addr:value = '{event.get('ip_address', '')}']"
        }
        
        # Add MITRE if available
        if event.get('mitre'):
            indicator['external_references'] = [
                {
                    "source_name": "mitre-attack",
                    "url": f"https://attack.mitre.org/techniques/{t}"
                }
                for t in event.get('mitre', [])
            ]
        
        # Build bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{self._generate_id()}",
            "objects": [indicator]
        }
        
        return bundle
    
    def _generate_id(self) -> str:
        """Generate unique ID."""
        import uuid
        return str(uuid.uuid4())


class MultiFormatter(OutputFormatter):
    """Format to multiple outputs simultaneously."""
    
    def __init__(self, formatters: Dict[str, OutputFormatter] = None):
        if formatters is None:
            formatters = {
                'json': JSONFormatter(),
                'cef': CEFFormatter(),
                'syslog': SyslogFormatter()
            }
        self.formatters = formatters
    
    def add_formatter(self, name: str, formatter: OutputFormatter):
        """Add a formatter."""
        self.formatters[name] = formatter
    
    def format(self, event: Dict) -> Dict[str, str]:
        """Format event to all configured formats."""
        return {
            name: fmt.format(event)
            for name, fmt in self.formatters.items()
        }


def create_formatter(format_type: str, **kwargs) -> OutputFormatter:
    """Factory function to create formatter."""
    
    formatters = {
        'json': JSONFormatter,
        'cef': CEFFormatter,
        'syslog': SyslogFormatter,
        'stix': STIXFormatter
    }
    
    formatter_class = formatters.get(format_type.lower())
    
    if formatter_class is None:
        raise ValueError(f"Unknown format: {format_type}")
    
    return formatter_class(**kwargs)