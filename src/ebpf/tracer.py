"""
LIDRA v3 eBPF Tracer
Controls eBPF probe lifecycle and event collection
"""

import os
import sys
import logging
import threading
import time
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Callable
from dataclasses import dataclass, asdict
import yaml

logger = logging.getLogger(__name__)


def _get_config_list(key, default):
    cfg_path = Path(__file__).parent.parent.parent / "config" / "config.yaml"
    try:
        with open(cfg_path) as f:
            cfg = yaml.safe_load(f)
        return cfg.get(key, default)
    except Exception:
        return default


@dataclass
class SecurityEvent:
    """Normalized security event from eBPF."""
    timestamp: datetime
    event_type: str  # exec, connect, open, write, kill
    pid: int
    uid: int
    username: str = ""
    comm: str = ""
    filename: str = ""
    args: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    raw_data: Dict = None

    def __post_init__(self):
        if self.raw_data is None:
            self.raw_data = {}


class EBPFTracer:
    """
    Manages eBPF probe lifecycle.
    
    Falls back to log-based detection if eBPF unavailable.
    """
    
    EVENT_TYPES = {
        1: "exec",
        2: "connect", 
        3: "open",
        4: "write",
        5: "kill",
        6: "network"
    }
    
    SUSPICIOUS_PATHS = _get_config_list("suspicious_paths", [
        "/tmp/", "/var/tmp/", "/dev/shm/",
        "/proc/self/", "/.ssh/", "/.aws/",
    ])
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.bpf_module = None
        self.running = False
        self.callbacks: List[Callable] = []
        self._thread: Optional[threading.Thread] = None
        
        # Fallback mode
        self.fallback_mode = False
        self.fallback_source = "log"  # "log" or "none"
        
        # Check eBPF availability
        self._check_ebpf_availability()
    
    def _check_ebpf_availability(self):
        """Check if eBPF can be loaded."""
        try:
            from bcc import BPF
            
            # Check kernel support
            if os.path.exists("/sys/kernel/debug/tracing/events"):
                logger.info("eBPF: Kernel tracepoints available")
                self.fallback_mode = False
            else:
                logger.warning("eBPF: No kernel tracepoint support, using fallback")
                self.fallback_mode = True
                
        except ImportError:
            logger.warning("eBPF: BCC library not available, using fallback mode")
            self.fallback_mode = True
        except Exception as e:
            logger.warning(f"eBPF: Not available ({e}), using fallback mode")
            self.fallback_mode = True
    
    def register_callback(self, callback: Callable[[SecurityEvent], None]):
        """Register callback for security events."""
        self.callbacks.append(callback)
    
    def load(self) -> bool:
        """Load eBPF programs into kernel."""
        if self.fallback_mode:
            logger.info("Using fallback mode (log-based detection)")
            return True
            
        try:
            from bcc import BPF
            
            # Load eBPF source
            bpf_path = Path(__file__).parent / "probe.c"
            if not bpf_path.exists():
                logger.error(f"eBPF probe not found: {bpf_path}")
                self.fallback_mode = True
                return False
            
            # Build and load BPF module
            self.bpf_module = BPF(src_file=str(bpf_path))
            
            logger.info("eBPF probe loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load eBPF: {e}")
            self.fallback_mode = True
            return False
    
    def _process_event(self, cpu, data, size):
        """Process event from perf buffer."""
        try:
            # Parse event data based on CPU architecture
            event = self.bpf_module.perf_buffer[data]
            
            # Normalize event
            security_event = self._normalize_event(event)
            
            # Call registered callbacks
            for callback in self.callbacks:
                try:
                    callback(security_event)
                except Exception as e:
                    logger.error(f"Callback error: {e}")
                    
        except Exception as e:
            logger.error(f"Event processing error: {e}")
    
    def _normalize_event(self, raw_event) -> SecurityEvent:
        """Convert raw eBPF event to normalized SecurityEvent."""
        event_type = self.EVENT_TYPES.get(raw_event.event_type, "unknown")
        timestamp = datetime.fromtimestamp(raw_event.timestamp / 1e9)
        
        # Resolve UID to username
        username = self._resolve_uid(raw_event.uid)
        
        # Format IPs
        src_ip = self._format_ip(raw_event.src_ip, raw_event.ip_version)
        dst_ip = self._format_ip(raw_event.dst_ip, raw_event.ip_version)
        
        # Get protocol
        protocol = {6: "TCP", 17: "UDP"}.get(raw_event.protocol, "UNKNOWN")
        
        return SecurityEvent(
            timestamp=timestamp,
            event_type=event_type,
            pid=raw_event.pid,
            uid=raw_event.uid,
            username=username,
            comm=raw_event.comm.decode('utf-8', errors='replace') if raw_event.comm else "",
            filename=raw_event.filename.decode('utf-8', errors='replace') if raw_event.filename else "",
            args=raw_event.args.decode('utf-8', errors='replace') if raw_event.args else "",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=raw_event.src_port,
            dst_port=raw_event.dst_port,
            protocol=protocol,
            raw_data={
                'raw_comm': raw_event.comm,
                'raw_filename': raw_event.filename,
                'raw_args': raw_event.args,
            }
        )
    
    def _resolve_uid(self, uid: int) -> str:
        """Resolve UID to username."""
        try:
            import pwd
            return pwd.getpwuid(uid).pw_name
        except (KeyError, ImportError):
            return str(uid)
    
    def _format_ip(self, ip_bytes: bytes, version: int) -> str:
        """Format IP bytes to string."""
        if version == 4:
            return ".".join(str(b) for b in ip_bytes[:4])
        elif version == 6:
            # Simplified IPv6
            return ":".join(f"{b:02x}{ip_bytes[i+1]:02x}" for i, b in enumerate(ip_bytes[::2]) if i < 8)
        return ""
    
    def start(self):
        """Start event collection."""
        self.running = True
        
        if self.fallback_mode:
            logger.info("Starting fallback mode (log monitoring)")
            self._start_fallback()
            return
        
        if not self.bpf_module:
            logger.error("eBPF module not loaded")
            return
        
        # Open perf buffers for each event type
        try:
            self.bpf_module["events"].open_perf_buffer(self._process_event)
            
            # Start polling thread
            self._thread = threading.Thread(target=self._poll_events, daemon=True)
            self._thread.start()
            
            logger.info("eBPF event collection started")
            
        except Exception as e:
            logger.error(f"Failed to start eBPF collection: {e}")
            self.fallback_mode = True
            self._start_fallback()
    
    def _poll_events(self):
        """Poll for events from perf buffer."""
        while self.running:
            try:
                self.bpf_module.perf_buffer_poll(100)
            except Exception as e:
                if self.running:
                    logger.error(f"Poll error: {e}")
    
    def _start_fallback(self):
        """Start fallback log-based collection."""
        from detection.log_parser import LogParser
        from detection.attack_detector import AttackDetector
        
        log_sources = self.config.get('detection', {}).get('log_sources', 
            ['/var/log/auth.log', '/var/log/syslog'])
        
        self.fallback_parser = LogParser(log_sources)
        self.fallback_detector = AttackDetector()
        
        # Start monitoring thread
        self._thread = threading.Thread(target=self._fallback_monitor, daemon=True)
        self._thread.start()
        
        logger.info("Fallback mode: log monitoring started")
    
    def _fallback_monitor(self):
        """Fallback: monitor log files."""
        while self.running:
            try:
                for log_path in self.fallback_parser.log_sources:
                    for event in self.fallback_parser.get_live_events(log_path):
                        # Pass to detector
                        attacks = self.fallback_detector.analyze_event(event)
                        
                        for attack in attacks:
                            # Convert to SecurityEvent format
                            sec_event = SecurityEvent(
                                timestamp=attack.timestamp,
                                event_type=attack.attack_type,
                                pid=0,
                                uid=0,
                                username=attack.details.get('username', ''),
                                filename=attack.details.get('path', ''),
                                dst_ip=attack.ip_address,
                                raw_data={'attack': asdict(attack)}
                            )
                            
                            # Notify callbacks
                            for callback in self.callbacks:
                                callback(sec_event)
                                
            except Exception as e:
                logger.error(f"Fallback monitor error: {e}")
            
            time.sleep(1)
    
    def stop(self):
        """Stop event collection and unload eBPF."""
        self.running = False
        
        if self._thread:
            self._thread.join(timeout=2)
        
        if self.bpf_module:
            self.bpf_module.cleanup()
            logger.info("eBPF probe unloaded")
        
        logger.info("eBPF tracer stopped")
    
    def is_using_ebpf(self) -> bool:
        """Check if running with eBPF or fallback."""
        return not self.fallback_mode
    
    def get_status(self) -> Dict:
        """Get current tracer status."""
        return {
            'mode': 'ebpf' if not self.fallback_mode else 'fallback',
            'running': self.running,
            'source': 'kernel' if not self.fallback_mode else 'log_files'
        }


class EBPFDetector:
    """
    High-level detector that uses eBPF events.
    Maps raw events to attack types.
    """

    SUSPICIOUS_COMMANDS = _get_config_list("suspicious_commands", [
        'wget', 'curl', 'nc', 'ncat', 'netcat',
        'python', 'python3', 'perl', 'ruby',
        'bash', 'sh', 'zsh',
        'nohup', 'setsid', 'disown',
        'chmod', 'chown', 'chattr',
    ])

    SUSPICIOUS_EXTENSIONS = _get_config_list("suspicious_extensions", [
        '.php', '.phtml', '.phar', '.php5', '.php7',
        '.jsp', '.jspx', '.asp', '.aspx', '.exe',
        '.sh', '.bat', '.cmd', '.ps1',
    ])
    
    def __init__(self):
        pass
    
    def analyze(self, event: SecurityEvent) -> Optional[Dict]:
        """Analyze event and return detection result."""
        
        if event.event_type == "exec":
            return self._analyze_exec(event)
        
        elif event.event_type == "connect":
            return self._analyze_connect(event)
        
        elif event.event_type == "open":
            return self._analyze_open(event)
        
        elif event.event_type == "kill":
            return self._analyze_kill(event)
        
        return None
    
    def _analyze_exec(self, event: SecurityEvent) -> Optional[Dict]:
        """Analyze process execution for suspicious activity."""
        
        # Check for suspicious commands
        filename_lower = event.filename.lower()
        args_lower = event.args.lower()
        
        # Shell execution
        if '/bin/sh' in filename_lower or '/bin/bash' in filename_lower:
            # Check for reverse shell patterns
            if any(pattern in args_lower for pattern in ['/dev/tcp', 'bash -i', 'sh -i', 'nc -e', 'ncat']):
                return {
                    'attack_type': 'reverse_shell',
                    'severity': 'critical',
                    'mitre': ['T1059', 'T1053'],
                    'details': {
                        'pid': event.pid,
                        'command': event.args[:200],
                        'suspicious_pattern': 'reverse_shell_indicator'
                    }
                }
            
            # Check for download + execute patterns
            if any(x in args_lower for x in ['wget', 'curl']) and any(x in args_lower for x in ['|sh', '|bash', '>']):
                return {
                    'attack_type': 'download_execute',
                    'severity': 'high',
                    'mitre': ['T1059', 'T1105'],
                    'details': {
                        'pid': event.pid,
                        'command': event.args[:200]
                    }
                }
            
            # Privilege escalation via sudo
            if 'sudo' in args_lower and event.uid != 0:
                return {
                    'attack_type': 'privilege_escalation_attempt',
                    'severity': 'medium',
                    'mitre': ['T1548'],
                    'details': {
                        'pid': event.pid,
                        'target_uid': event.uid
                    }
                }
        
        # Reverse shell via nc
        if 'nc' in filename_lower or 'ncat' in filename_lower:
            if '-e' in args_lower or '--exec' in args_lower:
                return {
                    'attack_type': 'reverse_shell',
                    'severity': 'critical',
                    'mitre': ['T1059', 'T1053'],
                    'details': {'pid': event.pid}
                }
        
        # Python reverse shell
        if 'python' in filename_lower or 'python3' in filename_lower:
            if any(x in args_lower for x in ['socket', 'subprocess', 'os.system', 'pty.spawn']):
                return {
                    'attack_type': 'reverse_shell',
                    'severity': 'high',
                    'mitre': ['T1059'],
                    'details': {'pid': event.pid}
                }
        
        return None
    
    def _analyze_connect(self, event: SecurityEvent) -> Optional[Dict]:
        """Analyze network connections."""
        
        # Known malicious ports
        if event.dst_port in {4444, 5555, 31337, 1337, 6667}:
            return {
                'attack_type': 'suspicious_connection',
                'severity': 'high',
                'mitre': ['T1071', 'T1573'],
                'details': {
                    'dst_ip': event.dst_ip,
                    'dst_port': event.dst_port,
                }
            }
        
        # Non-standard high ports (potential C2)
        if event.dst_port > 10000 and event.protocol == "TCP":
            # Could be C2 - needs baseline context
            return {
                'attack_type': 'high_port_connection',
                'severity': 'medium',
                'mitre': ['T1573'],
                'details': {
                    'dst_ip': event.dst_ip,
                    'dst_port': event.dst_port
                }
            }
        
        # SSH to unusual destinations
        if event.dst_port == 22 and event.dst_ip:
            return {
                'attack_type': 'external_ssh',
                'severity': 'low',
                'mitre': ['T1021'],
                'details': {
                    'dst_ip': event.dst_ip
                }
            }
        
        return None
    
    def _analyze_open(self, event: SecurityEvent) -> Optional[Dict]:
        """Analyze file access."""
        
        path_lower = event.filename.lower()
        
        # Sensitive file access
        sensitive_patterns = {
            '/etc/passwd': 'credential_access',
            '/etc/shadow': 'credential_access',
            '/.ssh/': 'credential_access',
            '/.aws/': 'credential_access',
            '/var/log/': 'log_tampering',
            '/proc/self/': 'process_memory_access',
        }
        
        for pattern, attack_type in sensitive_patterns.items():
            if pattern in path_lower:
                return {
                    'attack_type': attack_type,
                    'severity': 'high' if 'shadow' in pattern else 'medium',
                    'mitre': ['T1005', 'T1070'],
                    'details': {
                        'filename': event.filename,
                        'pid': event.pid
                    }
                }
        
        # Webshell patterns in web directories
        web_dirs = ['/var/www/', '/home/*/public_html', '/srv/http']
        for web_dir in web_dirs:
            if web_dir.replace('*', '') in path_lower:
                for ext in self.SUSPICIOUS_EXTENSIONS:
                    if ext in path_lower:
                        return {
                            'attack_type': 'webshell_creation',
                            'severity': 'critical',
                            'mitre': ['T1505'],
                            'details': {
                                'filename': event.filename,
                                'pid': event.pid
                            }
                        }
        
        return None
    
    def _analyze_kill(self, event: SecurityEvent) -> Optional[Dict]:
        """Analyze process termination (kill)."""
        
        return {
            'attack_type': 'process_termination',
            'severity': 'low',
            'mitre': ['T1489'],
            'details': {
                'target_pid': event.raw_data.get('ret', 0),
                'killer_pid': event.pid
            }
        }


def create_tracer(config: dict = None) -> EBPFTracer:
    """Factory function to create appropriate tracer."""
    tracer = EBPFTracer(config)
    return tracer