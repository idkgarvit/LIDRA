#!/usr/bin/env python3
"""
LIDRA v2 - Production-Grade Intrusion Detection System

Lightweight Intrusion Detection and Response with Adaptive Deception

Detects ALL types of server-based attacks:
- SSH: Bruteforce, invalid users, connection floods
- Web: SQL injection, XSS, path traversal, LFI/RFI, command injection
- Database: MySQL, PostgreSQL, MongoDB, Redis unauthorized access
- Email: SMTP, IMAP, POP3 brute force
- FTP: Login failures
- Network: Port scans, service probes
- Exploit: Shellshock, Log4j, CVE signatures
- Privilege: sudo/su failures
"""

import sys
import time
import logging
import threading
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

# Import LIDRA components
from database.db import LIDRADatabase
from intel.threat_intel import ThreatIntelOrchestrator
from intel.abuseipdb import AbuseIPDBProvider
from intel.virustotal import VirusTotalProvider
from alerts.notifier import Alert, AlertNotifier
from alerts.slack import SlackChannel
from alerts.discord import DiscordChannel
from response.firewall import FirewallManager
from detection.log_parser import LogParser
from detection.attack_detector import AttackDetector

import yaml

# Configure logging
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "lidra.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("LIDRA")

BASE = Path(__file__).parent.parent
CFG = BASE / "config" / "config.yaml"


def load_config():
    """Load configuration from YAML file."""
    if not CFG.exists():
        logger.error(f"Config not found: {CFG}")
        sys.exit(1)
    with open(CFG) as f:
        return yaml.safe_load(f)


class LIDRAv2:
    """Main LIDRA v2 orchestrator."""

    def __init__(self, config: dict):
        self.config = config
        self.running = False

        # Initialize components
        logger.info("Initializing LIDRA v2 components...")

        # Database
        db_path = BASE / config.get('database', {}).get('path', 'data/lidra.db')
        self.db = LIDRADatabase(str(db_path))
        logger.info(f"Database initialized: {db_path}")

        # Threat Intelligence
        providers = []
        abuse_key = config.get('threat_intel', {}).get('abuseipdb_api_key', '')
        vt_key = config.get('threat_intel', {}).get('virustotal_api_key', '')

        if abuse_key:
            providers.append(AbuseIPDBProvider(abuse_key))
            logger.info("AbuseIPDB integration enabled")
        else:
            logger.warning("AbuseIPDB API key not configured")

        if vt_key:
            providers.append(VirusTotalProvider(vt_key))
            logger.info("VirusTotal integration enabled")
        else:
            logger.warning("VirusTotal API key not configured")

        self.threat_intel = ThreatIntelOrchestrator(
            providers,
            check_on_detect=config.get('threat_intel', {}).get('check_on_detect', True)
        )

        # Alerting
        channels = []
        slack_webhook = config.get('alerts', {}).get('slack_webhook', '')
        discord_webhook = config.get('alerts', {}).get('discord_webhook', '')

        if slack_webhook:
            channels.append(SlackChannel(slack_webhook))
            logger.info("Slack alerting enabled")
        else:
            logger.info("Slack alerting disabled (no webhook)")

        if discord_webhook:
            channels.append(DiscordChannel(discord_webhook))
            logger.info("Discord alerting enabled")
        else:
            logger.info("Discord alerting disabled (no webhook)")

        self.notifier = AlertNotifier(channels)

        # Firewall/Response
        self.firewall = FirewallManager(
            backend=config.get('response', {}).get('firewall', 'iptables'),
            dry_run=config.get('response', {}).get('dry_run', True)
        )
        logger.info(f"Firewall initialized (dry_run={self.firewall.dry_run})")

        # Detection
        log_sources = config.get('detection', {}).get('log_sources', ['/var/log/auth.log'])
        self.log_parser = LogParser(log_sources)
        self.attack_detector = AttackDetector(str(BASE / "config" / "config.yaml"))
        logger.info(f"Detection initialized for {len(log_sources)} log sources")

        # Dashboard (started separately)
        self.dashboard_thread = None

    def start_dashboard(self):
        """Start web dashboard in background thread."""
        try:
            from dashboard.main import app
            import uvicorn

            def run_dashboard():
                uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning")

            self.dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
            self.dashboard_thread.start()
            logger.info("Dashboard available at http://0.0.0.0:8080")
        except Exception as e:
            logger.warning(f"Dashboard not started: {e}")

    def detection_cycle(self):
        """Run one detection cycle."""
        logger.debug("Running detection cycle...")

        log_sources = self.config.get('detection', {}).get('log_sources', ['/var/log/auth.log'])

        for log_path_str in log_sources:
            log_path = Path(log_path_str)
            if not log_path.exists():
                continue

            for event in self.log_parser.parse_file(log_path):
                attacks = self.attack_detector.analyze_event(event)

                for attack in attacks:
                    # Enrich with threat intel
                    intel = self.threat_intel.lookup_ip(attack.ip_address)
                    attack.details['threat_intel'] = intel

                    # Record in database
                    attacker_id = self.db.add_attacker(
                        attack.ip_address,
                        country=intel.get('details', {}).get('AbuseIPDB', {}).get('country'),
                        org=intel.get('details', {}).get('AbuseIPDB', {}).get('isp')
                    )

                    self.db.record_attack(
                        attacker_id,
                        attack.attack_type,
                        source_log=event.source,
                        raw_line=event.raw_line
                    )

                    # Alert if high severity and rate limit not exceeded
                    if attack.severity in ('high', 'critical') and self.attack_detector.should_alert(attack):
                        alert = Alert(
                            alert_type=attack.attack_type,
                            severity=attack.severity,
                            ip_address=attack.ip_address,
                            message=f"{attack.attack_type} detected from {attack.ip_address} (threat score: {intel.get('threat_score', 0)})"
                        )
                        self.notifier.notify(alert)
                        self.db.add_alert(
                            attack.attack_type,
                            attack.severity,
                            attack.ip_address,
                            alert.message
                        )

                    # Block if configured
                    if not self.config.get('response', {}).get('dry_run', True):
                        if intel.get('is_malicious') or intel.get('threat_score', 0) >= 50:
                            block_id = self.db.add_block(
                                attack.ip_address,
                                f"Auto-detected: {attack.attack_type}",
                                self.config.get('response', {}).get('block_ttl_seconds', 3600)
                            )
                            self.firewall.block_ip(
                                attack.ip_address,
                                self.config.get('response', {}).get('block_ttl_seconds', 3600)
                            )
                            self.db.mark_block_applied(block_id)

                            # Report to AbuseIPDB
                            if self.config.get('threat_intel', {}).get('auto_report', False):
                                self.threat_intel.report_ip(
                                    attack.ip_address,
                                    category=18,
                                    comment=f"LIDRA IDS detected {attack.attack_type}"
                                )

    def run(self):
        """Main run loop."""
        self.running = True
        sleep_time = 60 if self.config.get('mode') == 'development' else 300

        logger.info("=" * 60)
        logger.info("LIDRA v2 - Production IDS Starting")
        logger.info("=" * 60)
        logger.info(f"Mode: {self.config.get('mode')}")
        logger.info(f"Cycle interval: {sleep_time}s")
        logger.info(f"Detection sources: {len(self.config.get('detection', {}).get('log_sources', []))} logs")
        logger.info(f"Blocking: {'Enabled' if not self.config.get('response', {}).get('dry_run', True) else 'Demo mode'}")

        # Start dashboard
        self.start_dashboard()

        try:
            while self.running:
                self.detection_cycle()

                # Daily cleanup at 3 AM
                if datetime.now().hour == 3:
                    cleanup_days = self.config.get('database', {}).get('cleanup_days', 30)
                    self.db.cleanup_old_data(cleanup_days)
                    logger.info("Daily cleanup completed")

                logger.debug(f"Cycle complete. Sleeping {sleep_time}s...")
                time.sleep(sleep_time)

        except KeyboardInterrupt:
            logger.info("LIDRA stopped by user")
        finally:
            self.running = False
            self.db.close()
            logger.info("LIDRA shutdown complete")

    def stop(self):
        """Stop LIDRA."""
        self.running = False


def main():
    """Entry point."""
    # Ensure directories exist
    (BASE / "data").mkdir(exist_ok=True)
    (BASE / "logs").mkdir(exist_ok=True)
    (BASE / "state").mkdir(exist_ok=True)

    config = load_config()
    lidra = LIDRAv2(config)
    lidra.run()


if __name__ == "__main__":
    main()
