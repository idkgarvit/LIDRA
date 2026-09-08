# tests/test_detection.py
"""Tests for LIDRA detection engine."""

from pathlib import Path
import sys
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from detection.log_parser import LogParser, LogEvent
from detection.attack_detector import AttackDetector, AttackConfig, DetectedAttack


class TestLogParserSSH:
    """Test SSH log parsing."""

    def test_parse_ssh_failed_password(self):
        """Test parsing SSH failed password line."""
        parser = LogParser([])
        line = "Jan 15 10:30:45 server sshd[12345]: Failed password for admin from 192.168.1.100 port 22 ssh2"

        event = parser.parse_line(line, 'auth.log')

        assert event is not None
        assert event.ip_address == "192.168.1.100"
        assert event.username == "admin"
        assert event.port == 22
        assert event.log_type == "ssh_failed"

    def test_parse_ssh_invalid_user(self):
        """Test parsing SSH invalid user line."""
        parser = LogParser([])
        line = "Jan 15 10:30:45 server sshd[12345]: Invalid user root from 10.0.0.1"

        event = parser.parse_line(line, 'auth.log')

        assert event is not None
        assert event.ip_address == "10.0.0.1"
        assert event.username == "root"
        assert event.log_type == "ssh_invalid_user"

    def test_parse_empty_line(self):
        """Test parsing empty line."""
        parser = LogParser([])
        event = parser.parse_line("", 'auth.log')
        assert event is None

    def test_parse_unrelated_line(self):
        """Test parsing unrelated log line."""
        parser = LogParser([])
        line = "Jan 15 10:30:45 server systemd[1]: Started Daily apt activities."

        event = parser.parse_line(line, 'syslog')
        # Should return None for unrecognized formats
        assert event is None


class TestLogParserWeb:
    """Test web log parsing."""

    def test_parse_apache_combined(self):
        """Test parsing Apache combined log format."""
        parser = LogParser([])
        line = '192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /admin HTTP/1.1" 404 1234 "-" "Mozilla/5.0"'

        event = parser.parse_line(line, 'access.log')

        assert event is not None
        assert event.ip_address == "192.168.1.100"
        assert event.method == "GET"
        assert event.path == "/admin"
        assert event.status_code == 404
        assert event.user_agent == "Mozilla/5.0"


class TestLogParserWebAttacks:
    """Test web attack detection."""

    def test_detect_sql_injection(self):
        """Test SQL injection detection."""
        parser = LogParser([])
        line = '192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /search?q=1\' OR \'1\'=\'1 HTTP/1.1" 200 1234 "-" "sqlmap/1.0"'

        event = parser.parse_line(line, 'access.log')

        assert event is not None
        assert 'sql_injection' in event.log_type

    def test_detect_path_traversal(self):
        """Test path traversal detection."""
        parser = LogParser([])
        line = '192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /../../etc/passwd HTTP/1.1" 400 1234 "-" "curl/7.68"'

        event = parser.parse_line(line, 'access.log')

        assert event is not None
        assert 'path_traversal' in event.log_type

    def test_detect_xss(self):
        """Test XSS detection."""
        parser = LogParser([])
        line = '192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'

        event = parser.parse_line(line, 'access.log')

        assert event is not None
        assert 'xss' in event.log_type

    def test_detect_scanner(self):
        """Test security scanner detection."""
        parser = LogParser([])
        line = '192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET / HTTP/1.1" 200 1234 "-" "Nikto/2.1.6"'

        event = parser.parse_line(line, 'access.log')

        assert event is not None
        assert 'scanner' in event.log_type

    def test_detect_admin_probe(self):
        """Test admin panel probe detection."""
        parser = LogParser([])
        line = '192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /wp-admin HTTP/1.1" 404 1234 "-" "Mozilla/5.0"'

        event = parser.parse_line(line, 'access.log')

        assert event is not None
        assert 'admin_probe' in event.log_type


class TestAttackDetector:
    """Test attack detector."""

    def test_detector_initialization(self):
        """Test detector initializes correctly."""
        detector = AttackDetector()
        assert detector.config is not None

    def test_ssh_bruteforce_detection(self):
        """Test SSH bruteforce detection."""
        detector = AttackDetector()
        now = datetime.now()

        # Simulate failed SSH attempts
        for i in range(5):
            event = LogEvent(
                timestamp=now,
                source='auth.log',
                log_type='ssh_failed',
                raw_line=f"Failed password from 192.168.1.100",
                ip_address="192.168.1.100",
                username="admin",
                port=22
            )
            attacks = detector.analyze_event(event)

        # Should detect after threshold
        assert len(attacks) > 0
        assert attacks[0].attack_type == "ssh_bruteforce"
        assert attacks[0].severity == "high"

    def test_attack_severity(self):
        """Test attack severity assignment."""
        detector = AttackDetector()
        now = datetime.now()

        event = LogEvent(
            timestamp=now,
            source='access.log',
            log_type='web_sql_injection',
            raw_line="GET /search?q=' OR 1=1--",
            ip_address="10.0.0.1",
            path="/search"
        )

        attacks = detector.analyze_event(event)
        assert len(attacks) > 0
        assert attacks[0].severity == "critical"

    def test_known_attacker_tracking(self):
        """Test known attacker IP tracking."""
        detector = AttackDetector()
        now = datetime.now()

        event = LogEvent(
            timestamp=now,
            source='auth.log',
            log_type='ssh_failed',
            raw_line="Failed password",
            ip_address="192.168.1.100"
        )

        # Generate enough events for detection
        for _ in range(5):
            detector.analyze_event(event)

        assert detector.is_known_attacker("192.168.1.100")

    def test_threat_score_calculation(self):
        """Test threat score calculation."""
        detector = AttackDetector()

        # Initial score should be 0 for unknown IP
        score = detector.get_threat_score("10.0.0.1")
        assert score == 0


class TestAttackTypes:
    """Test all attack type definitions."""

    def test_all_attack_types_have_severity(self):
        """Test that all attack types have severity defined."""
        detector = AttackDetector()

        for attack_type, info in detector.ATTACK_TYPES.items():
            assert 'severity' in info
            assert info['severity'] in ['low', 'medium', 'high', 'critical']

    def test_all_attack_types_have_category(self):
        """Test that all attack types have category defined."""
        detector = AttackDetector()

        for attack_type, info in detector.ATTACK_TYPES.items():
            assert 'category' in info
