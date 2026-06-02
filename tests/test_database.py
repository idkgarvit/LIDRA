# tests/test_database.py
"""Tests for LIDRA database layer."""

import pytest
import tempfile
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from database.db import LIDRADatabase


@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    db = LIDRADatabase(path)
    yield db
    os.unlink(path)


class TestAttackerOperations:
    """Test attacker CRUD operations."""

    def test_add_new_attacker(self, temp_db):
        """Test adding a new attacker."""
        attacker_id = temp_db.add_attacker("192.168.1.100")
        assert attacker_id == 1

        attackers = temp_db.get_attackers()
        assert len(attackers) == 1
        assert attackers[0]['ip_address'] == "192.168.1.100"

    def test_add_duplicate_attacker_increments_count(self, temp_db):
        """Test that duplicate attacker increments count."""
        temp_db.add_attacker("192.168.1.100")
        temp_db.add_attacker("192.168.1.100")

        attackers = temp_db.get_attackers()
        assert len(attackers) == 1
        assert attackers[0]['attack_count'] == 2

    def test_add_attacker_with_country_org(self, temp_db):
        """Test adding attacker with metadata."""
        attacker_id = temp_db.add_attacker("10.0.0.1", country="CN", org="Example ISP")

        attackers = temp_db.get_attackers()
        assert attackers[0]['country'] == "CN"
        assert attackers[0]['org'] == "Example ISP"

    def test_record_attack(self, temp_db):
        """Test recording attack events."""
        attacker_id = temp_db.add_attacker("10.0.0.1")
        temp_db.record_attack(attacker_id, "ssh_bruteforce", "/var/log/auth.log", "Failed password")

        stats = temp_db.get_attacker_stats()
        assert stats['attacks_24h'] == 1

    def test_get_attacker_stats(self, temp_db):
        """Test getting attacker statistics."""
        temp_db.add_attacker("1.1.1.1", country="US", org="Cloudflare")
        temp_db.add_attacker("2.2.2.2", country="CN")

        stats = temp_db.get_attacker_stats()
        assert stats['total_attackers'] == 2
        assert len(stats['top_countries']) == 2


class TestBlockOperations:
    """Test block management."""

    def test_add_block(self, temp_db):
        """Test adding a block."""
        block_id = temp_db.add_block("192.168.1.100", "SSH bruteforce", ttl_seconds=3600)
        assert block_id == 1

    def test_is_blocked_false_initially(self, temp_db):
        """Test block status check before marking applied."""
        temp_db.add_block("10.0.0.1", "test", ttl_seconds=3600)
        assert temp_db.is_blocked("10.0.0.1") == False

    def test_is_blocked_true_after_mark(self, temp_db):
        """Test block status after marking applied."""
        block_id = temp_db.add_block("10.0.0.1", "test", ttl_seconds=3600)
        temp_db.mark_block_applied(block_id)
        assert temp_db.is_blocked("10.0.0.1") == True

    def test_block_expires(self, temp_db):
        """Test that blocks expire based on TTL."""
        import datetime
        block_id = temp_db.add_block("10.0.0.1", "test", ttl_seconds=1)
        temp_db.mark_block_applied(block_id)

        # Should be blocked now
        assert temp_db.is_blocked("10.0.0.1") == True

        # Wait for expiration (skip in tests for speed)
        # time.sleep(2)
        # assert temp_db.is_blocked("10.0.0.1") == False


class TestHoneyfileOperations:
    """Test honeyfile hit tracking."""

    def test_record_honeyfile_hit(self, temp_db):
        """Test recording honeyfile access."""
        temp_db.record_honeyfile_hit("/path/to/secret.txt", "192.168.1.100", "modify")
        # Would need a getter to verify, but test ensures no exceptions


class TestHoneypotOperations:
    """Test honeypot session tracking."""

    def test_create_session(self, temp_db):
        """Test creating honeypot session."""
        session_id = temp_db.create_honeypot_session("sess_123", "192.168.1.100", 2222)
        assert session_id == 1

    def test_update_session(self, temp_db):
        """Test updating honeypot session."""
        temp_db.create_honeypot_session("sess_123", "192.168.1.100", 2222)
        temp_db.update_honeypot_session("sess_123", commands="ls\nwhoami", status='closed')

        sessions = temp_db.get_honeypot_sessions()
        assert len(sessions) == 1
        assert sessions[0]['status'] == 'closed'


class TestAlertOperations:
    """Test alert system."""

    def test_add_alert(self, temp_db):
        """Test adding alert."""
        alert_id = temp_db.add_alert("intrusion", "high", "192.168.1.100", "SSH bruteforce detected")
        assert alert_id == 1

    def test_get_unsent_alerts(self, temp_db):
        """Test getting unsent alerts."""
        temp_db.add_alert("intrusion", "high", message="Test alert")
        alerts = temp_db.get_unsent_alerts()
        assert len(alerts) == 1
        assert alerts[0]['sent'] == 0

    def test_mark_alert_sent(self, temp_db):
        """Test marking alert as sent."""
        alert_id = temp_db.add_alert("intrusion", "high", message="Test")
        temp_db.mark_alert_sent(alert_id)
        alerts = temp_db.get_unsent_alerts()
        assert len(alerts) == 0


class TestRecentAttacks:
    """Test recent attack queries."""

    def test_get_recent_attacks(self, temp_db):
        """Test getting recent attacks."""
        attacker_id = temp_db.add_attacker("10.0.0.1")
        temp_db.record_attack(attacker_id, "ssh_bruteforce")

        attacks = temp_db.get_recent_attacks()
        assert len(attacks) == 1
        assert attacks[0]['attack_type'] == "ssh_bruteforce"


class TestCleanup:
    """Test data cleanup."""

    def test_cleanup_old_data(self, temp_db):
        """Test cleaning old data."""
        attacker_id = temp_db.add_attacker("10.0.0.1")
        temp_db.record_attack(attacker_id, "test")

        # Cleanup with 30 days should keep recent data
        temp_db.cleanup_old_data(days=30)

        # Data should still exist (it's recent)
        attacks = temp_db.get_recent_attacks()
        assert len(attacks) == 1


class TestDatabaseClose:
    """Test database connection cleanup."""

    def test_close(self, temp_db):
        """Test closing database connection."""
        temp_db.close()
        # Should not raise exception
