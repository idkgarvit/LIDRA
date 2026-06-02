#!/usr/bin/env python3
"""
LIDRA v3 Comprehensive Test Suite
Tests all detection capabilities
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from detection.log_parser import LogParser
from detection.attack_detector import AttackDetector
from detection.mitre import MITREMapper
from detection.ml.anomaly import AnomalyDetector
from detection.explainer import AttackExplainer


def test_ssh_detection():
    """Test SSH attack detection."""
    print("\n" + "=" * 60)
    print("TEST: SSH Attack Detection")
    print("=" * 60)
    
    parser = LogParser([])
    detector = AttackDetector('config/config.yaml')
    
    # SSH Brute Force
    print("\n[1] SSH Brute Force Detection")
    for i in range(6):
        line = f'Jan 15 10:30:{40+i} server sshd[12345]: Failed password for admin from 192.168.1.100 port 22 ssh2'
        event = parser.parse_line(line, 'auth.log')
        if event:
            attacks = detector.analyze_event(event)
            if attacks:
                for a in attacks:
                    print(f"  ✓ DETECTED: {a.attack_type} (severity: {a.severity})")
    
    # SSH Invalid User
    print("\n[2] SSH Invalid User Detection")
    detector2 = AttackDetector('config/config.yaml')
    for i in range(3):
        line = f'Jan 15 10:30:45 server sshd[12345]: Invalid user root from 192.168.1.200'
        event = parser.parse_line(line, 'auth.log')
        if event:
            attacks = detector2.analyze_event(event)
            for a in attacks:
                print(f"  ✓ DETECTED: {a.attack_type} (severity: {a.severity})")


def test_web_detection():
    """Test web attack detection."""
    print("\n" + "=" * 60)
    print("TEST: Web Attack Detection")
    print("=" * 60)
    
    parser = LogParser([])
    detector = AttackDetector('config/config.yaml')
    
    web_attacks = [
        ('SQL Injection', 'GET /search?q=1\' OR \'1\'=\'1'),
        ('XSS', 'GET /search?q=<script>alert(1)</script>'),
        ('Path Traversal', 'GET /../../etc/passwd'),
        ('Command Injection', 'GET /shell?cmd=;ls'),
        ('Admin Panel', 'GET /wp-admin'),
        ('PHPMyAdmin', 'GET /phpmyadmin'),
    ]
    
    for name, path in web_attacks:
        line = f'192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "POST {path} HTTP/1.1" 404 1234 "-" "Mozilla/5.0"'
        event = parser.parse_line(line, 'access.log')
        if event:
            attacks = detector.analyze_event(event)
            if attacks:
                for a in attacks:
                    print(f"  ✓ {name}: {a.attack_type} ({a.severity})")
            else:
                print(f"  ~ {name}: No attack detected (log type: {event.log_type})")


def test_mitre_mapping():
    """Test MITRE ATT&CK mapping."""
    print("\n" + "=" * 60)
    print("TEST: MITRE ATT&CK Mapping")
    print("=" * 60)
    
    mitre = MITREMapper()
    
    # Test known mappings
    test_cases = [
        ('ssh_bruteforce', ['T1110', 'T1078']),
        ('sql_injection', ['T1190', 'T1059']),
        ('reverse_shell', ['T1059', 'T1053']),
        ('webshell', ['T1505', 'T1059']),
    ]
    
    for attack_type, expected in test_cases:
        techniques = mitre.get_techniques(attack_type)
        match = "✓" if techniques == expected else "✗"
        print(f"  {match} {attack_type}: {techniques}")
    
    # Coverage report
    report = mitre.get_coverage_report()
    print(f"\n  Coverage: {report['total_techniques']} techniques, {report['coverage_percentage']}% of ATT&CK")


def test_ml_anomaly():
    """Test ML anomaly detection."""
    print("\n" + "=" * 60)
    print("TEST: ML Anomaly Detection")
    print("=" * 60)
    
    ml = AnomalyDetector()
    
    # Learn baseline
    ml.learn_baseline('user1', 'logins', [1, 2, 1, 2, 3, 1, 2, 1, 2, 2])
    print("  ✓ Baseline learned")
    
    # Normal behavior
    result = ml.detect('user1', 'logins', 3)
    print(f"  ~ Normal value (3): anomaly={result.is_anomaly if result else 'N/A'}")
    
    # Anomaly - very high
    result = ml.detect('user1', 'logins', 15)
    if result:
        print(f"  ✓ Anomaly detected: {result.severity} (z-score: {result.z_score:.1f})")
        print(f"    Explanation: {result.explanation}")


def test_explainer():
    """Test attack explainer."""
    print("\n" + "=" * 60)
    print("TEST: Attack Explainer")
    print("=" * 60)
    
    explainer = AttackExplainer()
    
    detection = {
        'attack_type': 'ssh_bruteforce',
        'severity': 'high',
        'mitre': ['T1110', 'T1078'],
        'details': {
            'dst_ip': '192.168.1.100',
            'count': 10,
            'username': 'admin'
        }
    }
    
    explanation = explainer.explain(detection, {})
    print("  ✓ Explanation generated")
    print("\n" + explanation[:500] + "...")


def test_database():
    """Test database storage."""
    print("\n" + "=" * 60)
    print("TEST: Database Operations")
    print("=" * 60)
    
    from database.db import LIDRADatabase
    
    db = LIDRADatabase('/tmp/test_lidra.db')
    
    # Add attacker
    attacker_id = db.add_attacker('192.168.1.100', 'US', 'TestOrg')
    print(f"  ✓ Attacker added: ID {attacker_id}")
    
    # Record attack
    db.record_attack(attacker_id, 'ssh_bruteforce', 'auth.log', 'test')
    print(f"  ✓ Attack recorded")
    
    # Get attackers
    attackers = db.get_attackers(limit=5)
    print(f"  ✓ Retrieved {len(attackers)} attackers")


def main():
    print("\n" + "#" * 60)
    print("# LIDRA v3 Comprehensive Test Suite")
    print("#" * 60)
    
    test_ssh_detection()
    test_web_detection()
    test_mitre_mapping()
    test_ml_anomaly()
    test_explainer()
    test_database()
    
    print("\n" + "=" * 60)
    print("ALL TESTS COMPLETE")
    print("=" * 60)


if __name__ == '__main__':
    main()