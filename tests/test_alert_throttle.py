"""One alert per (attack_type, ip) per cooldown — no per-packet storms."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from utils.alert_throttle import AlertThrottle


def test_first_alert_fires():
    assert AlertThrottle(cooldown_seconds=900).allow("syn_burst", "1.2.3.4") is True


def test_repeat_within_cooldown_suppressed():
    t = AlertThrottle(cooldown_seconds=900)
    assert t.allow("syn_burst", "1.2.3.4") is True
    for _ in range(1300):  # one nmap run's worth of repeat SYNs
        assert t.allow("syn_burst", "1.2.3.4") is False


def test_different_attack_type_not_suppressed():
    t = AlertThrottle(cooldown_seconds=900)
    assert t.allow("port_scan", "1.2.3.4") is True
    assert t.allow("sql_injection", "1.2.3.4") is True


def test_different_ip_not_suppressed():
    t = AlertThrottle(cooldown_seconds=900)
    assert t.allow("port_scan", "1.2.3.4") is True
    assert t.allow("port_scan", "5.6.7.8") is True


def test_cooldown_expiry_refires():
    t = AlertThrottle(cooldown_seconds=1)
    assert t.allow("x", "y") is True
    assert t.allow("x", "y") is False
    time.sleep(1.1)
    assert t.allow("x", "y") is True
