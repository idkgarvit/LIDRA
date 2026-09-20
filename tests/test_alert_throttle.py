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


def test_first_alert_fires_on_a_freshly_booted_machine(monkeypatch):
    """Regression: the never-seen sentinel was 0, but time.monotonic() is
    seconds-since-BOOT on Linux. For the first `cooldown` seconds of uptime,
    ``now - 0 < cooldown``, so a genuinely first-ever alert was suppressed —
    LIDRA was silent for the first 15 minutes after every reboot (and
    LIDRADatabase, which reuses this class for record dedupe with a 60 s
    cooldown, dropped attack rows for the first minute).

    Simulated rather than slept: the bug only reproduces when uptime < cooldown,
    which a long-running CI box never reaches.
    """
    monkeypatch.setattr(time, "monotonic", lambda: 5.0)
    t = AlertThrottle(cooldown_seconds=900)
    assert t.allow("syn_burst", "1.2.3.4") is True, (
        "a first-ever alert was suppressed on a freshly booted machine"
    )
    # and the throttle still throttles
    assert t.allow("syn_burst", "1.2.3.4") is False
    assert t.allow("port_scan", "1.2.3.4") is True


def test_zero_cooldown_always_fires(monkeypatch):
    """A 0 s cooldown (used by tests and by callers that want no dedupe) must
    never suppress the first sighting."""
    monkeypatch.setattr(time, "monotonic", lambda: 1.0)
    t = AlertThrottle(cooldown_seconds=0)
    assert t.allow("a", "b") is True
    assert t.allow("a", "b") is True
