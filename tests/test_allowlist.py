"""Tests for FP allowlist."""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from utils.allowlist import (
    build_allowlist, should_suppress, Allowlist,
    CLOUDFLARE_RANGES_V4, PRIVATE_RANGES_V4,
)


def test_cloudflare_ip_suppressed_for_timing_evasion():
    al = build_allowlist()
    suppress, reason = al.is_allowed("172.64.1.1")
    assert suppress is True
    assert reason == "cloudflare"


def test_google_dns_not_suppressed_by_default():
    al = build_allowlist()
    suppress, reason = al.is_allowed("8.8.8.8")
    assert suppress is False


def test_google_dns_suppressed_when_enabled():
    al = build_allowlist({"allowlist": {"include_google": True, "suppress_google": True}})
    suppress, reason = al.is_allowed("8.8.8.8")
    assert suppress is True


def test_private_ip_suppressed():
    al = build_allowlist()
    suppress, reason = al.is_allowed("192.168.1.100")
    assert suppress is True
    assert reason == "private"


def test_rfc1918_10_block():
    al = build_allowlist()
    suppress, reason = al.is_allowed("10.5.5.5")
    assert suppress is True


def test_loopback_suppressed():
    al = build_allowlist()
    suppress, reason = al.is_allowed("127.0.0.1")
    assert suppress is True


def test_random_public_ip_not_suppressed():
    al = build_allowlist()
    suppress, _ = al.is_allowed("203.0.113.42")
    assert suppress is False


def test_empty_ip_not_suppressed():
    al = build_allowlist()
    suppress, _ = al.is_allowed("")
    assert suppress is False


def test_unknown_placeholder_not_suppressed():
    al = build_allowlist()
    suppress, _ = al.is_allowed("unknown")
    assert suppress is False


def test_invalid_ip_returns_false():
    al = build_allowlist()
    suppress, _ = al.is_allowed("not.an.ip")
    assert suppress is False


def test_disabled_allowlist_returns_false():
    al = build_allowlist({"allowlist": {"enabled": False}})
    suppress, _ = al.is_allowed("172.64.1.1")
    assert suppress is False


def test_custom_trusted_cidr():
    al = build_allowlist({"allowlist": {"trusted_cidrs": ["203.0.113.0/24"]}})
    suppress, _ = al.is_allowed("203.0.113.5")
    assert suppress is True


def test_cidr_bare_ip_treated_as_host():
    al = build_allowlist({"allowlist": {"trusted_cidrs": ["198.51.100.42"]}})
    assert al.is_allowed("198.51.100.42")[0] is True
    assert al.is_allowed("198.51.100.43")[0] is False


def test_cidr_various_prefix_lengths():
    for cidr, match, miss in [
        ("203.0.113.0/24", "203.0.113.250", "203.0.114.1"),
        ("198.51.100.0/22", "198.51.103.255", "198.51.104.0"),
        ("192.0.2.0/24", "192.0.2.250", "192.0.3.1"),
        ("100.64.0.0/10", "100.127.255.255", "100.128.0.0"),
    ]:
        al = build_allowlist({"allowlist": {"trusted_cidrs": [cidr]}})
        assert al.is_allowed(match)[0] is True, f"{cidr} should match {match}"
        assert al.is_allowed(miss)[0] is False, f"{cidr} should NOT match {miss}"


def test_cidr_ipv6():
    al = build_allowlist({"allowlist": {"trusted_cidrs_v6": ["2001:db8::/32"]}})
    assert al.is_allowed("2001:db8::1")[0] is True
    assert al.is_allowed("2001:db9::1")[0] is False


def test_cidr_invalid_skipped_not_crashed():
    al = build_allowlist({"allowlist": {"trusted_cidrs": ["not-a-cidr", "999.999.999.0/24", "10.0.0.0/8"]}})
    assert al.is_allowed("10.5.5.5")[0] is True
    assert al.is_allowed("8.8.8.8")[0] is False


def test_cidr_zero_match_only_zero():
    al = build_allowlist({"allowlist": {"trusted_cidrs": ["0.0.0.0/0"]}})
    assert al.is_allowed("1.2.3.4")[0] is True
    assert al.is_allowed("203.0.113.1")[0] is True


def test_cidr_private_ranges_intact():
    al = build_allowlist({"allowlist": {}})
    for ip in ["10.0.0.1", "172.16.5.5", "192.168.1.1", "127.0.0.1"]:
        assert al.is_allowed(ip)[0] is True, f"{ip} should match private"


def test_should_suppress_broadcast_storm_cloudflare():
    suppress, reason = should_suppress("172.65.90.20", "broadcast_storm")
    assert suppress is True
    assert reason == "cloudflare"


def test_should_suppress_timing_evasion_cloudflare():
    suppress, reason = should_suppress("104.16.0.1", "timing_evasion")
    assert suppress is True


def test_should_suppress_port_scan_private():
    suppress, reason = should_suppress("192.168.1.5", "port_scan")
    assert suppress is True


def test_should_not_suppress_ssh_bruteforce_from_anywhere():
    suppress, _ = should_suppress("172.64.1.1", "ssh_bruteforce")
    assert suppress is False


def test_should_not_suppress_sql_injection_from_cloudflare():
    suppress, _ = should_suppress("172.64.1.1", "sql_injection")
    assert suppress is False


def test_should_not_suppress_random_attack():
    suppress, _ = should_suppress("203.0.113.1", "ssh_bruteforce")
    assert suppress is False


def test_ipv6_loopback():
    al = build_allowlist()
    suppress, _ = al.is_allowed("::1")
    assert suppress is True


def test_ipv6_link_local():
    al = build_allowlist()
    suppress, _ = al.is_allowed("fe80::1")
    assert suppress is True


def test_cloudflare_ipv6():
    al = build_allowlist()
    suppress, _ = al.is_allowed("2400:cb00::1")
    assert suppress is True


def test_allowlist_has_cloudflare_ranges():
    assert len(CLOUDFLARE_RANGES_V4) >= 10


def test_allowlist_has_private_ranges():
    assert "10.0.0.0/8" in PRIVATE_RANGES_V4
    assert "192.168.0.0/16" in PRIVATE_RANGES_V4
    assert "172.16.0.0/12" in PRIVATE_RANGES_V4


def test_allowlist_dataclass_fields():
    al = Allowlist()
    assert al.enabled is True
    assert al.suppress_private is True
    assert al.suppress_cloudflare is True
    assert al.suppress_google is False


def test_allowlist_with_suppress_private_disabled():
    al = build_allowlist({"allowlist": {"suppress_private": False}})
    suppress, _ = al.is_allowed("192.168.1.5")
    assert suppress is False


def test_allowlist_with_suppress_cloudflare_disabled():
    al = build_allowlist({"allowlist": {"suppress_cloudflare": False}})
    suppress, _ = al.is_allowed("172.64.1.1")
    assert suppress is False


def test_should_suppress_returns_tuple():
    result = should_suppress("1.2.3.4", "test")
    assert isinstance(result, tuple)
    assert len(result) == 2
