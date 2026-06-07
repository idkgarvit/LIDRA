"""Tests for FirewallManager IP validation and config secret resolution."""

import os
import sys
import unittest
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class TestIPValidation(unittest.TestCase):
    def test_valid_ipv4(self):
        from response.firewall import _validate_ip
        assert _validate_ip("1.2.3.4") == "1.2.3.4"
        assert _validate_ip("192.168.1.1") == "192.168.1.1"
        assert _validate_ip("8.8.8.8") == "8.8.8.8"

    def test_empty_string(self):
        from response.firewall import _validate_ip
        with pytest.raises(ValueError, match="non-empty"):
            _validate_ip("")

    def test_none(self):
        from response.firewall import _validate_ip
        with pytest.raises(ValueError):
            _validate_ip(None)

    def test_non_string(self):
        from response.firewall import _validate_ip
        with pytest.raises(ValueError):
            _validate_ip(12345)

    def test_shell_metachar(self):
        from response.firewall import _validate_ip
        with pytest.raises(ValueError, match="Invalid"):
            _validate_ip("1.2.3.4; rm -rf /")

    def test_out_of_range_octet(self):
        from response.firewall import _validate_ip
        with pytest.raises(ValueError):
            _validate_ip("999.999.999.999")

    def test_injection_attempt(self):
        from response.firewall import _validate_ip
        with pytest.raises(ValueError):
            _validate_ip("1.2.3.4`whoami`")

    def test_newline_injection(self):
        from response.firewall import _validate_ip
        with pytest.raises(ValueError):
            _validate_ip("1.2.3.4\nwhoami")

    def test_ipv6_rejected(self):
        from response.firewall import _validate_ip
        with pytest.raises(ValueError):
            _validate_ip("::1")

    def test_loopback_rejected(self):
        from response.firewall import _validate_ip
        with pytest.raises(ValueError, match="loopback"):
            _validate_ip("127.0.0.1")

    def test_unspecified_rejected(self):
        from response.firewall import _validate_ip
        with pytest.raises(ValueError, match="special-use"):
            _validate_ip("0.0.0.0")

    def test_multicast_rejected(self):
        from response.firewall import _validate_ip
        with pytest.raises(ValueError, match="special-use"):
            _validate_ip("224.0.0.1")


class TestFirewallEntryPoints:
    def _make_fw(self, dry_run=True):
        from response.firewall import FirewallManager
        return FirewallManager(backend="iptables", dry_run=dry_run, config={})

    def test_block_ip_rejects_garbage(self):
        fw = self._make_fw()
        assert fw.block_ip("not-an-ip") is False
        assert fw.block_ip("") is False
        assert fw.block_ip("1.2.3.4; rm -rf /") is False
        assert fw.block_ip(None) is False

    def test_block_ip_accepts_valid_in_dry_run(self):
        fw = self._make_fw(dry_run=True)
        assert fw.block_ip("1.2.3.4") is True

    def test_unblock_ip_rejects_garbage(self):
        fw = self._make_fw()
        assert fw.unblock_ip("not-an-ip") is False
        assert fw.unblock_ip("1.2.3.4; rm -rf /") is False

    def test_unblock_ip_accepts_valid_in_dry_run(self):
        fw = self._make_fw(dry_run=True)
        assert fw.unblock_ip("1.2.3.4") is True

    def test_bridge_block_rejects_garbage(self):
        fw = self._make_fw()
        fw.bridge_block_ip("not-an-ip")
        fw.bridge_block_ip("")

    def test_bridge_unblock_rejects_garbage(self):
        fw = self._make_fw()
        fw.bridge_unblock_ip("not-an-ip")


class TestResolveSecretFix:
    """Regression tests for the str(None)='None' truthy bug."""

    def test_none_value_does_not_skip_env_override(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LIDRA_ABUSEIPDB_KEY", "env-key-12345")
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text("threat_intel:\n  abuseipdb_api_key:\n")
        with patch("utils.config_loader.get_config_path", return_value=cfg_path):
            from utils import config_loader
            config_loader.invalidate_cache()
            cfg = config_loader.load_config()
        assert cfg["threat_intel"]["abuseipdb_api_key"] == "env-key-12345"

    def test_empty_string_does_skip_env_override_unchanged(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LIDRA_ABUSEIPDB_KEY", "env-key-12345")
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text('threat_intel:\n  abuseipdb_api_key: ""\n')
        with patch("utils.config_loader.get_config_path", return_value=cfg_path):
            from utils import config_loader
            config_loader.invalidate_cache()
            cfg = config_loader.load_config()
        assert cfg["threat_intel"]["abuseipdb_api_key"] == "env-key-12345"

    def test_explicit_value_used_when_no_env(self, monkeypatch, tmp_path):
        monkeypatch.delenv("LIDRA_ABUSEIPDB_KEY", raising=False)
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text('threat_intel:\n  abuseipdb_api_key: "yaml-key"\n')
        with patch("utils.config_loader.get_config_path", return_value=cfg_path):
            from utils import config_loader
            config_loader.invalidate_cache()
            cfg = config_loader.load_config()
        assert cfg["threat_intel"]["abuseipdb_api_key"] == "yaml-key"


if __name__ == "__main__":
    unittest.main()
