"""Tests for `lidra doctor --json` and idempotent block_ip."""

import json
import os
import sys
import unittest
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class TestDoctorJSON:
    def test_json_output_is_valid_json(self, capsys):
        from cli.doctor_cmd import cmd_doctor
        with patch("utils.distro_detect.detect_all") as mock_detect:
            mock_detect.return_value = {
                "system": {"hostname": "testhost"},
                "distro": {"name": "debian", "pretty_name": "Debian 12"},
                "network": {"interfaces": ["eth0"]},
                "logs": {"sources": []},
                "capabilities": {"iptables": True},
                "issues": [],
            }
            exit_code = cmd_doctor(["--json"])
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert isinstance(report, dict)
        assert report["ok"] is True
        assert report["exit_code"] == 0
        assert report["system"]["hostname"] == "testhost"
        assert "database" in report
        assert "lidra_config" in report
        assert exit_code == 0

    def test_json_warnings_have_exit_code_1(self, capsys):
        from cli.doctor_cmd import cmd_doctor
        with patch("utils.distro_detect.detect_all") as mock_detect:
            mock_detect.return_value = {
                "system": {"hostname": "testhost"},
                "distro": {"name": "debian", "pretty_name": "Debian 12"},
                "network": {"interfaces": []},
                "logs": {"sources": []},
                "capabilities": {"iptables": False},
                "issues": [{"level": "warning", "code": "no_iface", "message": "no network"}],
            }
            exit_code = cmd_doctor(["--json"])
        report = json.loads(capsys.readouterr().out)
        assert report["ok"] is False
        assert report["exit_code"] == 1
        assert exit_code == 1

    def test_json_errors_have_exit_code_2(self, capsys):
        from cli.doctor_cmd import cmd_doctor
        with patch("utils.distro_detect.detect_all") as mock_detect:
            mock_detect.return_value = {
                "system": {"hostname": "testhost"},
                "distro": {"name": "debian", "pretty_name": "Debian 12"},
                "network": {"interfaces": ["eth0"]},
                "logs": {"sources": []},
                "capabilities": {"iptables": True},
                "issues": [{"level": "error", "code": "no_root", "message": "must be root"}],
            }
            exit_code = cmd_doctor(["--json"])
        report = json.loads(capsys.readouterr().out)
        assert report["ok"] is False
        assert report["exit_code"] == 2
        assert exit_code == 2

    def test_human_output_unchanged_when_no_json(self, capsys):
        from cli.doctor_cmd import cmd_doctor
        with patch("utils.distro_detect.detect_all") as mock_detect:
            mock_detect.return_value = {
                "system": {"hostname": "h"},
                "distro": {"name": "d", "pretty_name": "D"},
                "network": {"interfaces": ["eth0"]},
                "logs": {"sources": []},
                "capabilities": {"iptables": True},
                "issues": [],
            }
            cmd_doctor([])
        captured = capsys.readouterr()
        assert "LIDRA Doctor" in captured.out
        assert "{" not in captured.out.split("LIDRA Doctor")[1].split("\n")[0] or "ok" not in captured.out


class TestIdempotentBlock:
    def test_block_ip_calls_iptables_check_first_then_append(self):
        from response.firewall import FirewallManager
        fw = FirewallManager(backend="iptables", dry_run=False, config={})
        calls = []
        def fake_run(cmd, *args, **kwargs):
            calls.append(cmd)
            r = unittest.mock.MagicMock()
            r.returncode = 1
            r.stdout = b""
            r.stderr = b""
            return r
        with patch("subprocess.run", side_effect=fake_run):
            with patch("threading.Timer"):
                fw.block_ip("1.2.3.4", ttl_seconds=10)
        check_call = [c for c in calls if "-C" in c]
        append_call = [c for c in calls if "-A" in c]
        assert len(check_call) == 1, f"should probe with -C first, got {calls}"
        assert len(append_call) == 1, f"should then append with -A, got {calls}"
        check_pos = calls.index(check_call[0])
        append_pos = calls.index(append_call[0])
        assert check_pos < append_pos, "-C must come before -A"

    def test_block_ip_skips_append_when_already_blocked(self):
        from response.firewall import FirewallManager
        fw = FirewallManager(backend="iptables", dry_run=False, config={})
        calls = []
        def fake_run(cmd, *args, **kwargs):
            calls.append(cmd)
            r = unittest.mock.MagicMock()
            r.returncode = 0
            r.stdout = b""
            r.stderr = b""
            return r
        with patch("subprocess.run", side_effect=fake_run):
            with patch("threading.Timer"):
                result = fw.block_ip("1.2.3.4", ttl_seconds=10)
        check_call = [c for c in calls if "-C" in c]
        append_call = [c for c in calls if "-A" in c]
        assert len(check_call) == 1, "should still probe with -C"
        assert len(append_call) == 0, "should NOT append duplicate rule"
        assert result is True

    def test_block_ip_dry_run_skips_iptables_entirely(self):
        from response.firewall import FirewallManager
        fw = FirewallManager(backend="iptables", dry_run=True, config={})
        with patch("subprocess.run") as mock_run:
            result = fw.block_ip("1.2.3.4", ttl_seconds=10)
        assert result is True
        assert not mock_run.called, "dry_run must not invoke iptables at all"


if __name__ == "__main__":
    unittest.main()
