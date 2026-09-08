"""Tests for the inline bridge/gateway setup module and inline engine
chain-selection logic.

These tests do NOT create or modify any real Linux bridge.  Every subprocess
call is mocked.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from bridge.bridge_setup import (
    BridgeCommandNotFound,
    BridgePermissionError,
    BridgeSetupError,
    BridgeStatus,
    bridge_status,
    create_bridge,
    has_forwarding,
    is_bridge_up,
    setup_forwarding_rules,
    teardown_bridge,
)


def _completed(rc=0, stdout="", stderr=""):
    cp = MagicMock()
    cp.returncode = rc
    cp.stdout = stdout
    cp.stderr = stderr
    cp.success = (rc == 0)
    return cp


class TestCreateBridge(unittest.TestCase):

    @patch("bridge.bridge_setup._have_root", return_value=False)
    def test_create_bridge_requires_root(self, _root):
        with self.assertRaises(BridgePermissionError):
            create_bridge("eth0", "eth1")

    @patch("bridge.bridge_setup.Path")
    @patch("bridge.bridge_setup._have_root", return_value=True)
    @patch("bridge.bridge_setup._ip_cmd", return_value="ip")
    def test_create_bridge_happy_path(self, _ip, _root, mock_path):
        sys_path = MagicMock()
        sys_path.exists.return_value = True
        mock_path.return_value = sys_path

        with patch("bridge.bridge_setup._run") as run, \
             patch("bridge.bridge_setup._bridge_exists", return_value=False):
            run.return_value = _completed(0, "ok", "")
            result = create_bridge("eth0", "eth1", bridge_name="br_test")

        self.assertTrue(result)
        commands = [c.args[0] for c in run.call_args_list]
        self.assertIn(
            ["ip", "link", "add", "name", "br_test", "type", "bridge"],
            commands,
        )
        self.assertIn(
            ["ip", "link", "set", "eth0", "master", "br_test"],
            commands,
        )
        self.assertIn(
            ["ip", "link", "set", "eth1", "master", "br_test"],
            commands,
        )
        self.assertIn(["ip", "link", "set", "br_test", "up"], commands)

    @patch("bridge.bridge_setup.Path")
    @patch("bridge.bridge_setup._have_root", return_value=True)
    @patch("bridge.bridge_setup._ip_cmd", return_value="ip")
    def test_create_bridge_idempotent_when_exists(self, _ip, _root, mock_path):
        sys_path = MagicMock()
        sys_path.exists.return_value = True
        mock_path.return_value = sys_path

        with patch("bridge.bridge_setup._run") as run, \
             patch("bridge.bridge_setup._bridge_exists", return_value=True), \
             patch(
                 "bridge.bridge_setup._interface_is_in_bridge",
                 return_value=True,
             ):
            run.return_value = _completed(0, "ok", "")
            result = create_bridge("eth0", "eth1", bridge_name="br_test")

        self.assertTrue(result)
        for c in run.call_args_list:
            cmd = c.args[0]
            self.assertNotEqual(
                cmd[:3],
                ["ip", "link", "add"],
                "Should not re-add an existing bridge",
            )

    @patch("bridge.bridge_setup._have_root", return_value=True)
    def test_create_bridge_rejects_identical_ifaces(self, _root):
        with self.assertRaises(BridgeSetupError):
            create_bridge("eth0", "eth0")

    @patch("bridge.bridge_setup._have_root", return_value=True)
    def test_create_bridge_rejects_empty_ifaces(self, _root):
        with self.assertRaises(BridgeSetupError):
            create_bridge("", "eth1")


class TestSetupForwardingRules(unittest.TestCase):

    @patch("bridge.bridge_setup._have_root", return_value=False)
    def test_setup_forwarding_requires_root(self, _root):
        with self.assertRaises(BridgePermissionError):
            setup_forwarding_rules("br_lidra", 0)

    @patch("bridge.bridge_setup.Path")
    @patch("bridge.bridge_setup._have_root", return_value=True)
    @patch("bridge.bridge_setup._nft_or_iptables", return_value="nft")
    def test_setup_forwarding_nft(self, _nat_tool, _root, mock_path):
        sys_path = MagicMock()
        sys_path.exists.return_value = True
        mock_path.return_value = sys_path

        with patch("bridge.bridge_setup._run") as run, \
             patch("bridge.bridge_setup._read_sysctl", return_value="0"):
            run.return_value = _completed(0, "", "")
            ok = setup_forwarding_rules(
                "br_lidra", 1, enable_ip_forward=True
            )

        self.assertTrue(ok)
        cmds = [c.args[0][0] for c in run.call_args_list]
        self.assertIn("sysctl", cmds)
        self.assertIn("nft", cmds)

    @patch("bridge.bridge_setup.Path")
    @patch("bridge.bridge_setup._have_root", return_value=True)
    @patch("bridge.bridge_setup._nft_or_iptables", return_value="iptables")
    def test_setup_forwarding_iptables_fallback(self, _nat_tool, _root, mock_path):
        sys_path = MagicMock()
        sys_path.exists.return_value = True
        mock_path.return_value = sys_path

        with patch("bridge.bridge_setup._run") as run, \
             patch("bridge.bridge_setup._read_sysctl", return_value="1"):
            run.return_value = _completed(0, "", "")
            ok = setup_forwarding_rules("br_lidra", 0)

        self.assertTrue(ok)
        cmds = [c.args[0] for c in run.call_args_list]
        iptables_cmds = [c for c in cmds if c and c[0] == "iptables"]
        self.assertGreater(len(iptables_cmds), 0)
        self.assertEqual(iptables_cmds[0][1], "-A")
        self.assertEqual(iptables_cmds[0][2], "FORWARD")
        last = iptables_cmds[-1]
        self.assertIn("NFQUEUE", last)
        self.assertIn("--queue-num", last)

    @patch("bridge.bridge_setup.Path")
    @patch("bridge.bridge_setup._have_root", return_value=True)
    @patch("bridge.bridge_setup._nft_or_iptables", return_value="nft")
    def test_setup_forwarding_with_nat(self, _nat_tool, _root, mock_path):
        sys_path = MagicMock()
        sys_path.exists.return_value = True
        mock_path.return_value = sys_path

        with patch("bridge.bridge_setup._run") as run, \
             patch("bridge.bridge_setup._read_sysctl", return_value="1"):
            run.return_value = _completed(0, "", "")
            ok = setup_forwarding_rules(
                "br_lidra",
                0,
                enable_nat=True,
                wan_iface="eth0",
                lan_iface="eth1",
            )

        self.assertTrue(ok)
        nat_cmds = [
            c.args[0]
            for c in run.call_args_list
            if c.args[0] and "masquerade" in c.args[0]
        ]
        self.assertGreater(len(nat_cmds), 0)

    @patch("bridge.bridge_setup.Path")
    @patch("bridge.bridge_setup._have_root", return_value=True)
    @patch("bridge.bridge_setup._nft_or_iptables", return_value="iptables")
    def test_setup_forwarding_failure_returns_false(
        self, _nat_tool, _root, mock_path
    ):
        sys_path = MagicMock()
        sys_path.exists.return_value = True
        mock_path.return_value = sys_path

        with patch("bridge.bridge_setup._run") as run, \
             patch("bridge.bridge_setup._read_sysctl", return_value="1"):
            run.return_value = _completed(1, "", "boom")
            ok = setup_forwarding_rules("br_lidra", 0)

        self.assertFalse(ok)


class TestTeardownBridge(unittest.TestCase):

    @patch("bridge.bridge_setup._have_root", return_value=False)
    def test_teardown_requires_root(self, _root):
        with self.assertRaises(BridgePermissionError):
            teardown_bridge("br_lidra")

    @patch("bridge.bridge_setup._have_root", return_value=True)
    @patch("bridge.bridge_setup._ip_cmd", return_value="ip")
    def test_teardown_happy_path(self, _ip, _root):
        with patch("bridge.bridge_setup._run") as run, \
             patch("bridge.bridge_setup._bridge_exists", return_value=True), \
             patch(
                 "bridge.bridge_setup._list_bridge_members",
                 return_value=["eth0", "eth1"],
             ):
            run.return_value = _completed(0, "", "")
            ok = teardown_bridge("br_lidra")

        self.assertTrue(ok)
        cmds = [c.args[0] for c in run.call_args_list]
        self.assertIn(["ip", "link", "set", "br_lidra", "down"], cmds)
        self.assertIn(["ip", "link", "delete", "br_lidra"], cmds)

    @patch("bridge.bridge_setup._have_root", return_value=True)
    @patch("bridge.bridge_setup._ip_cmd", return_value="ip")
    def test_teardown_noop_when_absent(self, _ip, _root):
        with patch("bridge.bridge_setup._bridge_exists", return_value=False), \
             patch("bridge.bridge_setup._run") as run:
            ok = teardown_bridge("br_does_not_exist")
            self.assertTrue(ok)
            run.assert_not_called()


class TestBridgeStatus(unittest.TestCase):

    @patch("bridge.bridge_setup._ip_cmd", return_value="ip")
    def test_status_when_bridge_up(self, _ip):
        ip_show = (
            "42: br_lidra: <BROADCAST,MULTICAST,UP,LOWER_UP> "
            "mtu 1500 state UP\n"
            "    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff"
        )
        addr_show = (
            "    inet 10.0.0.1/24 brd 10.0.0.255 scope global br_lidra\n"
        )
        with patch("bridge.bridge_setup._run") as run, \
             patch("bridge.bridge_setup._read_sysctl", return_value="1"):
            run.side_effect = [
                _completed(0, ip_show, ""),
                _completed(0, ip_show, ""),
                _completed(0, addr_show, ""),
            ]
            status = bridge_status("br_lidra")

        self.assertIsInstance(status, BridgeStatus)
        self.assertEqual(status.name, "br_lidra")
        self.assertTrue(status.exists)
        self.assertTrue(status.is_up)
        self.assertEqual(status.state, "UP")
        self.assertTrue(status.forwarding)
        self.assertEqual(status.addresses, ["10.0.0.1/24"])

    @patch("bridge.bridge_setup._ip_cmd", return_value="ip")
    def test_status_when_bridge_absent(self, _ip):
        with patch("bridge.bridge_setup._run") as run:
            run.return_value = _completed(1, "", "Cannot find device br0")
            status = bridge_status("br0")

        self.assertFalse(status.exists)
        self.assertFalse(status.is_up)
        self.assertEqual(status.state, "absent")

    def test_status_handles_missing_ip_command(self):
        with patch(
            "bridge.bridge_setup._ip_cmd",
            side_effect=BridgeCommandNotFound("no ip"),
        ):
            status = bridge_status("br_lidra")

        self.assertFalse(status.exists)
        self.assertEqual(status.state, "missing-ip")

    def test_status_to_dict_has_expected_keys(self):
        s = BridgeStatus(
            name="br_lidra", exists=True, is_up=True, state="UP"
        )
        d = s.to_dict()
        for key in (
            "name", "exists", "is_up", "state",
            "members", "addresses", "forwarding", "raw",
        ):
            self.assertIn(key, d)


class TestIsBridgeUp(unittest.TestCase):

    @patch("bridge.bridge_setup.bridge_status")
    def test_is_bridge_up_true(self, status):
        s = BridgeStatus(name="br", exists=True, is_up=True, state="UP")
        status.return_value = s
        self.assertTrue(is_bridge_up("br"))

    @patch("bridge.bridge_setup.bridge_status")
    def test_is_bridge_up_false_when_absent(self, status):
        s = BridgeStatus(name="br", exists=False, is_up=False, state="absent")
        status.return_value = s
        self.assertFalse(is_bridge_up("br"))


class TestForwardingHelpers(unittest.TestCase):

    @patch(
        "builtins.open",
        new_callable=unittest.mock.mock_open,
        read_data="1\n",
    )
    def test_has_forwarding_true(self, _m):
        self.assertTrue(has_forwarding())

    @patch("builtins.open", side_effect=OSError("nope"))
    def test_has_forwarding_false_on_error(self, _m):
        self.assertFalse(has_forwarding())


class TestMissingIpCommand(unittest.TestCase):

    @patch("bridge.bridge_setup._interface_exists", return_value=True)
    @patch("bridge.bridge_setup._ip_cmd", side_effect=BridgeCommandNotFound("x"))
    @patch("bridge.bridge_setup._have_root", return_value=True)
    def test_create_bridge_handles_missing_ip(self, _root, _ip, _iface):
        with self.assertRaises(BridgeCommandNotFound):
            create_bridge("eth0", "eth1")

    @patch("bridge.bridge_setup._interface_exists", return_value=True)
    @patch("bridge.bridge_setup._have_root", return_value=True)
    @patch("bridge.bridge_setup._nft_or_iptables", side_effect=BridgeCommandNotFound("x"))
    def test_setup_forwarding_handles_missing_nft_iptables(
        self, _tools, _root, _iface
    ):
        with self.assertRaises(BridgeCommandNotFound):
            setup_forwarding_rules("br_lidra", 0)


class TestInlineEngineChainSelection(unittest.TestCase):

    def _make_engine(self, config):
        from bridge.inline_engine import InlineEngine
        return InlineEngine(config)

    def test_default_local_mode_uses_input_chain(self):
        ie = self._make_engine({"mode": "local"})
        self.assertEqual(ie._nfqueue_chain(), "input")
        self.assertFalse(ie._is_bridge_mode())

    def test_inline_mode_with_bridge_name_uses_forward_chain(self):
        ie = self._make_engine(
            {
                "mode": "inline",
                "bridge": {
                    "bridge_name": "br_lidra",
                    "interfaces": {"wan": "eth0", "lan": "eth1"},
                },
            }
        )
        self.assertEqual(ie._nfqueue_chain(), "forward")
        self.assertTrue(ie._is_bridge_mode())

    def test_explicit_nfqueue_chain_overrides_default(self):
        ie = self._make_engine(
            {
                "mode": "inline",
                "bridge": {
                    "bridge_name": "br_lidra",
                    "nfqueue_chain": "INPUT",
                },
            }
        )
        self.assertEqual(ie._nfqueue_chain(), "input")

    def test_nft_params_for_forward_chain(self):
        from bridge.inline_engine import InlineEngine
        tool, family, _prio, hook = InlineEngine._nfqueue_nft_params("forward")
        self.assertEqual(tool, "nft")
        self.assertEqual(family, "bridge")
        self.assertEqual(hook, "forward")

    def test_nft_params_for_input_chain(self):
        from bridge.inline_engine import InlineEngine
        tool, family, _prio, hook = InlineEngine._nfqueue_nft_params("input")
        self.assertEqual(tool, "nft")
        self.assertEqual(family, "inet")
        self.assertEqual(hook, "input")

    def test_setup_nfqueue_chain_forwards_chain_arg(self):
        from bridge.inline_engine import InlineEngine
        ie = self._make_engine({"mode": "inline", "bridge": {"bridge_name": "br"}})
        with patch.object(ie, "_setup_nfqueue_nft", return_value=True) as m:
            ok = ie.setup_nfqueue_chain("FORWARD")
        self.assertTrue(ok)
        m.assert_called_once_with("forward")

    def test_apply_nf_verdict_pass_is_accept(self):
        from bridge.inline_engine import InlineEngine
        from response.verdict import Verdict
        ie = self._make_engine({})
        self.assertEqual(ie._apply_nf_verdict(Verdict.PASS), 1)

    def test_apply_nf_verdict_drop_is_drop(self):
        from bridge.inline_engine import InlineEngine
        from response.verdict import Verdict
        ie = self._make_engine({})
        self.assertEqual(ie._apply_nf_verdict(Verdict.DROP), 0)


class TestInitBridgeModeAttributes(unittest.TestCase):
    """Verify _init_bridge_mode() initializes TUI attributes unconditionally
    so that _push_tui_event() does not raise AttributeError when HAS_BRIDGE
    is False (modules unavailable).
    """

    def _import_agent_base_source(self):
        from pathlib import Path
        return (
            Path(__file__).resolve().parents[1]
            / "src"
            / "core"
            / "agent_base.py"
        ).read_text()

    def _import_gateway_source(self):
        from pathlib import Path
        return (
            Path(__file__).resolve().parents[1]
            / "src"
            / "core"
            / "gateway_agent.py"
        ).read_text()

    def test_init_bridge_mode_sets_tui_attrs_before_has_bridge_check(self):
        source = self._import_gateway_source()
        self.assertIn("_init_mode_components", source)
        idx = source.index("def _init_mode_components")
        body = source[idx:]
        if_has_bridge = body.find("if HAS_BRIDGE")
        self.assertGreater(if_has_bridge, 0)

    def test_init_bridge_mode_no_ugly_dict_trailing_comma(self):
        source = self._import_gateway_source()
        idx = source.index("def _init_mode_components")
        body = source[idx:]
        self.assertNotIn("{},)", body)

    def test_push_tui_event_does_not_attributeerror_when_tui_ipc_server_none(self):
        import re
        source = self._import_agent_base_source()
        push = re.search(
            r"def (?:push_event|_push_tui_event).*?(?=\n    def )",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(push)
        body = push.group(0)
        self.assertIn("self._tui_ipc_server", body)
        self.assertIn("if self._tui_ipc_server", body)


if __name__ == "__main__":
    unittest.main()
