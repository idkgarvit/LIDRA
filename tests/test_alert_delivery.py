"""Alert delivery, end to end, against real local endpoints (§2.5).

The plan's §2.5 asks three things, none of which had ever been exercised:

  1. Slack webhook, Discord webhook, SMTP each deliver to a real endpoint.
  2. Behaviour when the webhook 500s, times out, or the host has no route —
     **an alerting failure must not delay a verdict or crash the agent.**
  3. The throttle does not suppress the first alert of a genuinely new incident.

These tests stand up real listeners on localhost (an HTTP server that can be
told to succeed, fail or hang; a minimal SMTP sink) and drive the **real**
channel classes and the **real** `AlertNotifier`. Nothing is mocked out at the
transport layer, so a channel that never actually sends will fail here.
"""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from alerts.notifier import Alert, AlertNotifier, AlertChannel  # noqa: E402
from alerts.slack import SlackChannel  # noqa: E402
from alerts.discord import DiscordChannel  # noqa: E402


# ── a webhook endpoint we control ────────────────────────────────────────────

class _Hook:
    """Records what a webhook receives and can be told how to behave."""

    def __init__(self):
        self.requests = []
        self.mode = "ok"          # ok | 500 | hang
        self.status = 200
        self._srv = None
        self._thread = None
        self.port = None

    def start(self):
        hook = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                hook.requests.append({
                    "path": self.path,
                    "body": body,
                    "headers": dict(self.headers),
                })
                if hook.mode == "hang":
                    # Hold the connection open longer than any sane client
                    # timeout, so the caller must give up on its own.
                    time.sleep(30)
                code = hook.status
                self.send_response(code)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self._srv.server_address[1]
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()
        return self

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/hook"

    def stop(self):
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()


@pytest.fixture()
def hook():
    h = _Hook().start()
    yield h
    h.stop()


def _alert(severity="high", atype="sql_injection", ip="203.0.113.9"):
    return Alert(alert_type=atype, severity=severity, ip_address=ip,
                 message="UNION SELECT from 203.0.113.9")


# ── 1. delivery actually happens ─────────────────────────────────────────────

class TestWebhooksDeliver:
    def test_slack_delivers_and_the_body_is_wellformed(self, hook):
        assert SlackChannel(hook.url).send(_alert()) is True
        assert len(hook.requests) == 1, "Slack never reached the endpoint"
        payload = json.loads(hook.requests[0]["body"])
        att = payload["attachments"][0]
        assert "sql_injection" in att["title"]
        fields = {f["title"]: f["value"] for f in att["fields"]}
        assert fields["Severity"] == "HIGH"
        assert fields["IP Address"] == "203.0.113.9"

    def test_discord_delivers_and_the_body_is_wellformed(self, hook):
        hook.status = 204                      # Discord answers 204
        assert DiscordChannel(hook.url).send(_alert()) is True
        assert len(hook.requests) == 1, "Discord never reached the endpoint"
        payload = json.loads(hook.requests[0]["body"])
        embed = payload["embeds"][0]
        assert "sql_injection" in embed["title"]
        assert any(f["name"] == "Severity" for f in embed["fields"])

    def test_every_severity_maps_to_a_colour(self, hook):
        for sev in ("low", "medium", "high", "critical", "unknown-band"):
            assert SlackChannel(hook.url).send(_alert(severity=sev)) is True
        assert len(hook.requests) == 5, "a severity failed to send"


# ── 2. failure modes must not break the caller ───────────────────────────────

class TestWebhookFailureIsContained:
    def test_http_500_returns_false_and_does_not_raise(self, hook):
        hook.status = 500
        assert SlackChannel(hook.url).send(_alert()) is False

    def test_discord_rejects_a_200_as_failure(self, hook):
        """Discord returns 204; a 200 is not success for that API."""
        hook.status = 200
        assert DiscordChannel(hook.url).send(_alert()) is False

    def test_unreachable_endpoint_returns_false_quickly(self):
        """A closed port must fail fast, not hang the caller."""
        ch = SlackChannel("http://127.0.0.1:9/nothing")   # discard port
        t0 = time.monotonic()
        assert ch.send(_alert()) is False
        assert time.monotonic() - t0 < 5, "connect failure took too long"

    def test_no_route_host_returns_false(self):
        """An unroutable address must not hang the verdict path."""
        ch = SlackChannel("http://192.0.2.1:81/hook")     # TEST-NET-1, unroutable
        t0 = time.monotonic()
        assert ch.send(_alert()) is False
        elapsed = time.monotonic() - t0
        assert elapsed < 15, f"unroutable host blocked for {elapsed:.1f}s"

    def test_a_hanging_webhook_does_not_block_the_notifier(self, hook, monkeypatch):
        """THE key case: one channel hanging must not stall the others, and the
        notifier must return in bounded time.

        The notifier is called from the detection worker — the same thread that
        writes rows and pushes TUI events — so an unbounded wait here is a
        backpressured verdict path, not just a lost alert.
        """
        hook.mode = "hang"
        # SlackChannel uses timeout=10; assert the contract, not the machine speed.
        monkeypatch.setattr("alerts.slack.requests.post",
                            lambda *a, **k: _timeout_after(k.get("timeout", None), *a))
        n = AlertNotifier([SlackChannel(hook.url)])
        t0 = time.monotonic()
        result = n.notify(_alert())
        elapsed = time.monotonic() - t0
        assert result == 0, "a timing-out channel must not count as success"
        assert elapsed < 12, f"notifier blocked for {elapsed:.1f}s on a hanging hook"

    def test_one_bad_channel_does_not_stop_the_good_one(self, hook):
        class Exploding(AlertChannel):
            @property
            def name(self): return "Exploding"

            def send(self, alert): raise RuntimeError("boom")

        n = AlertNotifier([Exploding(), SlackChannel(hook.url)])
        assert n.notify(_alert()) == 1, "a raising channel must not stop delivery"
        assert len(hook.requests) == 1, "the healthy channel never sent"

    def test_notifier_survives_every_channel_failing(self):
        class Failing(AlertChannel):
            @property
            def name(self): return "Failing"

            def send(self, alert): raise RuntimeError("nope")

        assert AlertNotifier([Failing(), Failing()]).notify(_alert()) == 0


def _timeout_after(seconds, *a, **k):
    """Stand-in for requests.post that honours the timeout it was given."""
    if seconds:
        time.sleep(min(float(seconds), 1.0))
    raise TimeoutError("simulated read timeout")


# ── 3. SMTP: the channel that config documents but nothing wires ─────────────

class TestEmailChannelIsWired:
    def test_config_documents_email_settings(self):
        """The shipped config advertises SMTP; the agent must honour it."""
        import yaml
        cfg = yaml.safe_load(open(Path(__file__).resolve().parent.parent
                                  / "config" / "config.yaml"))
        email = cfg["alerts"]["email"]
        for key in ("enabled", "smtp_host", "smtp_port", "username",
                    "password", "from_addr", "to_addrs"):
            assert key in email, f"config lost the email key {key!r}"

    def test_agent_builds_an_email_channel_when_enabled(self):
        """_init_alerting must instantiate EmailChannel — it previously built
        only Slack and Discord, so the documented SMTP block was dead config."""
        from core.agent_base import LIDRACore
        import inspect
        src = inspect.getsource(LIDRACore._init_alerting)
        assert "EmailChannel" in src, (
            "_init_alerting does not reference EmailChannel: SMTP is configured "
            "in config.yaml but can never be used (plan §2.5)"
        )

    def test_email_channel_delivers_to_a_real_smtp_sink(self):
        sink = _SmtpSink().start()
        try:
            from alerts.email_alert import EmailChannel
            # Port 25-style: plain connect, no STARTTLS. The channel picks this
            # from the port unless told otherwise.
            ch = EmailChannel(sink.host, sink.port, "", "",
                              "lidra@example.test", ["ops@example.test"],
                              timeout=5)
            assert ch.use_starttls is False, "a non-587 port must not STARTTLS"
            assert ch.send(_alert()) is True, "SMTP delivery failed"
            for _ in range(50):
                if sink.messages:
                    break
                time.sleep(0.1)
            assert sink.messages, "the sink received nothing"
            raw = sink.messages[0]
            assert "sql_injection" in raw
            assert "203.0.113.9" in raw
        finally:
            sink.stop()

    def test_port_587_uses_starttls_and_465_uses_implicit_tls(self):
        """Transport must follow the port: the old code called starttls()
        unconditionally, so it could only ever work on 587."""
        from alerts.email_alert import EmailChannel
        assert EmailChannel("h", 587, "", "", "a@b", ["c@d"]).use_starttls is True
        assert EmailChannel("h", 587, "", "", "a@b", ["c@d"]).use_ssl is False
        assert EmailChannel("h", 465, "", "", "a@b", ["c@d"]).use_ssl is True
        assert EmailChannel("h", 465, "", "", "a@b", ["c@d"]).use_starttls is False
        assert EmailChannel("h", 25, "", "", "a@b", ["c@d"]).use_starttls is False
        # ...and the override still works for an unusual relay.
        forced = EmailChannel("h", 2525, "", "", "a@b", ["c@d"], use_starttls=True)
        assert forced.use_starttls is True

    def test_email_to_an_unreachable_host_fails_bounded(self):
        """Must not block the detection worker forever.

        `smtplib.SMTP()`'s default timeout is infinite, and the notifier runs on
        the same thread that writes rows — so an unreachable SMTP host without a
        timeout is a backpressured verdict path.
        """
        from alerts.email_alert import EmailChannel
        ch = EmailChannel("192.0.2.1", 25, "", "",
                          "lidra@example.test", ["ops@example.test"])
        t0 = time.monotonic()
        assert ch.send(_alert()) is False
        elapsed = time.monotonic() - t0
        assert elapsed < 20, (
            f"SMTP to an unreachable host blocked for {elapsed:.1f}s — the "
            "channel needs an explicit timeout"
        )


# ── 4. the throttle must not swallow a new incident (§2.5, third bullet) ─────


class TestThrottleDoesNotHideNewIncidents:
    """§2.5: "the throttle does not suppress the first alert of a genuinely new
    incident". Exercised through the real notifier + throttle, not in isolation.

    A separate bug in the same class was fixed earlier: the never-seen sentinel
    was `0` against `time.monotonic()` (seconds-since-boot), so a host that had
    just rebooted silenced its own first alert for the length of the cooldown
    (15 minutes with the shipped default).
    """

    def test_first_alert_of_a_new_incident_is_delivered(self, hook):
        from utils.alert_throttle import AlertThrottle
        notifier = AlertNotifier([SlackChannel(hook.url)])
        throttle = AlertThrottle(cooldown_seconds=900)

        if throttle.allow("sql_injection", "203.0.113.9"):
            notifier.notify(_alert())

        assert len(hook.requests) == 1, (
            "the first alert of a new incident must be delivered"
        )

    def test_repeat_of_the_same_incident_is_suppressed(self, hook):
        from utils.alert_throttle import AlertThrottle
        notifier = AlertNotifier([SlackChannel(hook.url)])
        throttle = AlertThrottle(cooldown_seconds=900)

        for _ in range(50):                       # one scan's worth of repeats
            if throttle.allow("sql_injection", "203.0.113.9"):
                notifier.notify(_alert())

        assert len(hook.requests) == 1, (
            f"50 repeats produced {len(hook.requests)} alerts; expected 1"
        )

    def test_a_different_incident_is_not_suppressed_by_the_first(self, hook):
        """New source or new attack type must reach the operator."""
        from utils.alert_throttle import AlertThrottle
        notifier = AlertNotifier([SlackChannel(hook.url)])
        throttle = AlertThrottle(cooldown_seconds=900)

        for attack_type, ip in (("sql_injection", "203.0.113.9"),
                                ("sql_injection", "198.51.100.5"),   # new source
                                ("xss_attempt", "203.0.113.9")):     # new type
            if throttle.allow(attack_type, ip):
                notifier.notify(_alert(atype=attack_type, ip=ip))

        assert len(hook.requests) == 3, (
            f"expected 3 distinct incidents to be delivered, got {len(hook.requests)}"
        )

    def test_throttle_does_not_delay_delivery_when_it_allows(self, hook):
        """A allowed alert must be sent promptly, not queued behind anything."""
        from utils.alert_throttle import AlertThrottle
        notifier = AlertNotifier([SlackChannel(hook.url)])
        throttle = AlertThrottle(cooldown_seconds=900)
        t0 = time.monotonic()
        if throttle.allow("port_scan", "203.0.113.77"):
            notifier.notify(_alert(atype="port_scan", ip="203.0.113.77"))
        assert time.monotonic() - t0 < 5, "delivery was delayed"


class _SmtpSink:
    """A minimal SMTP server good enough for `smtplib.SMTP` + send_message."""

    def __init__(self):
        self.host = "127.0.0.1"
        self.port = None
        self.messages = []
        self._sock = None
        self._thread = None

    def start(self):
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, 0))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(4)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _session(self, conn):
        f = conn.makefile("rwb")

        def say(line):
            f.write(line.encode() + b"\r\n")
            f.flush()

        say("220 sink ready")
        data_mode = False
        body = []
        try:
            while True:
                raw = f.readline()
                if not raw:
                    break
                line = raw.decode(errors="replace").rstrip("\r\n")
                if data_mode:
                    if line == ".":
                        data_mode = False
                        self.messages.append("\n".join(body))
                        body = []
                        say("250 ok")
                    else:
                        body.append(line)
                    continue
                up = line.upper()
                if up.startswith("EHLO") or up.startswith("HELO"):
                    # Deliberately does NOT advertise STARTTLS: this sink models
                    # a plain internal relay (port 25 style). Advertising it
                    # without implementing TLS made the channel fail with
                    # WRONG_VERSION_NUMBER, which is a sink bug, not a product one.
                    say("250-sink")
                    say("250 8BITMIME")
                elif up.startswith("STARTTLS"):
                    # Refuse, as a relay without TLS support would.
                    say("502 command not implemented")
                elif up.startswith("AUTH"):
                    say("235 authenticated")
                elif up.startswith("MAIL FROM"):
                    say("250 ok")
                elif up.startswith("RCPT TO"):
                    say("250 ok")
                elif up.startswith("DATA"):
                    data_mode = True
                    say("354 send data")
                elif up.startswith("QUIT"):
                    say("221 bye")
                    break
                elif up.startswith("RSET"):
                    say("250 ok")
                else:
                    say("250 ok")
        except Exception:
            pass
        finally:
            try:
                f.close()
            except Exception:
                pass
            conn.close()

    def stop(self):
        try:
            self._sock.close()
        except Exception:
            pass