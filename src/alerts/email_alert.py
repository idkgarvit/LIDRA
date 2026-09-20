"""Email alert integration."""

import logging
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional

from .notifier import AlertChannel, Alert

logger = logging.getLogger(__name__)

# Default SMTP timeout. `smtplib.SMTP()`'s own default is *infinite*, and the
# notifier runs on the same worker thread that writes rows and pushes TUI
# events — so an unreachable mail host without a timeout does not just lose an
# alert, it backpressures the verdict path. Measured before this was set: a
# send to an unroutable address blocked for **133 s**.
DEFAULT_TIMEOUT_SECONDS = 10.0


class EmailChannel(AlertChannel):
    """SMTP email alert channel.

    Transport is chosen from the port unless overridden, because the previous
    unconditional ``starttls()`` could only ever work on 587:

    * **465** — implicit TLS (``SMTP_SSL``); STARTTLS on top of it fails.
    * **587** — plain connect then STARTTLS (the submission port).
    * **anything else (e.g. 25)** — plain connect, no STARTTLS; many internal
      relays do not offer it, and the old code failed the send outright.

    Pass ``use_starttls=True/False`` to force the behaviour, and
    ``use_ssl=True/False`` to force implicit TLS.
    """

    def __init__(self, smtp_host: str, smtp_port: int, username: str,
                 password: str, from_addr: str, to_addrs: List[str],
                 timeout: float = DEFAULT_TIMEOUT_SECONDS,
                 use_starttls: Optional[bool] = None,
                 use_ssl: Optional[bool] = None):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        self.timeout = float(timeout)
        if use_ssl is None:
            use_ssl = int(smtp_port) == 465
        if use_starttls is None:
            use_starttls = int(smtp_port) == 587
        self.use_ssl = bool(use_ssl)
        self.use_starttls = False if self.use_ssl else bool(use_starttls)

    @property
    def name(self) -> str:
        return "Email"

    def send(self, alert: Alert) -> bool:
        if not self.smtp_host or not self.to_addrs:
            return False

        msg = MIMEMultipart()
        msg['From'] = self.from_addr
        msg['To'] = ', '.join(self.to_addrs)
        msg['Subject'] = f"[LIDRA] {alert.severity.upper()}: {alert.alert_type}"

        body = f"""
LIDRA Security Alert

Type: {alert.alert_type}
Severity: {alert.severity.upper()}
IP Address: {alert.ip_address or 'N/A'}
Time: {alert.timestamp.isoformat()}

Details:
{alert.message}

---
LIDRA IDS
"""
        msg.attach(MIMEText(body, 'plain'))

        server = None
        try:
            if self.use_ssl:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port,
                                          timeout=self.timeout,
                                          context=ssl.create_default_context())
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port,
                                      timeout=self.timeout)
                if self.use_starttls:
                    server.starttls(context=ssl.create_default_context())
            if self.username:
                server.login(self.username, self.password)
            server.send_message(msg)
            return True
        except Exception as e:
            logger.error(f"Email alert failed: {e}")
            return False
        finally:
            # Always tear the connection down: a half-open SMTP session holds a
            # socket and, on a throttled server, a slot.
            if server is not None:
                try:
                    server.quit()
                except Exception:
                    try:
                        server.close()
                    except Exception:
                        pass
