# src/alerts/email_alert.py
"""Email alert integration."""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List
from .notifier import AlertChannel, Alert

logger = logging.getLogger(__name__)


class EmailChannel(AlertChannel):
    """SMTP email alert channel."""

    def __init__(self, smtp_host: str, smtp_port: int, username: str,
                 password: str, from_addr: str, to_addrs: List[str]):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addrs = to_addrs

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

        try:
            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)
            server.quit()
            return True
        except Exception as e:
            logger.error(f"Email alert failed: {e}")
            return False
