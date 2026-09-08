# src/alerts/slack.py
"""Slack webhook integration."""

import requests
import logging
from .notifier import AlertChannel, Alert

logger = logging.getLogger(__name__)


class SlackChannel(AlertChannel):
    """Slack webhook alert channel."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    @property
    def name(self) -> str:
        return "Slack"

    def send(self, alert: Alert) -> bool:
        """Send alert to Slack."""
        if not self.webhook_url:
            return False

        color = {
            'low': '#36a64f',
            'medium': '#ff9800',
            'high': '#f44336',
            'critical': '#9c27b0'
        }.get(alert.severity, '#808080')

        payload = {
            "attachments": [{
                "color": color,
                "title": f"LIDRA Alert: {alert.alert_type}",
                "fields": [
                    {"title": "Severity", "value": alert.severity.upper(), "short": True},
                    {"title": "IP Address", "value": alert.ip_address or "N/A", "short": True},
                    {"title": "Message", "value": alert.message, "short": False}
                ],
                "ts": int(alert.timestamp.timestamp())
            }]
        }

        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Slack alert failed: {e}")
            return False
