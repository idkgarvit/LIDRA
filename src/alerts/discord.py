# src/alerts/discord.py
"""Discord webhook integration."""

import requests
import logging
from .notifier import AlertChannel, Alert

logger = logging.getLogger(__name__)


class DiscordChannel(AlertChannel):
    """Discord webhook alert channel."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    @property
    def name(self) -> str:
        return "Discord"

    def send(self, alert: Alert) -> bool:
        if not self.webhook_url:
            return False

        color = {
            'low': 3066993,
            'medium': 15158332,
            'high': 15105570,
            'critical': 10181046
        }.get(alert.severity, 8421504)

        payload = {
            "embeds": [{
                "title": f"LIDRA Alert: {alert.alert_type}",
                "color": color,
                "fields": [
                    {"name": "Severity", "value": alert.severity.upper(), "inline": True},
                    {"name": "IP Address", "value": alert.ip_address or "N/A", "inline": True},
                    {"name": "Message", "value": alert.message, "inline": False}
                ]
            }]
        }

        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            return response.status_code == 204
        except Exception as e:
            logger.error(f"Discord alert failed: {e}")
            return False
