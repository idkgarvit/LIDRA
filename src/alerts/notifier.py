# src/alerts/notifier.py
"""Alert notification system for LIDRA."""

import logging
from abc import ABC, abstractmethod
from typing import List, Optional
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class Alert:
    """Security alert dataclass."""
    alert_type: str
    severity: str  # low, medium, high, critical
    ip_address: Optional[str]
    message: str
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class AlertChannel(ABC):
    """Base class for alert channels."""

    @abstractmethod
    def send(self, alert: Alert) -> bool:
        """Send alert. Returns success status."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass


class AlertNotifier:
    """Main alert notification orchestrator."""

    def __init__(self, channels: List[AlertChannel]):
        self.channels = channels

    def notify(self, alert: Alert) -> int:
        """Send alert to all channels. Returns success count."""
        success_count = 0
        for channel in self.channels:
            try:
                if channel.send(alert):
                    success_count += 1
                    logger.info(f"Alert sent to {channel.name}")
                else:
                    logger.warning(f"Alert failed for {channel.name}")
            except Exception as e:
                logger.error(f"Alert error for {channel.name}: {e}")
        return success_count

    def notify_all(self, alerts: List[Alert]) -> int:
        """Send multiple alerts. Returns total success count."""
        total = 0
        for alert in alerts:
            total += self.notify(alert)
        return total
