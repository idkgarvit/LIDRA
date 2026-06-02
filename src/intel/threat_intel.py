# src/intel/threat_intel.py
"""Threat Intelligence integration for LIDRA."""

from abc import ABC, abstractmethod
from typing import Optional, Dict
import logging

logger = logging.getLogger(__name__)


class ThreatIntelProvider(ABC):
    """Base class for threat intelligence providers."""

    @abstractmethod
    def lookup_ip(self, ip: str) -> Optional[Dict]:
        pass

    @abstractmethod
    def report_ip(self, ip: str, category: int, comment: str = "") -> bool:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass


class ThreatIntelOrchestrator:
    """Orchestrates multiple threat intel providers."""

    def __init__(self, providers: list, check_on_detect: bool = True):
        self.providers = providers
        self.check_on_detect = check_on_detect
        self._cache = {}

    def lookup_ip(self, ip: str) -> Dict:
        if ip in self._cache:
            return self._cache[ip]

        results = {
            'ip': ip,
            'providers_checked': 0,
            'threat_score': 0,
            'is_malicious': False,
            'details': {}
        }

        for provider in self.providers:
            try:
                data = provider.lookup_ip(ip)
                if data:
                    results['providers_checked'] += 1
                    results['details'][provider.name] = data
                    if 'abuse_score' in data:
                        results['threat_score'] = max(results['threat_score'], data['abuse_score'])
                    if 'malicious' in data and data['malicious']:
                        results['is_malicious'] = True
            except Exception as e:
                logger.error(f"{provider.name} lookup failed: {e}")

        if results['threat_score'] >= 50:
            results['is_malicious'] = True

        self._cache[ip] = results
        return results

    def report_ip(self, ip: str, category: int = 18, comment: str = ""):
        for provider in self.providers:
            try:
                success = provider.report_ip(ip, category, comment)
                if success:
                    logger.info(f"Reported {ip} to {provider.name}")
            except Exception as e:
                logger.error(f"Failed to report to {provider.name}: {e}")
