# src/intel/abuseipdb.py
"""AbuseIPDB integration."""

import requests
import logging
from typing import Optional, Dict
from .threat_intel import ThreatIntelProvider

logger = logging.getLogger(__name__)


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB threat intelligence provider."""

    API_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }

    @property
    def name(self) -> str:
        return "AbuseIPDB"

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        try:
            response = requests.get(
                f"{self.API_URL}/check",
                headers=self.headers,
                params={'ipAddress': ip, 'maxAgeInDays': 90},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            if 'data' in data:
                return {
                    'abuse_score': data['data'].get('abuseConfidenceScore', 0),
                    'usage_type': data['data'].get('usageType', 'unknown'),
                    'country': data['data'].get('countryCode', ''),
                    'isp': data['data'].get('isp', ''),
                    'is_whitelisted': data['data'].get('isWhitelisted', False),
                    'total_reports': data['data'].get('totalReports', 0)
                }
        except requests.exceptions.RequestException as e:
            logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
        return None

    def report_ip(self, ip: str, category: int = 18, comment: str = "") -> bool:
        try:
            response = requests.post(
                f"{self.API_URL}/report",
                headers=self.headers,
                data={
                    'ip': ip,
                    'categories': str(category),
                    'comment': comment or 'Automated report from LIDRA IDS - SSH bruteforce attempt'
                },
                timeout=10
            )
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to report {ip} to AbuseIPDB: {e}")
            return False
