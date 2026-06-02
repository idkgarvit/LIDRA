# src/intel/virustotal.py
"""VirusTotal integration."""

import requests
import logging
from typing import Optional, Dict
from .threat_intel import ThreatIntelProvider

logger = logging.getLogger(__name__)


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal threat intelligence provider."""

    API_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            'x-apikey': api_key,
            'Accept': 'application/json'
        }

    @property
    def name(self) -> str:
        return "VirusTotal"

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        try:
            response = requests.get(
                f"{self.API_URL}/ip_addresses/{ip}",
                headers=self.headers,
                timeout=10
            )
            if response.status_code == 404:
                return None
            response.raise_for_status()
            data = response.json()

            if 'data' in data and 'attributes' in data['data']:
                attrs = data['data']['attributes']
                stats = attrs.get('last_analysis_stats', {})
                total = stats.get('harmless', 0) + stats.get('malicious', 0) + stats.get('suspicious', 0)

                return {
                    'malicious': stats.get('malicious', 0) > 0,
                    'malicious_count': stats.get('malicious', 0),
                    'suspicious_count': stats.get('suspicious', 0),
                    'harmless_count': stats.get('harmless', 0),
                    'total_vendors': total,
                    'reputation': attrs.get('reputation', 0),
                    'country': attrs.get('country', ''),
                    'asn': attrs.get('asn', 0)
                }
        except requests.exceptions.RequestException as e:
            logger.warning(f"VirusTotal lookup failed for {ip}: {e}")
        return None

    def report_ip(self, ip: str, category: int = 18, comment: str = "") -> bool:
        return False  # VT doesn't support IP reporting
