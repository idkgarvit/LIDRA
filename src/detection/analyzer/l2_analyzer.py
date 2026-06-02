import logging
import time
from collections import defaultdict
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class L2Analyzer:
    def __init__(self):
        self._arp_cache: Dict[str, str] = {}
        self._arp_flap: Dict[str, int] = defaultdict(int)
        self._mac_tracker: Dict[str, List[str]] = defaultdict(list)
        self._broadcast_counts: Dict[str, int] = defaultdict(int)
        self._last_cleanup = time.time()

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        detections = []
        self._cleanup_if_needed()

        src_ip = packet.get("src_ip", "")
        src_mac = packet.get("src_mac", "")
        eth_type = packet.get("eth_type", 0)
        raw_len = packet.get("raw_len", 0)

        if eth_type == 0x0806:
            r = self._check_arp_spoof(src_ip, src_mac, packet)
            if r:
                detections.append(r)

        if src_mac and src_ip:
            self._mac_tracker[src_ip].append(src_mac)
            macs = self._mac_tracker[src_ip]
            if len(set(macs)) >= 3:
                detections.append({
                    "attack_type": "mac_spoofing",
                    "severity": "high",
                    "source_ip": src_ip,
                    "details": f"IP {src_ip} used multiple MACs: {set(macs)}",
                })
                self._mac_tracker[src_ip] = []

        if src_ip:
            self._broadcast_counts[src_ip] += 1
            if self._broadcast_counts[src_ip] > 500:
                detections.append({
                    "attack_type": "broadcast_storm",
                    "severity": "high",
                    "source_ip": src_ip,
                    "details": f"Broadcast storm: {self._broadcast_counts[src_ip]} pkts from {src_ip}",
                })

        if raw_len > 9000:
            detections.append({
                "attack_type": "jumbo_frame",
                "severity": "low",
                "source_ip": src_ip,
                "details": f"Jumbo frame: {raw_len} bytes",
            })

        return detections if detections else None

    def _check_arp_spoof(self, ip, mac, packet):
        now = time.time()
        if ip in self._arp_cache:
            old_mac = self._arp_cache[ip]
            if old_mac != mac:
                self._arp_flap[ip] += 1
                if self._arp_flap[ip] >= 3:
                    return {
                        "attack_type": "arp_spoofing",
                        "severity": "critical",
                        "source_ip": ip,
                        "details": f"ARP cache poison: {old_mac} -> {mac} ({self._arp_flap[ip]} flips)",
                    }
        else:
            self._arp_cache[ip] = mac
        return None

    def _cleanup_if_needed(self):
        if time.time() - self._last_cleanup > 60:
            self._arp_flap.clear()
            self._broadcast_counts.clear()
            self._last_cleanup = time.time()
