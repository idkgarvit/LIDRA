import logging
import struct
import time
from threading import Lock
from typing import Dict, Optional, Tuple
import unicodedata

logger = logging.getLogger(__name__)

_OVERLAP_LOG: Dict = {}
_TCP_TS_LOG: Dict[str, float] = {}
_PAWS_MAX_DIST = 0x7FFFFFFF
_TS_LOCK = Lock()
_OVERLAP_LOCK = Lock()
_MAX_TS_ENTRIES = 10000
_MAX_OVERLAP_ENTRIES = 5000


def check_ttl_enforcement(ip_ttl: int, expected_min: int = 64) -> Optional[Dict]:
    if ip_ttl < expected_min:
        return {
            "attack_type": "ttl_anomaly",
            "severity": "medium",
            "details": f"Low TTL ({ip_ttl} vs expected {expected_min}) — possible path hopping or evasion",
            "confidence": min(0.3 + (expected_min - ip_ttl) * 0.01, 0.8),
        }
    return None


def check_bad_checksum_rst(tcp_header: bytes, ip_pseudo: bytes, total_len: int) -> Optional[Dict]:
    if len(tcp_header) < 14:
        return None
    flags = tcp_header[13]
    if flags & 0x04 == 0:
        return None
    if len(tcp_header) < 16:
        return None
    provided_cksum = struct.unpack(">H", tcp_header[16:18])[0]
    if provided_cksum == 0:
        return None
    zeroed = bytearray(tcp_header)
    zeroed[16] = 0
    zeroed[17] = 0
    cksum_data = ip_pseudo + bytes(zeroed)
    if len(cksum_data) % 2:
        cksum_data += b'\x00'
    total = 0
    for i in range(0, len(cksum_data), 2):
        total += struct.unpack(">H", cksum_data[i:i + 2])[0]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    computed = (~total) & 0xFFFF
    if computed != provided_cksum:
        return {
            "attack_type": "bad_checksum_rst",
            "severity": "medium",
            "details": f"RST with invalid checksum: provided={provided_cksum:04x} computed={computed:04x}",
            "confidence": 0.85,
        }
    return None


def check_ip_frag_overlap(ip_id: int, frag_offset: int, more_frags: bool, proto: str, total_len: int) -> Optional[Dict]:
    key = (ip_id, frag_offset)
    with _OVERLAP_LOCK:
        if key in _OVERLAP_LOG:
            return {
                "attack_type": "ip_frag_overlap",
                "severity": "high",
                "details": f"TCP fragmentation offset={frag_offset} — RFC 5722 risk",
                "confidence": 0.5,
            }
        _OVERLAP_LOG[key] = time.time()
        if len(_OVERLAP_LOG) > _MAX_OVERLAP_ENTRIES:
            cutoff = time.time() - 300
            for k in [k for k, v in _OVERLAP_LOG.items() if v < cutoff]:
                del _OVERLAP_LOG[k]
    return None


def check_ipv6_atomic_frag(ipv6_payload: bytes) -> Optional[Dict]:
    if len(ipv6_payload) < 8:
        return None
    next_header = ipv6_payload[0] if len(ipv6_payload) > 0 else 0
    if next_header == 44:
        return {
            "attack_type": "ipv6_atomic_fragment",
            "severity": "high",
            "details": "IPv6 atomic fragment (RFC 7112 violation)",
            "confidence": 0.9,
        }
    return None


def check_qinq_double_vlan(eth_type: int, payload: bytes) -> Optional[Dict]:
    if eth_type == 0x8100 and len(payload) >= 4:
        inner_eth_type = struct.unpack(">H", payload[2:4])[0]
        if inner_eth_type == 0x8100:
            return {
                "attack_type": "qinq_double_vlan",
                "severity": "low",
                "details": "Double 802.1Q VLAN tag (QinQ) detected",
                "confidence": 0.8,
            }
    return None


def _trim_ts_cache():
    global _TCP_TS_LOG
    if len(_TCP_TS_LOG) > _MAX_TS_ENTRIES:
        cutoff = time.time() - 3600
        _TCP_TS_LOG = {k: v for k, v in _TCP_TS_LOG.items() if v > cutoff}


def check_tcp_paws(tcp_options: bytes, src_ip: str) -> Optional[Dict]:
    if len(tcp_options) < 10:
        return None
    i = 0
    while i < len(tcp_options):
        kind = tcp_options[i]
        if kind == 8:
            if i + 10 <= len(tcp_options):
                ts_val = struct.unpack(">I", tcp_options[i + 2:i + 6])[0]
                with _TS_LOCK:
                    prev = _TCP_TS_LOG.get(src_ip, 0)
                    if prev and ts_val < prev and (prev - ts_val) < _PAWS_MAX_DIST:
                        return {
                            "attack_type": "tcp_paws_violation",
                            "severity": "medium",
                            "details": f"TCP timestamp went backwards: {prev} → {ts_val} (possible PAWS attack)",
                            "confidence": 0.7,
                        }
                    _TCP_TS_LOG[src_ip] = ts_val
                    _trim_ts_cache()
            break
        if kind == 0:
            break
        if kind == 1:
            i += 1
        else:
            i += 2 + tcp_options[i + 1]
    return None


def check_content_type_normalization(content_type: str) -> Optional[Dict]:
    manipulations = [
        ("text/plain", False),
        ("text/html", True),
    ]
    ct_lower = content_type.lower()
    for manipulation, is_attack in manipulations:
        if manipulation in ct_lower:
            return None
    if "javascript" in ct_lower or "ecmascript" in ct_lower:
        return None
    return None


def normalize_unicode(text: str) -> Optional[Tuple[str, Optional[Dict]]]:
    nfc = unicodedata.normalize("NFC", text)
    nfkc = unicodedata.normalize("NFKC", text)
    if nfc != nfkc:
        return nfkc, {
            "attack_type": "unicode_normalization",
            "severity": "medium",
            "details": f"Unicode confusables detected: NFC={repr(nfc[:50])} vs NFKC={repr(nfkc[:50])}",
            "confidence": 0.6,
        }
    if nfc != text:
        return nfc, None
    return text, None
