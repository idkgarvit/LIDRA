import logging
import struct
from typing import Dict, List, Optional, Tuple
from threading import Lock
from utils.config_loader import get_cfg

logger = logging.getLogger(__name__)

_KNOWN_MALICIOUS_JA4: set = set()


def _load_ja4_db():
    global _KNOWN_MALICIOUS_JA4
    fingerprints = get_cfg("tls_fingerprints.malicious_ja4", [])
    _KNOWN_MALICIOUS_JA4 = set(fingerprints)


def _ja4_trunc(value: int) -> str:
    if value > 0xFFFF:
        return hex(value)[2:6]
    if value > 0xFF:
        return hex(value)[2:4]
    return f"{value:02x}"


def _cipher_group(ciphers: List[int]) -> str:
    groups = []
    for c in ciphers[:8]:
        groups.append(f"{c:04x}")
    return "_".join(groups) if groups else "00"


def _ext_group(extensions: List[int]) -> str:
    groups = []
    for e in extensions:
        groups.append(f"{e:04x}")
    return "_".join(groups[:6]) if groups else "00"


def _first_alpn(ext_data: bytes) -> str:
    if len(ext_data) < 2:
        return "00"
    alpn_len = struct.unpack(">H", ext_data[:2])[0]
    offset = 2
    alpns = []
    while offset + 1 < len(ext_data) and offset < 2 + alpn_len:
        proto_len = ext_data[offset]
        offset += 1
        if offset + proto_len <= len(ext_data):
            alpns.append(ext_data[offset:offset + proto_len].decode("ascii", errors="replace"))
            offset += proto_len
        else:
            break
    return alpns[0][:8] if alpns else "00"


def parse_tls_client_hello(data: bytes) -> Optional[Dict]:
    if len(data) < 5:
        return None
    content_type = data[0]
    if content_type != 0x16:
        return None
    version = struct.unpack(">H", data[1:3])[0]
    if version < 0x0301 or version > 0x0304:
        return None
    if len(data) < 5 + 4:
        return None
    handshake_type = data[5]
    if handshake_type != 0x01:
        return None
    if len(data) < 5 + 4 + 38:
        return None
    offset = 5 + 4
    client_version = struct.unpack(">H", data[offset:offset + 2])[0]
    offset += 2
    random = data[offset:offset + 32]
    offset += 32
    if offset + 1 > len(data):
        return None
    session_id_len = data[offset]
    offset += 1 + session_id_len
    if offset + 2 > len(data):
        return None
    cipher_len = struct.unpack(">H", data[offset:offset + 2])[0]
    offset += 2
    if offset + cipher_len > len(data):
        return None
    ciphers = []
    for i in range(0, cipher_len, 2):
        ciphers.append(struct.unpack(">H", data[offset + i:offset + i + 2])[0])
    offset += cipher_len
    if offset + 1 > len(data):
        return None
    comp_len = data[offset]
    offset += 1 + comp_len
    if offset + 2 > len(data):
        return None
    ext_len = struct.unpack(">H", data[offset:offset + 2])[0]
    offset += 2
    if offset + ext_len > len(data):
        ext_len = len(data) - offset
    ext_data = data[offset:offset + ext_len]
    extensions = []
    sni = None
    alpn_data = b""
    i = 0
    while i + 4 <= len(ext_data):
        ext_type = struct.unpack(">H", ext_data[i:i + 2])[0]
        ext_len_field = struct.unpack(">H", ext_data[i + 2:i + 4])[0]
        extensions.append(ext_type)
        if ext_type == 0x00 and ext_len_field > 5:
            sni_list_len = struct.unpack(">H", ext_data[i + 4:i + 6])[0]
            sni_offset = i + 6
            if sni_offset + 1 <= len(ext_data):
                sni_name_type = ext_data[sni_offset]
                sni_offset += 1
                if sni_offset + 2 <= len(ext_data):
                    sni_len = struct.unpack(">H", ext_data[sni_offset:sni_offset + 2])[0]
                    sni_offset += 2
                    if sni_offset + sni_len <= len(ext_data):
                        sni = ext_data[sni_offset:sni_offset + sni_len].decode("ascii", errors="replace")
        if ext_type == 0x10:
            alpn_data = ext_data[i + 4:i + 4 + ext_len_field]
        i += 4 + ext_len_field
    alpn = _first_alpn(alpn_data)
    proto = "tcp"
    ja4a = _cipher_group(ciphers)
    ja4b = _ext_group(extensions)
    ja4c = alpn
    ja4d = _ja4_trunc(client_version)
    ja4_hash = f"t{proto}a{ja4a}b{ja4b}c{ja4c}d{ja4d}"
    return {
        "ja4": ja4_hash,
        "sni": sni,
        "version": f"0x{client_version:04x}",
        "cipher_count": len(ciphers),
        "ext_count": len(extensions),
        "first_ciphers": ciphers[:3],
        "alpn": alpn,
    }


class TLSFingerprinter:
    def __init__(self, config: dict = None):
        self._config = config or {}
        self._lock = Lock()
        _load_ja4_db()

    def analyze(self, stream_data: bytes) -> Optional[Dict]:
        parsed = parse_tls_client_hello(stream_data)
        if not parsed:
            return None
        ja4 = parsed["ja4"]
        with self._lock:
            is_malicious = ja4 in _KNOWN_MALICIOUS_JA4
        if is_malicious:
            parsed["attack_type"] = "malicious_tls_fingerprint"
            parsed["severity"] = "high"
            parsed["details"] = f"Known malicious JA4: {ja4}"
            parsed["confidence"] = 0.9
            return parsed
        if parsed["sni"]:
            parsed["attack_type"] = "tls_fingerprint"
            parsed["severity"] = "info"
            parsed["details"] = f"JA4={ja4} SNI={parsed['sni']}"
            parsed["confidence"] = 0.1
        else:
            parsed["attack_type"] = "tls_fingerprint"
            parsed["severity"] = "info"
            parsed["details"] = f"JA4={ja4}"
            parsed["confidence"] = 0.1
        return parsed
