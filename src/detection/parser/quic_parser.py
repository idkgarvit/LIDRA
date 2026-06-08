import logging
import struct
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

QUIC_LONG_HEADER_MASK = 0x80
QUIC_FIXED_BIT_MASK = 0x40
QUIC_VERSION_MASK = 0x0F

QUIC_INITIAL = 0x00
QUIC_HANDSHAKE = 0x02
QUIC_1RTT = 0x03

QUIC_V1 = 0x00000001
QUIC_V2 = 0x6b3343cf

GQUIC_V1 = 0x51303130
GQUIC_V2 = 0x51303230


def parse_quic_initial(payload: bytes) -> Optional[Dict]:
    if len(payload) < 5:
        return None
    first_byte = payload[0]
    if not (first_byte & QUIC_LONG_HEADER_MASK):
        return None
    if not (first_byte & QUIC_FIXED_BIT_MASK):
        return None

    form = "long"
    pkt_type = (first_byte >> 4) & 0x03

    if len(payload) < 6:
        return None
    version = struct.unpack(">I", payload[1:5])[0]

    offset = 5
    if offset + 4 > len(payload):
        return None
    dcil = payload[offset] >> 4
    scil = payload[offset] & 0x0F
    offset += 1

    dst_conn_id = b""
    if dcil > 0 and dcil <= 20 and offset + dcil <= len(payload):
        dst_conn_id = payload[offset:offset + dcil]
        offset += dcil
    else:
        return None

    src_conn_id = b""
    if scil > 0 and scil <= 20 and offset + scil <= len(payload):
        src_conn_id = payload[offset:offset + scil]
        offset += scil

    result = {
        "form": form,
        "packet_type": ["initial", "0rtt", "handshake", "retry"][pkt_type] if pkt_type < 4 else "unknown",
        "version": _format_version(version),
        "version_num": version,
        "dst_conn_id": dst_conn_id.hex(),
        "src_conn_id": src_conn_id.hex(),
        "is_gquic": version in (GQUIC_V1, GQUIC_V2),
    }

    if pkt_type == QUIC_INITIAL or pkt_type == QUIC_HANDSHAKE:
        if offset + 4 > len(payload):
            return result
        token_len = 0
        if pkt_type == QUIC_INITIAL:
            token_len = struct.unpack(">I", payload[offset:offset + 4])[0]
            offset += 4
            if offset + token_len > len(payload):
                return result
            offset += token_len
        if offset + 4 <= len(payload):
            pkt_num_len = (payload[offset] & 0x03) + 1
            offset += 1
            if offset + pkt_num_len <= len(payload):
                result["packet_number"] = int.from_bytes(
                    payload[offset:offset + pkt_num_len], "big"
                )
                offset += pkt_num_len
                if offset + 4 <= len(payload):
                    result["payload_length"] = len(payload) - offset
                    result["crypto_data"] = payload[offset:].hex()[:64]

    return result


def _format_version(version: int) -> str:
    if version == QUIC_V1:
        return "QUICv1"
    if version == QUIC_V2:
        return "QUICv2"
    if version == GQUIC_V1:
        return "gQUICv1"
    if version == GQUIC_V2:
        return "gQUICv2"
    b = struct.pack(">I", version)
    if all(32 <= c < 127 for c in b):
        return b.decode("ascii", errors="replace")
    return f"0x{version:08x}"


def classify_quic_version(version: int) -> str:
    if version == QUIC_V1:
        return "ietf_v1"
    if version == QUIC_V2:
        return "ietf_v2"
    if version in (GQUIC_V1, GQUIC_V2):
        return "gquic"
    return "unknown"
