"""JA4 must be spec-shaped (FoxIO) so dataset fingerprints can match."""
import re
import struct
import sys
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import detection.fingerprint.tls_fingerprinter as tfp  # noqa: E402

JA4_RE = re.compile(r"^t1[0-3][di]\d{4}([0-9a-z]{2}|00)_[0-9a-f]{12}_[0-9a-f]{12}$")


def _hello(ciphers, exts, version=0x0303):
    body = struct.pack(">H", version) + b"R" * 32
    body += b"\x00"  # session id len
    body += struct.pack(">H", len(ciphers) * 2)
    for c in ciphers:
        body += struct.pack(">H", c)
    body += b"\x01\x00"  # compression
    ext_blob = b"".join(struct.pack(">HH", t, len(d)) + d for t, d in exts)
    body += struct.pack(">H", len(ext_blob)) + ext_blob
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def _sni_ext(host=b"example.com"):
    inner = b"\x00" + struct.pack(">H", len(host)) + host
    return (0x00, struct.pack(">H", len(inner)) + inner)


CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
EXTS = [(0x00, b"\x00"), (0x10, b"\x00\x02h2"), (0x0B, b"\x01\x02"), (43, b"\x02\x03\x04")]


def test_format_and_determinism():
    pkt = _hello(CIPHERS, EXTS)
    a = tfp.parse_tls_client_hello(pkt)["ja4"]
    b = tfp.parse_tls_client_hello(pkt)["ja4"]
    assert JA4_RE.match(a), a
    assert a == b


def test_sni_flag_and_tls13():
    with_sni = tfp.parse_tls_client_hello(_hello(CIPHERS, [_sni_ext()] + EXTS[1:]))["ja4"]
    no_sni = tfp.parse_tls_client_hello(_hello(CIPHERS, EXTS[1:]))["ja4"]
    assert with_sni[3] == "d" and no_sni[3] == "i"
    assert with_sni.startswith("t13")  # 0x0303 + supported_versions(43)


def test_known_malicious_matches():
    pkt = _hello(CIPHERS, EXTS)
    fp = tfp.parse_tls_client_hello(pkt)
    tfp._KNOWN_MALICIOUS_JA4 = {fp["ja4"]}
    try:
        eng = tfp.TLSFingerprinter.__new__(tfp.TLSFingerprinter)
        eng._lock = threading.Lock()  # skip __init__ (would reload JA4 db from disk)
        hit = eng.analyze(pkt)
    finally:
        tfp._KNOWN_MALICIOUS_JA4 = set()
    assert hit["attack_type"] == "malicious_tls_fingerprint"
    assert hit["severity"] == "high"
