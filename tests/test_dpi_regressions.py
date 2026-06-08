"""Regression tests for bugs found by the pcap replay harness.

These are unit-level tests for specific bugs the harness discovered.
Each one documents the bug, the broken code, and the fix.
"""
import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC))

from detection.dpi_engine import DPIEngine  # noqa: E402


class TestDPIEngineRegressions:
    """Bugs that were found by replaying real attack pcaps through LIDRA."""

    def test_dpi_decode_handles_none(self):
        """Bug: `_decode(None)` crashed with AttributeError on
        unquote_plus(None) when `transfer-encoding` was absent and
        body defaulted to None in multipart path.

        Fix: `_decode` now returns "" on falsy input.
        """
        dpi = DPIEngine()
        assert dpi._decode(None) == ""
        assert dpi._decode("") == ""
        assert dpi._decode(0) == ""

    def test_dpi_http_parser_preserves_spaces_in_uri(self):
        """Bug: `_parse_http` split the request line on space, cutting
        the URI at the first space. SQLi payloads like
        `GET /search?query=' OR '1'='1` have unencoded spaces, so the
        parser saw `uri="/search?query='"`, missing the actual attack.

        Fix: parse URI as `parts[1:-1]` (everything between first method
        and last HTTP version token).
        """
        dpi = DPIEngine()
        # Classic SQLi with unencoded spaces
        http = (b"GET /search?query=' OR '1'='1 -- HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\nUser-Agent: Test\r\n\r\n")
        parsed = dpi._parse_http(http)
        assert parsed is not None
        assert "OR" in parsed["uri"]
        assert "'1'='1" in parsed["uri"]

    def test_dpi_detects_sqli_in_url_with_spaces(self):
        """End-to-end: full SQLi request with spaces should be detected."""
        dpi = DPIEngine()
        http = (b"GET /search?query=' OR '1'='1 -- HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n\r\n")
        result = dpi.inspect_stream(http, "http")
        assert result is not None
        assert result.attack_type == "sql_injection"
        assert result.severity == "critical"

    def test_dpi_http_parser_preserves_normal_request(self):
        """Ensure the URI parser fix didn't break normal requests."""
        dpi = DPIEngine()
        http = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        parsed = dpi._parse_http(http)
        assert parsed["method"] == "GET"
        assert parsed["uri"] == "/index.html"
        assert parsed["headers"]["host"] == "example.com"

    def test_dpi_http_parser_handles_h2_preface(self):
        """HTTP/2 preface 'PRI * HTTP/2.0' should still be detected."""
        dpi = DPIEngine()
        h2 = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        parsed = dpi._parse_http(h2)
        assert parsed is not None
        assert parsed.get("http2") is True

    def test_tls_fingerprint_fires_through_dpi_engine(self):
        """C1: TLS ClientHello should produce a tls_fingerprint detection
        through inspect_stream(). Before the fix, the TLS branch in
        inspect_stream() only checked for malicious_jA4 fingerprints;
        benign ClientHello traffic was silently ignored, so the pipeline
        never picked up the fingerprint.
        """
        import struct

        dpi = DPIEngine()

        # Build a real-looking TLS ClientHello with a valid SNI extension
        sni_name = b"example.com"
        sni_entry = struct.pack("B", 0) + struct.pack(">H", len(sni_name)) + sni_name
        sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
        sni_extension = (
            struct.pack(">H", 0x0000)
            + struct.pack(">H", len(sni_list))
            + sni_list
        )
        extensions_block = struct.pack(">H", len(sni_extension)) + sni_extension

        random_bytes = b"\x02" * 32
        ciphers_body = struct.pack(">HHHH", 0x1301, 0x1302, 0x1303, 0xC02B)
        ciphers = struct.pack(">H", len(ciphers_body)) + ciphers_body
        session_id = struct.pack("B", 0)
        compression = struct.pack("B", 0)

        client_hello = (
            struct.pack(">H", 0x0303)  # TLS 1.2
            + random_bytes
            + session_id
            + ciphers
            + compression
            + extensions_block
        )
        hello_len = len(client_hello)
        handshake = struct.pack("B", 0x01) + struct.pack(">I", hello_len)[1:] + client_hello
        record_len = len(handshake)
        tls_record = (
            struct.pack("B", 0x16)  # Handshake content type
            + struct.pack(">H", 0x0303)
            + struct.pack(">H", record_len)
            + handshake
        )

        result = dpi.inspect_stream(tls_record, "tls")

        assert result is not None
        assert result.attack_type == "tls_fingerprint"
        assert result.severity == "info"
        assert "JA4=" in result.details
