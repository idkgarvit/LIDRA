"""Generate the TLS capture pair that closes the "no TLS pcap at all" gap.

Why this file exists
--------------------
Before this, the repository had **no** TLS capture in `tests/attack_pcap/`.
That is exactly how the observation-severity leak (see
`docs/PRODUCTION_READINESS.md` §0.1.1) stayed invisible: the benign baseline
contained zero TCP/443 packets, so the FP numbers could not show it.

Two captures are produced:

* ``benign/https_traffic.pcap`` — ordinary ClientHellos (with SNI) from many
  peers. This is the "normal HTTPS must not become an attack" baseline.
* ``tls/malicious_clienthello.pcap`` — a ClientHello crafted so its JA4 matches
  a **synthetic** blocklist entry supplied by the test.

On the malicious fixture — why it is synthetic and says so
---------------------------------------------------------
A JA4's `b` and `c` components are ``sha256(...)[:12]`` — 48 bits each. Matching
one of the 9 published hashes in ``config/config.yaml`` would therefore require
an infeasible ~2^48 preimage search; you cannot "craft a Cobalt Strike
ClientHello" from a published hash. So this capture is built the other way
round: craft a hello, compute its JA4, and let the test add *that* hash to its
own blocklist. The match is synthetic and the test states it. It exercises the
real detection and response path; it does not claim to be real malware traffic.

The published list in ``config/config.yaml`` is deliberately not touched.

Run from the repo root:
    .venv/bin/python tests/attack_pcap/_generate_tls_pcaps.py
"""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

import dpkt

HERE = Path(__file__).resolve().parent

# A Chrome-like cipher list and extension set: ordinary, modern, not malicious.
BROWSER_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC030, 0xCCA8, 0xCCA9]
BROWSER_EXTS_BASE = [
    (0x0B, b"\x01\x00"),       # ec_point_formats
    (0x10, b"\x00\x05h2h2-14"),  # ALPN: h2, http/1.1
    (0x2B, b"\x03\x04\x03\x03"),  # supported_versions incl. TLS 1.3
    (0x0D, b"\x00\x08\x04\x03\x08\x04\x04\x01"),  # signature_algorithms
]

# A deliberately different shape for the malicious fixture: a minimal,
# tool-like hello (one TLS1.3 suite, sparse extensions, no SNI). It is the
# *shape* a C2 beacon tends to have, but the hash match the test asserts is
# synthetic — see the module docstring.
TOOL_CIPHERS = [0x1301]
TOOL_EXTS = [(0x0B, b"\x01\x00"), (0x2B, b"\x03\x04\x03\x04")]


def sni_ext(host: bytes):
    inner = b"\x00" + struct.pack(">H", len(host)) + host
    return (0x00, struct.pack(">H", len(inner)) + inner)


def client_hello(ciphers, exts, version=0x0303, random_fill=b"R") -> bytes:
    """A well-formed TLS ClientHello record."""
    body = struct.pack(">H", version) + (random_fill * 32) + b"\x00"
    body += struct.pack(">H", len(ciphers) * 2)
    for c in ciphers:
        body += struct.pack(">H", c)
    body += b"\x01\x00"
    blob = b"".join(struct.pack(">HH", t, len(d)) + d for t, d in exts)
    body += struct.pack(">H", len(blob)) + blob
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def frame_tcp(payload: bytes, sport: int, dport: int, src: str, dst: str,
              seq: int = 1, flags=None) -> bytes:
    flags = flags if flags is not None else (dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK)
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=1,
                       win=65535, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(src=b"\xaa" * 6, dst=b"\xbb" * 6,
                                 type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    return bytes(eth)


def write_pcap(path: Path, packets) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh)
        t = 1_700_000_000.0
        for i, (buf, ts_off) in enumerate(packets):
            w.writepkt(buf, ts=t + ts_off)
            n += 1
        w.close()
    return n


def build_benign() -> list:
    """N ordinary HTTPS conversations from N distinct clients."""
    packets = []
    server = "93.184.216.34"
    t = 0.0
    for client in range(12):
        src = f"198.51.100.{client + 10}"
        sport = 40000 + client
        # TCP handshake so the flow looks real
        packets.append((frame_tcp(b"", sport, 443, src, server,
                                  flags=dpkt.tcp.TH_SYN), t))
        packets.append((frame_tcp(b"", 443, sport, server, src,
                                  flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK), t))
        packets.append((frame_tcp(b"", sport, 443, src, server,
                                  flags=dpkt.tcp.TH_ACK), t))
        # The ClientHello — the packet whose JA4 observation must not be an attack
        hello = client_hello(
            BROWSER_CIPHERS,
            [sni_ext(f"site{client}.example.com".encode())] + BROWSER_EXTS_BASE,
            random_fill=bytes([client % 256]),
        )
        packets.append((frame_tcp(hello, sport, 443, src, server), t))
        # A little server response so the session is not degenerate
        packets.append((frame_tcp(b"\x16\x03\x03\x00\x2a" + b"srv" * 14, 443, sport,
                                  server, src), t))
        t += 0.05
    return packets


def build_malicious() -> list:
    """One ClientHello with a tool-like shape (hash matched synthetically)."""
    packets = []
    server = "203.0.113.200"
    src = "203.0.113.66"
    sport = 51000
    packets.append((frame_tcp(b"", sport, 443, src, server,
                              flags=dpkt.tcp.TH_SYN), 0.0))
    packets.append((frame_tcp(b"", 443, sport, server, src,
                              flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK), 0.0))
    packets.append((frame_tcp(b"", sport, 443, src, server,
                              flags=dpkt.tcp.TH_ACK), 0.0))
    hello = client_hello(TOOL_CIPHERS, TOOL_EXTS, random_fill=b"\x00")
    packets.append((frame_tcp(hello, sport, 443, src, server), 0.0))
    return packets


def main() -> int:
    sys.path.insert(0, str(HERE.parent.parent / "src"))
    from detection.fingerprint.tls_fingerprinter import parse_tls_client_hello

    benign = HERE / "benign" / "https_traffic.pcap"
    malicious = HERE / "tls" / "malicious_clienthello.pcap"

    nb = write_pcap(benign, build_benign())
    nm = write_pcap(malicious, build_malicious())

    benign_ja4 = parse_tls_client_hello(
        client_hello(BROWSER_CIPHERS,
                     [sni_ext(b"site0.example.com")] + BROWSER_EXTS_BASE,
                     random_fill=b"\x00"))["ja4"]
    malicious_ja4 = parse_tls_client_hello(
        client_hello(TOOL_CIPHERS, TOOL_EXTS, random_fill=b"\x00"))["ja4"]

    print(f"wrote {benign}  ({nb} packets)")
    print(f"  benign JA4  = {benign_ja4}")
    print(f"wrote {malicious}  ({nm} packets)")
    print(f"  tool-like JA4 = {malicious_ja4}   <- the test adds THIS to its blocklist")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())