import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_INVALID_FLAGS = [
    "FS", "FR", "SR",
]


class TCPFingerprinter:
    def __init__(self):
        self._source_ttls: Dict[str, List[int]] = defaultdict(list)
        self._source_isns: Dict[str, List[int]] = defaultdict(list)
        self._source_ips: Dict[str, int] = defaultdict(int)
        # Corroboration state for low_entropy_isn — see _check_isn_randomness.
        self._handshake_ok: Dict[str, bool] = {}
        self._handshake_fail: Dict[str, int] = defaultdict(int)
        self._syn_sent: Dict[str, int] = defaultdict(int)
        self._synack_seen: Dict[str, int] = defaultdict(int)
        self._last_cleanup = time.time()
        self._lock = Lock()

    def analyze(self, packet: Dict) -> Optional[List[Dict]]:
        with self._lock:
            return self._analyze_locked(packet)

    def _analyze_locked(self, packet: Dict) -> Optional[List[Dict]]:
        detections = []
        self._cleanup_if_needed()
        protocol = packet.get("protocol", "")
        if protocol != "tcp":
            return None

        src_ip = packet.get("src_ip", "")
        flags = packet.get("flags", "")
        ttl = packet.get("ttl", 0)
        tcp_seq = packet.get("tcp_seq", 0)
        src_port = packet.get("src_port", 0)
        dst_port = packet.get("dst_port", 0)

        # Feed the corroboration state before any verdict is reached, so the
        # decision for this packet sees the handshake evidence gathered so far.
        self._track_handshakes(packet, flags)

        r = self._check_flag_anomalies(flags)
        if r:
            detections.append(r)

        r = self._check_ttl_jitter(src_ip, ttl)
        if r:
            detections.append(r)

        r = self._check_isn_randomness(src_ip, tcp_seq, flags)
        if r:
            detections.append(r)

        r = self._check_rare_port_pairing(src_port, dst_port)
        if r:
            detections.append(r)

        return detections if detections else None

    def _track_handshakes(self, packet: Dict, flags: str) -> None:
        """Note, per TCP flow, whether connections actually complete.

        A SYN carrying no ACK opens a connection; a SYN-ACK addressed *to* that
        host proves the connection was answered. This is the evidence
        ``low_entropy_isn`` needs before it may claim a spoofed source: a spoofer
        never receives (or never cares about) the SYN-ACK, so its connections do
        not complete. Measured on the bundled corpora — benign traffic completes
        100% of handshakes, `nmap_syn_scan.pcap` 0.45%, `syn_flood.pcap` 0%.
        """
        if "S" not in flags:
            return
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        if "A" in flags:
            # SYN-ACK travelling server -> client: the client's SYN was answered.
            if dst_ip:
                self._handshake_ok[dst_ip] = True
                self._synack_seen[dst_ip] = self._synack_seen.get(dst_ip, 0) + 1
            return
        if src_ip:
            self._syn_sent[src_ip] = self._syn_sent.get(src_ip, 0) + 1

    def note_handshake(self, ip: str, *, completed: bool) -> None:
        """Record whether a client's connections complete.

        Kept for callers that already know the answer (tests, and any future
        capture source with conntrack access); ``_track_handshakes`` derives the
        same state from the packet stream when nothing calls this.
        """
        if not ip:
            return
        if completed:
            self._handshake_ok[ip] = True
        else:
            self._handshake_fail[ip] = self._handshake_fail.get(ip, 0) + 1

    def _looks_spoofed(self, ip: str) -> bool:
        """True when a low-entropy ISN is backed by failed-connection evidence.

        A completed handshake is positive proof of a real peer, so it vetoes the
        alert outright. Otherwise require unanswered SYNs — a source that opens
        connections nobody answers is the actual spoofed-flood signature. With no
        evidence either way we stay quiet: the ISN field alone is not sufficient
        to accuse a host (see _check_isn_randomness).
        """
        if self._handshake_ok.get(ip):
            return False
        if self._handshake_fail.get(ip, 0) >= 3:
            return True
        sent = self._syn_sent.get(ip, 0)
        answered = self._synack_seen.get(ip, 0)
        return sent >= 3 and (sent - answered) >= 3

    @staticmethod
    def _check_flag_anomalies(flags: str) -> Optional[Dict]:
        if not flags or len(flags) < 2:
            return None
        for invalid in _INVALID_FLAGS:
            if invalid in flags:
                return {
                    "attack_type": "invalid_tcp_flags",
                    "severity": "medium",
                    "source_ip": "",
                    "details": f"Invalid flag combo: {flags} (possible scan/spoof)",
                }
        return None

    def _check_ttl_jitter(self, ip: str, ttl: int) -> Optional[Dict]:
        if ttl == 0:
            return None
        self._source_ttls[ip].append(ttl)
        recent = self._source_ttls[ip][-10:]
        if len(recent) >= 3:
            unique = set(recent)
            if len(unique) > 1:
                expected = max(recent)
                anomalies = [t for t in recent if abs(t - expected) > 5]
                if len(anomalies) >= 2:
                    return {
                        "attack_type": "ttl_inconsistency",
                        "severity": "medium",
                        "source_ip": ip,
                        "details": f"TTL jitter: values {unique} (possible spoofing/covert)",
                    }
        return None

    def _check_isn_randomness(self, ip: str, tcp_seq: int, flags: str) -> Optional[Dict]:
        """Flag a genuinely predictable ISN sequence.

        Requires corroboration before it may claim "spoofed", because the raw
        pattern alone is satisfied by capture artifacts:

        * ``seq == 0`` on every SYN is how most **pcap writers** (and scapy's
          default) emit packets, and it is what a tap sees if it zeroes the
          field. `web_traffic.pcap`, `syn_flood.pcap` and `nmap_syn_scan.pcap`
          in this repo all carry zero ISNs, so "all ISNs identical" distinguishes
          nothing — see docs/PRODUCTION_READINESS.md §3.3.
        * A real spoofed-ISN attack also fails to complete handshakes, and shows
          RST storms or retransmissions. A host whose connections *complete*
          (SYN-ACK comes back and an ACK follows) is not being spoofed, whatever
          its ISN field looks like.

        So: fire only when the ISN pattern is suspicious **and** the evidence is
        a real signal rather than a zeroed capture — i.e. require a non-zero
        sample, and require the host to show failed-connection evidence. The
        caller feeds that evidence in via ``note_handshake``.
        """
        if "S" not in flags or "A" in flags:
            return None
        self._source_isns[ip].append(tcp_seq)
        recent = self._source_isns[ip][-5:]
        if len(recent) < 4:
            return None

        # A zero ISN is a capture/emitter artifact, not spoofing. It carries no
        # information about entropy, so it can never corroborate a verdict.
        if all(s == 0 for s in recent):
            return None

        gaps = [abs(recent[i + 1] - recent[i]) for i in range(len(recent) - 1)]
        reason = None
        if all(g == 0 for g in gaps):
            reason = f"Identical ISNs in {len(gaps)} samples (possible replay)"
        elif all(g < 100 for g in gaps):
            reason = f"ISN increments <100 in {len(gaps)} samples (likely spoofed counter)"
        elif len(set(gaps)) == 1 and gaps[0] < 10000:
            reason = f"Predictable ISN deltas (constant {gaps[0]}) in {len(gaps)} samples"
        if reason is None:
            return None

        # Corroboration: a host that completes handshakes is talking to a real
        # peer. Without this, synthetic captures and lazy emitters are reported
        # as "spoofed" at high severity.
        if not self._looks_spoofed(ip):
            return None

        return {
            "attack_type": "low_entropy_isn",
            "severity": "high",
            "source_ip": ip,
            "details": reason,
        }

    @staticmethod
    def _check_rare_port_pairing(src_port: int, dst_port: int) -> Optional[Dict]:
        if src_port < 1024 and dst_port < 1024 and src_port != dst_port:
            if src_port in (22, 80, 443) or dst_port in (22, 80, 443):
                return {
                    "attack_type": "rare_port_pairing",
                    "severity": "low",
                    "source_ip": "",
                    "details": f"Both ports privileged: {src_port}:{dst_port} (possible tunneling)",
                }
        return None

    def _cleanup_if_needed(self):
        if time.time() - self._last_cleanup > 60:
            self._source_ttls.clear()
            self._source_isns.clear()
            self._source_ips.clear()
            self._handshake_ok.clear()
            self._handshake_fail.clear()
            self._syn_sent.clear()
            self._synack_seen.clear()
            self._last_cleanup = time.time()
