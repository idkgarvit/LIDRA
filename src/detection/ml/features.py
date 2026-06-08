import logging
import math
import struct
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class FlowFeatures:
    __slots__ = (
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "flow_duration", "fwd_pkts", "bwd_pkts",
        "fwd_pkt_lens", "bwd_pkt_lens",
        "fwd_iats", "bwd_iats",
        "fwd_ttls", "bwd_ttls",
        "tcp_flags", "tls_version", "tls_cipher_count",
        "tls_ext_count", "payload_bytes",
        "flow_start", "flow_end",
    )

    def __init__(self):
        self.src_ip = ""
        self.dst_ip = ""
        self.src_port = 0
        self.dst_port = 0
        self.protocol = ""
        self.flow_duration = 0.0
        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.fwd_pkt_lens: List[int] = []
        self.bwd_pkt_lens: List[int] = []
        self.fwd_iats: List[float] = []
        self.bwd_iats: List[float] = []
        self.fwd_ttls: List[int] = []
        self.bwd_ttls: List[int] = []
        self.tcp_flags: List[str] = []
        self.tls_version = 0
        self.tls_cipher_count = 0
        self.tls_ext_count = 0
        self.payload_bytes = 0
        self.flow_start = 0.0
        self.flow_end = 0.0

    def to_vector(self) -> List[float]:
        def _stats(vals):
            if not vals:
                return [0.0] * 6
            n = len(vals)
            mean = sum(vals) / n
            variance = sum((x - mean) ** 2 for x in vals) / n
            std = math.sqrt(variance)
            mn = min(vals)
            mx = max(vals)
            p25 = _percentile(vals, 25)
            p75 = _percentile(vals, 75)
            return [mean, std, mn, mx, p25, p75]

        def _percentile(data, p):
            s = sorted(data)
            idx = int(len(s) * p / 100)
            return s[min(idx, len(s) - 1)]

        total_pkts = self.fwd_pkts + self.bwd_pkts
        all_lens = self.fwd_pkt_lens + self.bwd_pkt_lens
        all_iats = self.fwd_iats + self.bwd_iats

        syn = self.tcp_flags.count("S")
        ack = self.tcp_flags.count("A")
        fin = self.tcp_flags.count("F")
        rst = self.tcp_flags.count("R")

        vec = [
            float(self.fwd_pkts),
            float(self.bwd_pkts),
            float(total_pkts),
            self.flow_duration,
            self.payload_bytes / max(total_pkts, 1),
        ]

        vec.extend(_stats(all_lens))
        vec.extend(_stats(all_iats))

        vec.extend(_stats(self.fwd_pkt_lens))
        vec.extend(_stats(self.fwd_iats))
        vec.extend(_stats(self.bwd_pkt_lens))
        vec.extend(_stats(self.bwd_iats))

        vec.extend([
            float(syn),
            float(ack),
            float(fin),
            float(rst),
            syn / max(total_pkts, 1),
            ack / max(total_pkts, 1),
            fin / max(total_pkts, 1),
            rst / max(total_pkts, 1),
        ])

        vec.extend([
            float(self.tls_version),
            float(self.tls_cipher_count),
            float(self.tls_ext_count),
            _stats(self.fwd_ttls)[0],
            _stats(self.bwd_ttls)[0],
        ])

        return vec

    @property
    def feature_names(self) -> List[str]:
        return [
            "fwd_pkts", "bwd_pkts", "total_pkts", "flow_duration", "bytes_per_pkt",
            "pkt_len_mean", "pkt_len_std", "pkt_len_min", "pkt_len_max", "pkt_len_p25", "pkt_len_p75",
            "iat_mean", "iat_std", "iat_min", "iat_max", "iat_p25", "iat_p75",
            "fwd_pkt_len_mean", "fwd_pkt_len_std", "fwd_pkt_len_min", "fwd_pkt_len_max",
            "fwd_pkt_len_p25", "fwd_pkt_len_p75",
            "fwd_iat_mean", "fwd_iat_std", "fwd_iat_min", "fwd_iat_max", "fwd_iat_p25", "fwd_iat_p75",
            "bwd_pkt_len_mean", "bwd_pkt_len_std", "bwd_pkt_len_min", "bwd_pkt_len_max",
            "bwd_pkt_len_p25", "bwd_pkt_len_p75",
            "bwd_iat_mean", "bwd_iat_std", "bwd_iat_min", "bwd_iat_max", "bwd_iat_p25", "bwd_iat_p75",
            "syn_count", "ack_count", "fin_count", "rst_count",
            "syn_ratio", "ack_ratio", "fin_ratio", "rst_ratio",
            "tls_version", "tls_ciphers", "tls_exts",
            "fwd_ttl_mean", "bwd_ttl_mean",
        ]

    @staticmethod
    def n_features() -> int:
        return 54


class FlowExtractor:
    def __init__(self, idle_timeout: float = 120.0, max_flows: int = 10000):
        self._idle_timeout = idle_timeout
        self._max_flows = max_flows
        self._flows: Dict[Tuple, FlowFeatures] = {}
        self._last_seen: Dict[Tuple, float] = {}

    def _flow_key(self, packet: Dict) -> Tuple:
        return (
            packet.get("src_ip", ""),
            packet.get("dst_ip", ""),
            packet.get("src_port", 0),
            packet.get("dst_port", 0),
            packet.get("protocol", ""),
        )

    def add_packet(self, packet: Dict) -> Optional[FlowFeatures]:
        key_fwd = self._flow_key(packet)
        key_rev = (
            packet.get("dst_ip", ""),
            packet.get("src_ip", ""),
            packet.get("dst_port", 0),
            packet.get("src_port", 0),
            packet.get("protocol", ""),
        )
        key = key_fwd if key_fwd in self._flows else key_rev
        now = time.time()

        self._evict_idle(now)

        if key not in self._flows:
            if len(self._flows) >= self._max_flows:
                return None
            fwd = key == key_fwd
            flow = FlowFeatures()
            flow.src_ip = key[0]
            flow.dst_ip = key[1]
            flow.src_port = key[2]
            flow.dst_port = key[3]
            flow.protocol = key[4]
            flow.flow_start = now
            self._flows[key] = flow

        flow = self._flows[key]
        fwd = key == key_fwd
        pkt_len = len(packet.get("payload", b""))
        flags = packet.get("flags", "")
        ttl = packet.get("ttl", 0)
        last = self._last_seen.get(key, now)
        iat = now - last if last != now else 0.0

        flow.flow_end = now
        flow.payload_bytes += pkt_len

        if fwd:
            flow.fwd_pkts += 1
            flow.fwd_pkt_lens.append(pkt_len)
            flow.fwd_iats.append(iat)
            flow.fwd_ttls.append(ttl)
        else:
            flow.bwd_pkts += 1
            flow.bwd_pkt_lens.append(pkt_len)
            flow.bwd_iats.append(iat)
            flow.bwd_ttls.append(ttl)

        if flags:
            for f in flags.upper():
                if f in ("S", "A", "F", "R"):
                    flow.tcp_flags.append(f)

        self._last_seen[key] = now
        return flow

    def get_completed_flow(self, key: Tuple) -> Optional[FlowFeatures]:
        flow = self._flows.pop(key, None)
        if flow:
            flow.flow_duration = flow.flow_end - flow.flow_start
        return flow

    def get_flow(self, key: Tuple) -> Optional[FlowFeatures]:
        return self._flows.get(key)

    def _evict_idle(self, now: float):
        stale = [
            k for k, t in self._last_seen.items()
            if now - t > self._idle_timeout
        ]
        for k in stale:
            flow = self._flows.pop(k, None)
            if flow:
                flow.flow_duration = flow.flow_end - flow.flow_start
            self._last_seen.pop(k, None)

    def clear(self):
        self._flows.clear()
        self._last_seen.clear()


def extract_flow_features(packet: Dict) -> Dict:
    return {
        "src_ip": packet.get("src_ip", ""),
        "dst_ip": packet.get("dst_ip", ""),
        "src_port": packet.get("src_port", 0),
        "dst_port": packet.get("dst_port", 0),
        "protocol": packet.get("protocol", ""),
        "payload_len": len(packet.get("payload", b"")),
        "ttl": packet.get("ttl", 0),
        "flags": packet.get("flags", ""),
        "timestamp": time.time(),
    }
