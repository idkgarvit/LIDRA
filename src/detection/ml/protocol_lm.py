import logging
import math
from collections import defaultdict, deque
from threading import Lock
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def _bin_value(v: float, bins: List[float]) -> int:
    for i, b in enumerate(bins):
        if v <= b:
            return i
    return len(bins)


_LEN_BINS = [64, 128, 256, 512, 1024, 1500]
_IAT_BINS = [0.001, 0.01, 0.1, 1.0, 10.0]
_PORT_BINS = [1024, 5000, 10000, 30000, 50000]


def _tokenize_packet(packet: Dict) -> Tuple:
    direction = 0 if packet.get("src_port", 0) > 1024 else 1
    pkt_len = len(packet.get("payload", b""))
    iat = packet.get("_iat", 0.0)
    ttl = packet.get("ttl", 64)
    proto = packet.get("protocol", "tcp")
    flags = packet.get("flags", "")
    src_port = packet.get("src_port", 0)
    dst_port = packet.get("dst_port", 0)
    win = packet.get("window", 0)

    toks = (
        direction,
        _bin_value(pkt_len, _LEN_BINS),
        _bin_value(iat, _IAT_BINS),
        _bin_value(ttl, [32, 64, 128, 255]),
        0 if proto == "tcp" else 1,
        1 if "S" in flags else 0,
        1 if "A" in flags else 0,
        1 if "F" in flags else 0,
        _bin_value(src_port, _PORT_BINS),
        _bin_value(dst_port, _PORT_BINS),
        min(win // 4096, 15),
    )
    return toks


class ProtocolLM:
    _N_GRAMS = 3
    _PERPLEXITY_THRESHOLD = 100.0

    def __init__(self, lr: float = 0.01, decay: float = 0.999):
        self._lr = lr
        self._decay = decay
        self._ngram_counts: Dict[Tuple, float] = defaultdict(float)
        self._context_counts: Dict[Tuple, float] = defaultdict(float)
        self._total_ngrams = 0
        self._total_contexts = 0
        self._lock = Lock()
        self._stream_cache: Dict[str, deque] = defaultdict(lambda: deque(maxlen=16))
        self._perplexities: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

    def observe(self, packet: Dict):
        key = (packet.get("src_ip", ""), packet.get("dst_ip", ""),
               packet.get("src_port", 0), packet.get("dst_port", 0))
        tokens = _tokenize_packet(packet)
        self._stream_cache[key].append(tokens)

        stream = list(self._stream_cache[key])
        if len(stream) < self._N_GRAMS:
            return None

        with self._lock:
            for i in range(len(stream) - self._N_GRAMS + 1):
                context = tuple(stream[i:i + self._N_GRAMS - 1][j] for j in range(self._N_GRAMS - 1))
                ngram = tuple(stream[i + j] for j in range(self._N_GRAMS))
                self._ngram_counts[ngram] += 1.0
                self._context_counts[context] += 1.0
                self._total_ngrams += 1
                self._total_contexts += 1

            self._apply_decay()
        return None

    def _apply_decay(self):
        if self._total_ngrams > 10000:
            decay = self._decay
            for k in list(self._ngram_counts.keys()):
                self._ngram_counts[k] *= decay
                if self._ngram_counts[k] < 0.01:
                    del self._ngram_counts[k]
            for k in list(self._context_counts.keys()):
                self._context_counts[k] *= decay
                if self._context_counts[k] < 0.01:
                    del self._context_counts[k]
            self._total_ngrams = int(self._total_ngrams * decay)
            self._total_contexts = int(self._total_contexts * decay)

    def perplexity(self, packet: Dict) -> Optional[float]:
        key = (packet.get("src_ip", ""), packet.get("dst_ip", ""),
               packet.get("src_port", 0), packet.get("dst_port", 0))
        tokens = _tokenize_packet(packet)
        self._stream_cache[key].append(tokens)
        stream = list(self._stream_cache[key])

        if len(stream) < self._N_GRAMS:
            return None

        log_prob = 0.0
        n = 0
        smoothing = 0.01

        with self._lock:
            for i in range(len(stream) - self._N_GRAMS + 1):
                context = tuple(stream[i:i + self._N_GRAMS - 1][j] for j in range(self._N_GRAMS - 1))
                ngram = tuple(stream[i + j] for j in range(self._N_GRAMS))

                ngram_count = self._ngram_counts.get(ngram, 0.0)
                context_count = self._context_counts.get(context, 0.0)

                prob = (ngram_count + smoothing) / (context_count + smoothing * self._total_contexts + 1)
                log_prob += math.log(max(prob, 1e-10))
                n += 1

        if n == 0:
            return None

        pp = math.exp(-log_prob / n)
        self._perplexities[f"{key[0]}:{key[1]}"].append(pp)
        return pp

    def is_anomalous(self, packet: Dict) -> Tuple[bool, Optional[float]]:
        pp = self.perplexity(packet)
        if pp is None:
            return False, None
        return pp > self._PERPLEXITY_THRESHOLD, pp

    def get_flow_perplexity(self, src_ip: str, dst_ip: str) -> Optional[float]:
        key = f"{src_ip}:{dst_ip}"
        vals = list(self._stream_cache.get(key, []))
        if not vals:
            return None
        return sum(vals) / len(vals)

    def get_metrics(self) -> Dict:
        with self._lock:
            return {
                "ngrams": len(self._ngram_counts),
                "contexts": len(self._context_counts),
                "total_ngrams": self._total_ngrams,
                "active_flows": len(self._stream_cache),
            }
