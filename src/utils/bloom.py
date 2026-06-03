import hashlib
import math
from typing import Callable, Optional


class BloomFilter:
    def __init__(self, capacity: int = 100000, error_rate: float = 0.001):
        self._capacity = capacity
        self._error_rate = error_rate
        self._bit_count = self._optimal_bits(capacity, error_rate)
        self._hash_count = self._optimal_hashes(capacity, self._bit_count)
        self._bits = bytearray((self._bit_count + 7) // 8)
        self._inserted = 0

    @staticmethod
    def _optimal_bits(n: int, p: float) -> int:
        return int(-n * math.log(p) / (math.log(2) ** 2)) + 1

    @staticmethod
    def _optimal_hashes(n: int, m: int) -> int:
        return int(m / n * math.log(2)) + 1

    def _hashes(self, item: str):
        h = hashlib.sha256(item.encode()).digest()
        for i in range(self._hash_count):
            val = int.from_bytes(h[i * 4:(i + 1) * 4], "big") if (i + 1) * 4 <= len(h) else hash((item, i))
            yield val % self._bit_count

    def add(self, item: str):
        for bit in self._hashes(item):
            byte_idx = bit >> 3
            bit_idx = bit & 7
            self._bits[byte_idx] |= 1 << bit_idx
        self._inserted += 1

    def contains(self, item: str) -> bool:
        for bit in self._hashes(item):
            byte_idx = bit >> 3
            bit_idx = bit & 7
            if not (self._bits[byte_idx] & (1 << bit_idx)):
                return False
        return True

    def clear(self):
        self._bits = bytearray((self._bit_count + 7) // 8)
        self._inserted = 0

    @property
    def size(self) -> int:
        return self._inserted


class FlowCache:
    def __init__(self, capacity: int = 10000, clean_threshold: int = 10):
        self._capacity = capacity
        self._clean_threshold = clean_threshold
        self._cache: dict = {}
        self._counts: dict = {}

    def is_benign(self, flow_key: str) -> bool:
        return flow_key in self._cache and self._cache[flow_key]

    def track_packet(self, flow_key: str, has_payload: bool):
        if flow_key in self._cache:
            return
        if not has_payload:
            return
        self._counts[flow_key] = self._counts.get(flow_key, 0) + 1
        if self._counts[flow_key] >= self._clean_threshold:
            self._cache[flow_key] = True
            del self._counts[flow_key]
            if len(self._cache) > self._capacity:
                for k in list(self._cache.keys())[:self._capacity // 4]:
                    del self._cache[k]

    def mark_suspicious(self, flow_key: str):
        self._cache[flow_key] = False
        self._counts.pop(flow_key, None)

    def clear(self):
        self._cache.clear()
        self._counts.clear()
