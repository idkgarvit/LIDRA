"""Metrics collection API — the piece that was missing.

`metrics/server.py` defines the Prometheus series and serves them, but nothing
in the codebase ever incremented them: a scrape returned only `python_*` and
`process_*` families, so every dashboard built on this endpoint was empty. This
module is the write side.

Design rules:

* **Never raise into the caller.** These calls sit on the verdict path in some
  cases; a metrics bug must not cost a packet its verdict. Every function is
  wrapped and degrades to a no-op.
* **Never require prometheus_client.** Everything is guarded by the same
  HAS_PROMETHEUS flag the server uses, so a bare install still runs.
* **No per-packet work beyond a counter increment.** Label values are the
  attack type and severity, which are already strings on the detection dict —
  no formatting, no dictionaries built per packet.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

try:  # reuse the objects the server already registered
    from metrics import server as _server
    _HAS = bool(getattr(_server, "HAS_PROMETHEUS", False))
except Exception:  # pragma: no cover - import path issues
    _server = None  # type: Any
    _HAS = False

logger = logging.getLogger("LIDRA-metrics")

# Static-typing note: `_server` is Any on purpose. The Prometheus objects are
# None at import time when prometheus_client is absent, and every use here is
# already gated on _HAS; annotating them as Optional forces a pile of idiotic
# None-checks that the flag already covers.
_server: Any

# Cache the last observed values so the pull-style gauges can be set without
# every caller needing to know the full stats dict.
_last: dict = {}

# Attack types are a bounded set, but a malformed payload could produce a
# surprising label and Prometheus cardinality is per unique label set. Cap the
# label length defensively.
_MAX_LABEL = 64


def _clip(value) -> str:
    text = str(value or "unknown")
    return text[:_MAX_LABEL]


def record_verdict(verdict) -> None:
    """Count one packet by its verdict (pass/drop/rate_limit/log_only)."""
    if not _HAS:
        return
    try:
        name = getattr(verdict, "value", verdict)
        _server.packets_total.labels(verdict=_clip(name)).inc()
    except Exception as e:
        logger.debug(f"[Metrics] verdict record skipped: {e}")


def record_detection(attack_type: str, severity: str) -> None:
    """Count one detection."""
    if not _HAS:
        return
    try:
        _server.attacks_total.labels(
            type=_clip(attack_type), severity=_clip(severity)
        ).inc()
    except Exception as e:
        logger.debug(f"[Metrics] detection record skipped: {e}")


def record_block(method: str = "firewall") -> None:
    """Count one IP block applied."""
    if not _HAS:
        return
    try:
        _server.blocks_total.labels(method=_clip(method)).inc()
    except Exception as e:
        logger.debug(f"[Metrics] block record skipped: {e}")


def record_latency(seconds: float) -> None:
    """Observe detection processing latency in seconds."""
    if not _HAS:
        return
    try:
        _server.detection_latency.observe(float(seconds))
    except Exception as e:
        logger.debug(f"[Metrics] latency record skipped: {e}")


def set_gauges(active_connections: Optional[int] = None,
               cpu_percent: Optional[float] = None,
               memory_percent: Optional[float] = None,
               rate_pps: Optional[float] = None,
               throughput_mbps: Optional[float] = None) -> None:
    """Update the pull-style gauges. Only the values passed are touched."""
    if not _HAS:
        return
    try:
        if active_connections is not None:
            _server.active_connections.set(active_connections)
        if cpu_percent is not None:
            _server.cpu_usage.set(cpu_percent)
        if memory_percent is not None:
            _server.memory_usage.set(memory_percent)
        if rate_pps is not None:
            _server.packet_rate.set(rate_pps)
        if throughput_mbps is not None:
            _server.throughput_mbps.set(throughput_mbps)
    except Exception as e:
        logger.debug(f"[Metrics] gauge update skipped: {e}")


def set_gauges_from_stats(stats: dict,
                          cpu_percent: Optional[float] = None,
                          memory_percent: Optional[float] = None) -> None:
    """Convenience: push an InlineEngine.get_stats() dict into the gauges."""
    if not _HAS or not isinstance(stats, dict):
        return
    packets = stats.get("packets_in", 0) or 0
    set_gauges(
        active_connections=stats.get("active_connections"),
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        rate_pps=stats.get("packet_rate"),
        # 1500 B is the assumed mean frame size used elsewhere in the agent.
        throughput_mbps=round(packets * 1500 * 8 / 1_000_000, 3) if packets else 0.0,
    )
