"""Severity semantics shared by every path that can act on a detection.

A detection's severity decides two different things, and conflating them is a
bug: whether the *response* layer should act (alert/block/persist a row), and
whether an operator should *see* it. LIDRA's lowest band, ``info``, is the
observation band — a factual statement about traffic, not an accusation.

Today the only producer is the TLS JA4 passthrough
(``detection/dpi_engine.py``), which returns a ``tls_fingerprint`` detection at
``info`` for **any** parseable ClientHello. Before this module existed, ordinary
HTTPS created attacker/attacks rows: the row write sits above the
alert/block gate in ``core/agent_base.py``, so the ``severity in
("high", "critical")`` guard never saw it. That made the "attackers" figure in
``lidra status`` grow with normal browsing.

Rule: ``info`` is observed, never acted upon. It must not create
attacker/attacks rows, must not alert and must not block. The detection itself is
still returned by the detector and still counted in Prometheus — only the
response/persistence side is suppressed.
"""

from __future__ import annotations

# The response band: severities that may persist and act.
ACTIONABLE_SEVERITIES = frozenset({"low", "medium", "high", "critical"})

# The observation band: reported, never acted upon.
OBSERVATION_SEVERITIES = frozenset({"info"})


def normalize_severity(severity: object) -> str:
    """Lower-case/strip a severity, defaulting the way the agents do."""
    return str(severity or "medium").strip().lower()


def is_actionable_severity(severity: object) -> bool:
    """True when ``severity`` may persist a row, alert, or block.

    Unknown values are treated as actionable: an unrecognised severity is more
    likely a new detector with a typo than a deliberate observation, and
    silently dropping a real detection is worse than persisting a noisy one.
    """
    return normalize_severity(severity) not in OBSERVATION_SEVERITIES