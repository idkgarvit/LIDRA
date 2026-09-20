"""Who is acting — the name that ends up in the operator audit trail.

The audit log answers "who blocked that", and the useful answer is the human's
account, not ``root``. ``SUDO_USER`` is what sudo sets to the invoking account,
so it is the first choice; the effective user is the fallback for a real root
shell or an unsudoed run. For the IPC socket the name comes from the kernel's
peer credentials instead (see ``tui/ipc_server.py``) because that path must not
trust what the client claims.
"""

from __future__ import annotations

import getpass
import logging
import os

logger = logging.getLogger(__name__)


def current_actor() -> str:
    """Best-effort name of the human behind this process."""
    try:
        return os.environ.get("SUDO_USER") or getpass.getuser() or "unknown"
    except Exception:  # pragma: no cover - getpass can fail without a passwd entry
        logger.debug("[actor] could not determine the current user")
        return "unknown"
