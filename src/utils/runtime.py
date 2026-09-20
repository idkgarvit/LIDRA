"""Runtime-directory resolution for LIDRA's IPC socket.

Why this is not `/tmp` any more
-------------------------------
The agent creates a Unix socket that the TUI attaches to. It used to live at
`/tmp/lidra_tui_<pid>.sock`. Two problems, both verified on a live system:

1. **systemd `PrivateTmp=true` splits `/tmp`.** The service gets its own mount
   namespace, so a user-shell TUI cannot see the socket the service created.
   The README's own attach command (`ls /tmp/lidra_tui_*.sock`) therefore
   returned nothing on every systemd install — the install path the installer
   creates. Reproduced: 1 file visible inside the namespace, 0 from outside.

2. **`0666` in a shared, world-writable directory.** `/tmp` is sticky, but the
   socket itself was world-writable and accepts block/unblock commands, so any
   local user could drive the IDS.

`/run/<name>/` is the correct location for daemon runtime state: it is a tmpfs
(so it is empty after a reboot, with no stale sockets to clean), systemd can
create it with the right owner and mode via `RuntimeDirectory=`, and it is not
subject to `PrivateTmp` or `ProtectSystem` the way `/tmp` is.

Resolution order, so this works in every deployment shape:

1. `LIDRA_RUNTIME_DIR` — explicit override, used by tests and containers.
2. `$XDG_RUNTIME_DIR/lidra` — per-user session (running as a normal user).
3. `/run/lidra` — systemd-installed daemon (created via `RuntimeDirectory=`).
4. `<install root>/run` — no systemd, no `/run` write access (dev checkout).
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Socket file prefix, shared by the server and every client that looks for it.
SOCKET_PREFIX = "lidra_tui"

# Directory mode for the runtime dir. Group-writable so an operator in the
# `lidra` group can attach a TUI without being root; not world-accessible.
RUNTIME_DIR_MODE = 0o750

# Socket mode. Owner (the agent, root) and group (`lidra`) only.
SOCKET_MODE = 0o660

# Legacy location — still scanned as a fallback so an in-flight upgrade does not
# orphan a running agent's socket.
LEGACY_SOCKET_DIR = "/tmp"


def runtime_dir_candidates() -> list:
    """Return candidate runtime directories, most-preferred first."""
    candidates = []
    env = os.environ.get("LIDRA_RUNTIME_DIR")
    if env:
        candidates.append(Path(env))

    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        candidates.append(Path(xdg) / "lidra")

    candidates.append(Path("/run/lidra"))

    try:
        from utils.paths import get_lidra_root
        candidates.append(get_lidra_root() / "run")
    except Exception:
        pass

    return candidates


def get_runtime_dir(create: bool = True) -> Optional[Path]:
    """Best writable runtime directory, or None if none could be prepared.

    Never raises: a failure here must not stop the agent from starting. The
    caller falls back to monitoring without IPC, which is degraded but safe.
    """
    for cand in runtime_dir_candidates():
        try:
            if create:
                cand.mkdir(parents=True, exist_ok=True)
                # Only tighten what we are allowed to; /run/lidra may be
                # owned by root and already correct, and a chmod failure on a
                # systemd-managed path is not fatal.
                try:
                    current = stat.S_IMODE(cand.stat().st_mode)
                    if current & 0o007:
                        os.chmod(cand, RUNTIME_DIR_MODE)
                except OSError:
                    pass
            if cand.is_dir() and os.access(cand, os.W_OK | os.X_OK):
                return cand
        except (OSError, PermissionError) as e:
            logger.debug("[runtime] %s not usable: %s", cand, e)
            continue
    return None


def socket_path_for(pid: int, directory: Optional[Path] = None) -> Optional[Path]:
    """Path for the agent's IPC socket, creating the runtime dir if needed."""
    base = directory or get_runtime_dir()
    if base is None:
        return None
    return base / f"{SOCKET_PREFIX}_{pid}.sock"


def find_socket(pid_alive_check=None) -> Optional[str]:
    """Locate the most recent live agent socket.

    Scans the runtime dirs and then the legacy `/tmp` location, keeping only
    sockets whose owning pid is still alive. `pid_alive_check` is injectable so
    tests do not depend on real processes.
    """
    check = pid_alive_check or (lambda pid: os.path.exists(f"/proc/{pid}"))
    dirs = list(runtime_dir_candidates())
    dirs.append(Path(LEGACY_SOCKET_DIR))

    found = []
    for base in dirs:
        try:
            names = os.listdir(base)
        except (PermissionError, FileNotFoundError):
            continue
        for name in names:
            if not (name.startswith(SOCKET_PREFIX + "_") and name.endswith(".sock")):
                continue
            pid_part = name[len(SOCKET_PREFIX) + 1:-5]
            if not pid_part.isdigit():
                continue
            if not check(int(pid_part)):
                continue
            found.append((int(pid_part), str(base / name)))

    if not found:
        return None
    found.sort(reverse=True)
    return found[0][1]