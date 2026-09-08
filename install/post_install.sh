#!/usr/bin/env bash
# LIDRA post-install script — distro-agnostic, idempotent.
#
# Environment overrides:
#   LIDRA_PREFIX  — install root (default: /opt/lidra)
#   LIDRA_USER    — service user (default: root, required for AF_PACKET/NFQUEUE)
#   LIDRA_SRC     — source directory to copy (default: script/../)
#   LIDRA_NO_SERVICE — set non-empty to skip systemd unit install
#   LIDRA_NO_DEPS — set non-empty to skip apt/dnf/pacman package install

set -euo pipefail

PREFIX="${LIDRA_PREFIX:-/opt/lidra}"
LIDRA_USER="${LIDRA_USER:-root}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="${LIDRA_SRC:-$(cd "$SCRIPT_DIR/.." && pwd)}"
VENV_DIR="$PREFIX/venv"
LOG_DIR="/var/log/lidra"
SERVICE_FILE_SRC="$SCRIPT_DIR/systemd/lidra.service"
SERVICE_FILE_DST="/etc/systemd/system/lidra.service"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { printf "${BLUE}[lidra-install]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[  ok  ]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[ warn ]${NC} %s\n" "$*" >&2; }
err()  { printf "${RED}[ fail ]${NC} %s\n" "$*" >&2; }

[ "$(id -u)" -eq 0 ] || { err "Must be run as root (need to write to $PREFIX and /etc/systemd)."; exit 1; }

# ----- distro detection -----
detect_pkg_manager() {
    if   command -v apt    >/dev/null 2>&1; then echo "apt"
    elif command -v dnf    >/dev/null 2>&1; then echo "dnf"
    elif command -v yum    >/dev/null 2>&1; then echo "yum"
    elif command -v pacman >/dev/null 2>&1; then echo "pacman"
    elif command -v zypper >/dev/null 2>&1; then echo "zypper"
    elif command -v apk    >/dev/null 2>&1; then echo "apk"
    else echo "unknown"
    fi
}

detect_distro_family() {
    if [ -r /etc/os-release ]; then
        . /etc/os-release
        local id_lc="${ID:-}"
        local like_lc="${ID_LIKE:-}"
        case " $id_lc $like_lc " in
            *" debian "*|*" ubuntu "*|*" kali "*|*" mint "*|*" raspbian "*) echo "debian" ;;
            *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" alma "*)      echo "rhel" ;;
            *" arch "*|*" manjaro "*)                                         echo "arch" ;;
            *" suse "*|*" opensuse "*)                                        echo "suse" ;;
            *" alpine "*)                                                     echo "alpine" ;;
            *)                                                                echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

PKG_MGR="$(detect_pkg_manager)"
DISTRO_FAMILY="$(detect_distro_family)"
log "Detected: family=${DISTRO_FAMILY} pkg=${PKG_MGR} prefix=${PREFIX}"

# ----- package install -----
PKG_LIST_NEEDED=()
has_pkg() { command -v "$1" >/dev/null 2>&1; }

case "$DISTRO_FAMILY" in
    debian)
        PKG_LIST_NEEDED+=(python3 python3-venv python3-pip libpcap-dev ethtool iptables)
        has_pkg nft  || PKG_LIST_NEEDED+=(nftables)
        ;;
    rhel)
        PKG_LIST_NEEDED+=(python3 python3-pip libpcap-devel ethtool iptables)
        has_pkg nft  || PKG_LIST_NEEDED+=(nftables)
        ;;
    arch)
        PKG_LIST_NEEDED+=(python python-pip libpcap ethtool iptables nftables)
        ;;
    suse)
        PKG_LIST_NEEDED+=(python3 python3-pip libpcap-devel ethtool iptables nftables)
        ;;
    alpine)
        PKG_LIST_NEEDED+=(python3 py3-pip libpcap-dev ethtool iptables nftables)
        ;;
    *)
        warn "Unknown distro family — skipping system package install."
        warn "Make sure these are present: python3, pip, libpcap-dev, ethtool, iptables or nftables"
        ;;
esac

if [ "${LIDRA_NO_DEPS:-}" = "" ] && [ "${#PKG_LIST_NEEDED[@]}" -gt 0 ]; then
    log "Installing system packages: ${PKG_LIST_NEEDED[*]}"
    case "$PKG_MGR" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y --no-install-recommends "${PKG_LIST_NEEDED[@]}"
            ;;
        dnf|yum)
            "$PKG_MGR" install -y "${PKG_LIST_NEEDED[@]}"
            ;;
        pacman)
            pacman -Sy --noconfirm "${PKG_LIST_NEEDED[@]}"
            ;;
        zypper)
            zypper --non-interactive install -y "${PKG_LIST_NEEDED[@]}"
            ;;
        apk)
            apk add --no-cache "${PKG_LIST_NEEDED[@]}"
            ;;
        *)
            warn "No supported package manager found; please install: ${PKG_LIST_NEEDED[*]}"
            ;;
    esac
    ok "System packages installed."
else
    log "Skipping system package install (LIDRA_NO_DEPS or list empty)."
fi

# ----- directories -----
log "Creating install directories under $PREFIX"
mkdir -p "$PREFIX" "$PREFIX/data" "$PREFIX/logs" "$PREFIX/state" "$LOG_DIR"
ok "Directories ready."

# ----- copy source (idempotent rsync if available, else cp) -----
log "Copying source from $SRC_DIR -> $PREFIX"
if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
        --exclude='venv/' --exclude='__pycache__/' --exclude='*.pyc' \
        --exclude='data/lidra.db' --exclude='logs/' --exclude='state/' \
        "$SRC_DIR/" "$PREFIX/"
else
    find "$PREFIX" -maxdepth 6 -type d \( -name venv -o -name __pycache__ \) -prune -o \
        -type f -name '*.pyc' -print -delete 2>/dev/null || true
    cp -r "$SRC_DIR"/. "$PREFIX"/
    rm -rf "$PREFIX/venv" 2>/dev/null || true
fi
ok "Source copied to $PREFIX"

# ----- venv + python deps -----
if [ ! -x "$VENV_DIR/bin/python3" ]; then
    log "Creating Python venv at $VENV_DIR"
    python3 -m venv "$VENV_DIR"
fi
log "Installing Python dependencies from $PREFIX/requirements.txt"
"$VENV_DIR/bin/pip" install --upgrade pip --quiet
"$VENV_DIR/bin/pip" install -r "$PREFIX/requirements.txt"
ok "Python dependencies installed."

# ----- optional XDP build (fast-path bonus; core works without it) -----
# The agent detects + blocks via iptables/nftables with zero extra toolchain.
# XDP only needs clang + kernel headers + make; skip quietly if absent.
if [ "${LIDRA_NO_XDP:-}" != "" ]; then
    log "Skipping XDP build (LIDRA_NO_XDP set)."
elif ! has_pkg clang || ! has_pkg make; then
    warn "clang/make not found — skipping XDP build (optional)."
    warn "Core detection + firewall blocking work without it."
    warn "To enable XDP later: install clang + kernel headers, then run:  make -C $PREFIX build"
elif ! make -C "$PREFIX" build >/tmp/lidra-xdp-build.log 2>&1; then
    warn "XDP build failed — continuing without it (core protection unaffected)."
    warn "See /tmp/lidra-xdp-build.log for details."
else
    ok "XDP program built."
fi

# ----- systemd unit -----
if [ "${LIDRA_NO_SERVICE:-}" = "" ] && [ -f "$SERVICE_FILE_SRC" ] && [ -d /etc/systemd/system ]; then
    log "Installing systemd unit to $SERVICE_FILE_DST"
    install -m 0644 "$SERVICE_FILE_SRC" "$SERVICE_FILE_DST"
    # Resume hook: restart agent after suspend (lid close) — capture sockets go stale.
    if [ -f "$SCRIPT_DIR/systemd/lidra-sleep" ] && [ -d /usr/lib/systemd/system-sleep ]; then
        install -m 0755 "$SCRIPT_DIR/systemd/lidra-sleep" /usr/lib/systemd/system-sleep/lidra
        ok "Suspend/resume hook installed."
    fi
    systemctl daemon-reload
    if [ "${LIDRA_NO_ENABLE:-}" = "" ]; then
        systemctl enable --now lidra
        ok "Service enabled and started (auto-boots from now on)."
    else
        ok "systemd unit installed. Enable with:  systemctl enable --now lidra"
    fi
elif [ "${LIDRA_NO_SERVICE:-}" = "" ]; then
    warn "systemd not detected or service file missing — skipping unit install."
    if [ ! -f "$SERVICE_FILE_SRC" ]; then
        warn "Service template not found at $SERVICE_FILE_SRC"
    fi
else
    log "Skipping systemd unit install (LIDRA_NO_SERVICE set)."
fi

# ----- final doctor check -----
log "Running lidra doctor for sanity check..."
if [ -x "$VENV_DIR/bin/python3" ]; then
    if LIDRA_ROOT="$PREFIX" PYTHONPATH="$PREFIX/src" "$VENV_DIR/bin/python3" \
            -c "from utils.distro_detect import detect_all; import json; print(json.dumps(detect_all(), indent=2, default=str))" \
            >/tmp/lidra-doctor.json 2>/tmp/lidra-doctor.err; then
        ok "Doctor check passed. Summary:"
        python3 - <<'PY' 2>/dev/null || true
import json
try:
    with open('/tmp/lidra-doctor.json') as f:
        r = json.load(f)
    d = r.get('distro', {})
    n = r.get('network', {})
    c = r.get('capabilities', {})
    print(f"  distro      : {d.get('pretty_name') or d.get('name')}")
    print(f"  interface   : {n.get('interface') or 'NONE'}")
    print(f"  iptables    : {c.get('iptables')}   nftables: {c.get('nftables')}   bcc: {c.get('bcc')}")
    issues = r.get('issues', [])
    if issues:
        for i in issues:
            print(f"  [{i['level']}] {i['code']}: {i['message']}")
except Exception as e:
    print(f"  (could not summarize: {e})")
PY
    else
        warn "Doctor check reported issues — see /tmp/lidra-doctor.err"
        sed 's/^/  /' /tmp/lidra-doctor.err || true
    fi
else
    warn "Could not run doctor — venv missing or import failed."
fi

cat <<EOF

${GREEN}LIDRA install complete.${NC}

  Install root : ${PREFIX}
  Venv         : ${VENV_DIR}
  Service unit : ${SERVICE_FILE_DST}

Next steps:
  sudo systemctl enable --now lidra
  sudo -E PYTHONPATH=${PREFIX}/src ${VENV_DIR}/bin/python3 -m cli.doctor_cmd

EOF
