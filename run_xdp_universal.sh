#!/bin/bash
# Universal LIDRA XDP runner - works across distros
set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err() { echo -e "${RED}[ERR]${NC} $*"; }

# Find command in common locations
find_cmd() {
    local cmd="$1"
    local paths=("/usr/sbin/$cmd" "/sbin/$cmd" "/usr/bin/$cmd" "/bin/$cmd")
    for p in "${paths[@]}"; do
        if [[ -x "$p" ]]; then
            echo "$p"
            return 0
        fi
    done
    command -v "$cmd" 2>/dev/null || return 1
}

# Detect distro
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    elif [[ -f /etc/fedora-release ]]; then
        echo "fedora"
    elif [[ -f /etc/arch-release ]]; then
        echo "arch"
    else
        echo "unknown"
    fi
}

DISTRO=$(detect_distro)
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XDP_OBJ="$SRC_DIR/src/ebpf/xdp_drop.o"
IFACE="${1:-eth0}"

# Find critical commands
IP_CMD=$(find_cmd ip) || { log_err "ip command not found"; exit 1; }
BPFTOOL_CMD=$(find_cmd bpftool) || { log_err "bpftool not found - install bpftool package"; exit 1; }
PYTHON_CMD=$(command -v python3) || { log_err "python3 not found"; exit 1; }

log_info "=============================================="
log_info "LIDRA XDP Runner"
log_info "=============================================="
log_info "Distro: $DISTRO"
log_info "Interface: $IFACE"
log_info "XDP Object: $XDP_OBJ"
log_info "ip: $IP_CMD"
log_info "bpftool: $BPFTOOL_CMD"
log_info "python3: $PYTHON_CMD"

# Check root
if [[ $EUID -ne 0 ]]; then
    log_err "Must run as root (use sudo)"
    exit 1
fi

# Check BPF filesystem
if ! mount | grep -q "bpffs on /sys/fs/bpf"; then
    log_info "Mounting bpffs..."
    mount -t bpf bpffs /sys/fs/bpf 2>/dev/null || log_warn "bpffs already mounted or failed"
fi

# Check XDP object exists
if [[ ! -f "$XDP_OBJ" ]]; then
    log_err "XDP object not found: $XDP_OBJ"
    log_info "Run ./build_xdp_universal.sh first"
    exit 1
fi

# Detect if interface exists
if ! $IP_CMD link show "$IFACE" &>/dev/null; then
    log_err "Interface $IFACE not found"
    $IP_CMD link show
    exit 1
fi

# Run the Python test
log_info "Running XDP drop test on $IFACE..."
cd "$SRC_DIR"
$PYTHON_CMD test_xdp_drop.py "$IFACE"

log_ok "Done"