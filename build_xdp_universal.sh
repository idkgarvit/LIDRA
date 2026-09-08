#!/bin/bash
# Universal XDP build script - works on Debian, Ubuntu, Fedora, Arch, Kali, etc.
set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*" >&2; }
log_ok() { echo -e "${GREEN}[OK]${NC} $*" >&2; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
log_err() { echo -e "${RED}[ERR]${NC} $*" >&2; }

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
log_info "Detected distro: $DISTRO"

# Find kernel headers - match running kernel version
find_kernel_headers() {
    local kernel_ver=$(uname -r)
    log_info "Kernel: $kernel_ver"

    # First try: exact match for running kernel
    local exact="/usr/src/linux-headers-${kernel_ver}"
    if [[ -d "$exact" && -f "$exact/Makefile" ]]; then
        echo "$exact"
        return 0
    fi

    # Second try: /lib/modules/<kernel>/build
    local mod_build="/lib/modules/${kernel_ver}/build"
    if [[ -d "$mod_build" && -f "$mod_build/Makefile" ]]; then
        echo "$mod_build"
        return 0
    fi

    # Third try: any headers directory with matching kernel version in name
    for dir in /usr/src/linux-headers-*; do
        if [[ -d "$dir" && -f "$dir/Makefile" ]]; then
            # Check if this dir corresponds to the running kernel
            local dir_kernel=$(basename "$dir" | sed 's/^linux-headers-//')
            if [[ "$dir_kernel" == "$kernel_ver"* ]]; then
                echo "$dir"
                return 0
            fi
        fi
    done

    # Last resort: any kernel headers (may work for BPF compilation)
    for dir in /usr/src/linux-headers-*; do
        if [[ -d "$dir" && -f "$dir/Makefile" ]]; then
            log_warn "Using non-matching kernel headers: $dir"
            echo "$dir"
            return 0
        fi
    done

    echo ""
}

KERNEL_HEADERS=$(find_kernel_headers)
if [[ -z "$KERNEL_HEADERS" || ! -d "$KERNEL_HEADERS" ]]; then
    log_err "Kernel headers not found. Install them:"
    case "$DISTRO" in
        debian|ubuntu|kali) log_err "  sudo apt install linux-headers-$(uname -r)";;
        fedora|rhel|centos) log_err "  sudo dnf install kernel-headers-$(uname -r) kernel-devel-$(uname -r)";;
        arch|manjaro) log_err "  sudo pacman -S linux-headers";;
    esac
    exit 1
fi
log_ok "Kernel headers: $KERNEL_HEADERS"

# Find BPF helpers (libbpf)
find_bpf_helpers() {
    local candidates=(
        "/usr/include/bpf"
        "/usr/include/linux/bpf.h"
        "$KERNEL_HEADERS/include/uapi/linux/bpf.h"
        "$KERNEL_HEADERS/tools/lib/bpf"
    )

    for path in "${candidates[@]}"; do
        if [[ -d "$path" ]] || [[ -f "$path" ]]; then
            echo "$path"
            return 0
        fi
    done
    echo ""
}

BPF_HELPERS=$(find_bpf_helpers)
if [[ -n "$BPF_HELPERS" ]]; then
    log_ok "BPF helpers: $BPF_HELPERS"
else
    log_warn "BPF helpers not found in standard locations"
fi

# Source and output
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XDP_SRC="$SRC_DIR/src/ebpf/xdp_drop.c"
XDP_OBJ="$SRC_DIR/src/ebpf/xdp_drop.o"

# Detect multiarch for asm headers
MULTIARCH=$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo "x86_64-linux-gnu")

# Build include path
# System includes first (have bpf.h and asm/types.h)
# Then kernel headers for version-specific definitions
INCLUDES="-I/usr/include"
if [[ -d "/usr/include/bpf" ]]; then
    INCLUDES="$INCLUDES -I/usr/include/bpf"
fi
if [[ -d "/usr/include/$MULTIARCH" ]]; then
    INCLUDES="$INCLUDES -I/usr/include/$MULTIARCH"
fi
if [[ -d "$KERNEL_HEADERS/include" ]]; then
    INCLUDES="$INCLUDES -I$KERNEL_HEADERS/include"
fi
if [[ -d "$KERNEL_HEADERS/arch/x86/include" ]]; then
    INCLUDES="$INCLUDES -I$KERNEL_HEADERS/arch/x86/include"
fi
if [[ -d "$KERNEL_HEADERS/arch/x86/include/generated" ]]; then
    INCLUDES="$INCLUDES -I$KERNEL_HEADERS/arch/x86/include/generated"
fi

# Detect architecture for target
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) BPF_TARGET="bpf" ; CLANG_ARCH="x86" ;;
    aarch64) BPF_TARGET="bpf" ; CLANG_ARCH="arm64" ;;
    *) log_err "Unsupported arch: $ARCH"; exit 1 ;;
esac

# Compile
log_info "Compiling with clang..."
clang \
    -O2 \
    -target "$BPF_TARGET" \
    -D__TARGET_ARCH_${CLANG_ARCH} \
    $INCLUDES \
    -c "$XDP_SRC" \
    -o "$XDP_OBJ" \
    -Wno-compare-distinct-pointer-types \
    -Wno-address-of-packed-member \
    -Wno-unknown-warning-option \
    || { log_err "Compilation failed"; exit 1; }

# Verify
log_info "Verifying output..."
file "$XDP_OBJ"
ls -lh "$XDP_OBJ"

# Check sections
readelf -S "$XDP_OBJ" | grep -E '\.maps|\.text|xdp|license' | while read line; do
    log_info "  ELF: $line"
done

# Check relocations
log_info "Relocations:"
readelf -r "$XDP_OBJ" 2>/dev/null || llvm-objdump -r "$XDP_OBJ" 2>/dev/null || true

log_ok "XDP object built: $XDP_OBJ"
exit 0