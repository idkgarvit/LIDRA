# LIDRA XDP - Cross-Distribution BPF/eBPF Packet Filtering

LIDRA's eXpress Data Path (XDP) component provides kernel-level packet filtering for IDS/IPS functionality. It uses raw `bpf()` syscalls (no libbpf dependency) to load BPF programs and manages blocklists via BPF maps with Unix socket IPC.

## Quick Start

```bash
# 1. Build (auto-detects distro and kernel)
make build

# 2. Test packet dropping
sudo make test IFACE=eth0

# 3. Run as daemon (blocks until Ctrl+C)
sudo make run IFACE=eth0
# In another terminal:
sudo make block IP=192.168.1.100
sudo make status
sudo make unblock IP=192.168.1.100
sudo make stop
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Userspace                                │
├─────────────────────────────────────────────────────────────────┤
│  xdp_loader.py (daemon)          CLI Commands                   │
│  ┌──────────────────┐             ┌──────────────────┐          │
│  │ ELF Parser       │  Unix       │ block IP         │          │
│  │ BPF Syscalls     │◄──Socket───►│ unblock IP       │          │
│  │ Map Management   │             │ status           │          │
│  └──────────────────┘             └──────────────────┘          │
└──────────────────────────┬──────────────────────────────────────┘
                           │ bpf() syscall
           ┌───────────────┼───────────────────────┐
           ▼               ▼                       ▼
      ┌──────────┐   ┌──────────┐            ┌──────────┐
      │ blocklist│   │rate_limit│            │  stats   │
      │ BPF_MAP  │   │ BPF_MAP  │            │ BPF_MAP  │
      │ HASH     │   │PERCPU_HASH│            │PERCPU_ARR│
      │ 100k     │   │ 10k      │            │ 1        │
      └──────────┘   └──────────┘            └──────────┘
           │               │                       │
           └───────────────┼───────────────────────┘
                           ▼
                    ┌──────────────┐
                    │  XDP Program │
                    │  (kernel)    │
                    │  xdp_drop.o  │
                    │  - parse Eth │
                    │  - parse IP  │
                    │  - lookup IP │
                    │  - drop/allow│
                    └──────────────┘
```

## Components

| File | Purpose |
|------|---------|
| `src/ebpf/xdp_drop.c` | BPF program - Ethernet/IP parsing, blocklist lookup, stats |
| `src/ebpf/xdp_loader.py` | Python loader - ELF parse, bpf() syscalls, IPC server |
| `build_xdp_universal.sh` | Cross-distro build script (Debian/Ubuntu/Fedora/Arch/Kali) |
| `test_xdp_drop.py` | End-to-end test: load, attach, block, verify |
| `Makefile` | Build/test/run automation |

## Supported Distributions

| Distro | Package Manager | Kernel Headers | Tested |
|--------|----------------|----------------|--------|
| Debian/Ubuntu | apt | `linux-headers-$(uname -r)` | ✅ |
| Kali Linux | apt | `linux-headers-$(uname -r)` | ✅ |
| Fedora/RHEL | dnf | `kernel-devel-$(uname -r)` | |
| Arch/Manjaro | pacman | `linux-headers` | |

## Requirements

```bash
# Debian/Ubuntu/Kali
sudo apt install clang llvm linux-headers-$(uname -r) bpftool iproute2 python3

# Fedora/RHEL
sudo dnf install clang llvm kernel-devel-$(uname -r) bpftool iproute python3

# Arch
sudo pacman -S clang llvm linux-headers bpftool iproute2 python3
```

## BPF Map Design

| Map | Type | Key | Value | Max Entries | Purpose |
|-----|------|-----|-------|-------------|---------|
| `blocklist` | HASH | `__u32` (IPv4) | `__u8` (1) | 100,000 | IP blocklist |
| `rate_limit` | PERCPU_HASH | `__u32` (IPv4) | `__u64` (count) | 10,000 | Rate limiting |
| `stats` | PERCPU_ARRAY | `__u32` (0) | `__u64` (dropped) | 1 | Drop counter |

## Building

### Universal Build Script
```bash
./build_xdp_universal.sh
```

Auto-detects:
- Distribution (Debian/Ubuntu/Fedora/Arch/Kali)
- Kernel version
- Kernel headers location
- Architecture (x86_64/arm64)
- BPF helper headers

### Manual Build
```bash
clang -O2 -target bpf -D__TARGET_ARCH_x86 \
  -I/usr/include -I/usr/include/bpf \
  -I/usr/src/linux-headers-$(uname -r)/include \
  -I/usr/src/linux-headers-$(uname -r)/arch/x86/include \
  -c src/ebpf/xdp_drop.c -o src/ebpf/xdp_drop.o \
  -Wno-compare-distinct-pointer-types -Wno-address-of-packed-member
```

## Running

### Test Mode (one-shot)
```bash
sudo python3 test_xdp_drop.py eth0
```
Loads program, attaches to interface, blocks test IP, verifies, cleans up.

### Daemon Mode (production)
```bash
# Terminal 1 - starts loader daemon
sudo python3 src/ebpf/xdp_loader.py load eth0

# Terminal 2 - control via CLI
sudo python3 src/ebpf/xdp_loader.py block 192.168.1.100
sudo python3 src/ebpf/xdp_loader.py status
sudo python3 src/ebpf/xdp_loader.py unblock 192.168.1.100
sudo python3 src/ebpf/xdp_loader.py stop
```

### Makefile Shortcuts
```bash
make build          # Build XDP object
make test IFACE=eth0     # Run test
make run IFACE=eth0      # Run daemon
make block IP=1.2.3.4    # Block IP
make status              # Show stats
make unblock IP=1.2.3.4  # Unblock IP
make stop                # Stop daemon
make unload IFACE=eth0   # Detach only
make clean               # Remove artifacts
```

## IPC Protocol

Unix socket: `/tmp/lidra_xdp.sock`

| Command | Request | Payload | Response | Data |
|---------|---------|---------|----------|------|
| Block | `BLOCK` (4) | IPv4 string | `OK`/`ERR` | `blocked`/`failed` |
| Unblock | `UNBLK` (4) | IPv4 string | `OK`/`ERR` | `unblocked`/`failed` |
| Status | `STATS` (4) | - | `DATA` | JSON `{"dropped": N}` |
| Stop | `STOP` (4) | - | `OK` | `stopping` |
| Ping | `PING` (4) | - | `OK` | `pong` |

Message format: `uint32_t type[4] + uint32_t len + payload`

## Verification

```bash
# Check program loaded
bpftool prog show

# Check attachment
bpftool net show
ip link show eth0

# Check maps
bpftool map show
bpftool map dump id <blocklist_id>
```

Output example:
```
xdpgeneric qdisc fq_codel state UP
prog/xdp id 123 name  tag b1e84bda33025a37 jited
```

## Cross-Distro Notes

### Kernel Version Compatibility
- Requires kernel 5.7+ for `BPF_LINK_CREATE`
- Tested on: 6.x, 7.x

### Architecture Support
- `x86_64` (primary)
- `aarch64` (compile target supported)

### BPF Helpers
Uses system-wide `/usr/include/bpf/bpf_helpers.h` instead of kernel-tree headers.
Works on all modern distros with `libbpf-dev` or equivalent.

### Common Issues

**"Kernel headers not found"**
```bash
# Install matching headers
# Debian/Ubuntu/Kali:
sudo apt install linux-headers-$(uname -r)

# Fedora:
sudo dnf install kernel-devel-$(uname -r)

# Arch:
sudo pacman -S linux-headers
```

**"bpftool not found"**
```bash
# Debian/Ubuntu/Kali:
sudo apt install bpftool

# Fedora:
sudo dnf install bpftool

# Arch:
sudo pacman -S bpftool
```

**"asm/types.h not found"**
The build script adds `/usr/include/$(dpkg-architecture -qDEB_HOST_MULTIARCH)` for multiarch headers.

## Integration with LIDRA Core

The XDP component is designed to integrate with LIDRA's detection engine:

```python
# In detection engine:
from xdp_loader import XDPManager

xdp = XDPManager("src/ebpf/xdp_drop.o")
xdp.load()
xdp.attach("eth0")

# When detection triggers:
xdp.block_ip("192.168.1.50")  # Drops at kernel level

# Get stats:
stats = xdp.get_stats()
print(f"Packets dropped: {stats['dropped']}")
```

## Files Generated

| File | Description |
|------|-------------|
| `src/ebpf/xdp_drop.o` | Compiled BPF object (ELF) |
| `/tmp/lidra_xdp.sock` | IPC socket (runtime) |
| `/sys/fs/bpf/` | BPF filesystem (for pinned objects) |

## License

GPL-2.0 (BPF program) / MIT (loader)

---

**LIDRA** — Lightweight Intrusion Detection & Response Agent