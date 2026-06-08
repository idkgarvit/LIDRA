# Scaling LIDRA — From Python to eBPF/XDP

## Current performance

Python inline engine: **1,000–15,000 pps** depending on analysis depth.
On the reference hardware (i5-12450H, 7.8 GiB RAM) this translates to
roughly **10–100 Mbps** of sustained throughput.

See `bench/RESULTS.md` for detailed numbers.

## Why not just faster Python?

The Python path has three hard limits:

1. **Packet decode (dpkt)**: Each packet is decoded field-by-field
   in Python. Ethernet + IP + TCP header extraction is ~10 µs/packet,
   or 100,000 pps for header-only. Adding payload inspection (DPI,
   DNS parsing, entropy) pushes this to 100–1,000 µs/packet.

2. **GIL contention**: The pipeline is single-threaded by design
   (packet ordering matters for flow reassembly). Scaling across
   cores requires RSS + per-queue workers, each with its own
   engine instance and a merge step.

3. **Python VM overhead**: A no-op packet handler in Python
   maxes out at ~200,000 pps. The "fastest possible" Python
   path is still 50× slower than a kernel bypass solution.

## The eBPF/XDP offload path

The strategy is **three-tier filtering**:

```
Packet arrives
    │
    ▼
Tier 1: XDP (kernel, eBPF)    → 10–50 Mpps
    │  Drop known-bad, ratelimit, sample to userspace
    │
    ▼
Tier 2: AF_XDP / nfqueue       → 1–5 Mpps
    │  Fast-path pass, slow-path redirect
    │
    ▼
Tier 3: Python engine          → 1–15 Kpps
    │  Deep inspection of sampled / suspicious flows
    │
    ▼
Verdict: block, log, or ignore
```

### Tier 1: eBPF/XDP (first-pass filter)

**What it does:**
- Drops traffic from CIDR allowlist (known-good IPs never reach Python)
- Drops traffic on blocklist (previously-seen attackers)
- Rate-limits per-source-IP at kernel speed (token bucket in eBPF)
- Hashes + counts flows for SYN flood detection (lightweight, counter-based)
- Passes everything else to Tier 2

**Performance:** 10–50 million pps (limited by NIC + kernel, not eBPF).

**Implementation:**
```c
// xdp_filter.c (conceptual)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, u32);   // source IP
    __type(value, u64); // packet count
} ip_counter SEC(".maps");

SEC("xdp")
int xdp_pass_or_drop(struct xdp_md *ctx) {
    // Parse Ethernet + IP
    // Check allowlist map
    // Check blocklist map
    // Count and ratelimit
    // Return XDP_PASS or XDP_DROP
}
```

**Dependencies:**
- Kernel: Linux 5.15+ with CONFIG_BPF=y
- Toolchain: clang-14+, bpftool
- NIC driver with XDP support (most modern drivers: ixgbe, i40e, mlx5, virtio_net)

### Tier 2: AF_XDP fast path

**What it does:**
- Receives XDP_PASS packets from Tier 1
- Reconstructs flows using a zero-copy userspace ring buffer
- Applies deterministic filters (port, protocol, packet size)
- Routes to Python via shared memory ring buffer
- Can forward at > 1 Mpps without touching the kernel stack

**Implementation:**
Written in Rust (or C). A 500-line program using libbpf + AF_XDP sockets.

**Performance:** 1–5 million pps (bounded by memory bandwidth, not CPU).

**Dependencies:**
- Rust 1.75+ with `libbpf-sys` crate (or plain C with libbpf)
- Hugepages (2 MB pages for the UMEM region)

### Tier 3: Python deep inspection

**What it does:**
- Receives only suspicious flows from Tier 2 (not every packet)
- Runs full detection pipeline (DPI, entropy, behavioral, fingerprinting)
- Returns verdict: block, ignore, or escalate

This is the existing `InlineEngine`. No changes needed to the detection
logic — only the input mechanism changes (shared memory ring → packet
callback).

**Performance:** 1–15 Kpps (unchanged from today — this is the quality
layer, not the speed layer).

## Implementation stages

### Stage 0: socket filter (easiest, lowest impact)

Add a BPF (cBPF) socket filter via `tcpdump` expression to the
existing pcap/nfqueue capture. This is a 30-line change to
`bridge/inline_engine.py`:

```python
import bpf
from scapy.arch.bpf.supersocket import SOCKET_FILTER

# Filter: drop inbound SSH (already handled by auth.log parser)
filter_expr = "not (port 22 and inbound)"
SOCKET_FILTER.append(bpf.compile(filter_expr))
```

**Effect:** Reduces idle CPU by 10–20% on servers with high SSH traffic.
**Effort:** 1 hour.

### Stage 1: allowlist + blocklist in eBPF (high value, medium effort)

Compile and load a simple XDP program that checks two LRU hash maps
before passing to Python. The existing allowlist and blocklist in
Python are synced to eBPF maps periodically.

**Files:** `src/ebpf/xdp_filter.c`, `src/ebpf/loader.py`
**Effort:** 3–5 days.

### Stage 2: kernel-side rate limiting (medium)

Add a per-IP token bucket in eBPF. Drops sustained high-rate sources
without telling Python. Configurable pps threshold.

**Effort:** 2–3 additional days.

### Stage 3: AF_XDP ring buffer (hard)

Replace the nfqueue/pcap read with an AF_XDP zero-copy umem.
Python reads from a shared memory ring; Tier 2 Rust/C layer
feeds the ring.

**Effort:** 2–4 weeks (Rust libbpf bindings, memory management,
  Python C extension or ctypes loop).

### Stage 4: flow-level sampling (hardest)

Instead of passing every packet to Python, Tier 2 groups packets into
flows and sends only the first N packets + periodic samples. Python
makes a verdict per-flow, not per-packet.

**Effort:** 4–8 weeks (flow table in Rust, session key hashing,
  interaction with existing `ConnectionTracker` and `StreamReassembler`).

## Expected performance by stage

| Stage | Pps | Sustained throughput | Implementation effort |
|---|---|---|---|
| 0 (socket filter) | 1–15 K | 10–100 Mbps | 1 hour |
| 1 (XDP + maps) | 10–50 K | 100–400 Mbps | 3–5 days |
| 2 (XDP + rate limit) | 50–100 K | 400–800 Mbps | 1 week |
| 3 (AF_XDP ring) | 500 K–1 M | 1–5 Gbps | 2–4 weeks |
| 4 (flow sampling) | 1–10 M | 5–40 Gbps | 1–2 months |

## When to scale

**Current state (Stage 0):** Sufficient for:
- Edge/SOHO networks with < 500 clients
- Traffic <= 50 Mbps sustained
- Lab/demo/prototype environments

**Stage 1–2:** Needed when:
- Traffic consistently exceeds 20 Kpps
- > 50 Mbps sustained on a single interface
- CPU usage from Python packet handling exceeds 60%

**Stage 3–4:** Needed when:
- Deploying on 10 Gbps+ links
- Handling > 100 Kpps
- Running as an inline gateway (not just a tap/SPAN)

## Integration with existing LIDRA

The existing detection logic does not change. Each stage adds a kernel
filter that either drops packets or feeds them to Python. The Python
engine sees a smaller, more curated packet stream.

The key invariant: **a packet that reaches Python must be processed by
all 13 analyzers**. Tier 1+2 only decide *which* packets reach Python;
they never make detection decisions (except allowlist/blocklist, which
are deterministic).

## Existing eBPF code

The repo already has `src/ebpf/tracer.py` which loads and manages eBPF
programs. The current implementation is a basic traffic counter. This
is the right module to extend for the XDP path. See `src/ebpf/` for
the existing kernel-side infrastructure.
