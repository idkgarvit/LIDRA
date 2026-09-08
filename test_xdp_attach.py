#!/usr/bin/env python3
"""
Quick test: load XDP and attach via bpftool.
"""
import os
import subprocess
import json
import sys
import time
from pathlib import Path

if os.geteuid() != 0:
    sys.exit("needs root (bpf syscalls): rerun with sudo")

# Add the src/ebpf directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent / "src" / "ebpf"))

from xdp_loader import XDPManager

OBJ = Path(__file__).resolve().parent / "src" / "ebpf" / "xdp_drop.o"
IFACE = sys.argv[1] if len(sys.argv) > 1 else "eth0"
XDP_TAG = "b1e84bda33025a37"

print(f"Loading XDP from {OBJ}, attaching to {IFACE}")

# 1. Load the program
xdp = XDPManager(OBJ)
if not xdp.load():
    print("FAILED to load XDP program")
    sys.exit(1)

print(f"Program fd: {xdp.prog_fd}")
print(f"Map fds: blocklist={xdp.map_fds.get('blocklist')}, "
      f"rate_limit={xdp.map_fds.get('rate_limit')}, "
      f"stats={xdp.map_fds.get('stats')}")

# 2. Get prog_id via bpftool by tag
time.sleep(0.5)  # brief pause for kernel to register
result = subprocess.run(
    ["bpftool", "prog", "list", "--json"],
    capture_output=True, timeout=10, text=True,
)
if result.returncode != 0:
    print(f"bpftool list failed: {result.stderr}")
    sys.exit(1)

prog_id = None
for p in json.loads(result.stdout):
    if p.get("tag") == XDP_TAG:
        prog_id = p["id"]
        print(f"Found program: id={p['id']}, tag={p['tag']}, type={p.get('type')}")
        break

if prog_id is None:
    print(f"Could not find program with tag {XDP_TAG}")
    print("Available XDP programs:")
    for p in json.loads(result.stdout):
        if p.get("type") == "xdp":
            print(f"  id={p['id']}, tag={p['tag']}, name={p.get('name', '')}")
    sys.exit(1)

# 3. Attach via bpftool
print(f"Attaching XDP (id={prog_id}) to {IFACE}...")

# First detach any existing XDP
subprocess.run(
    ["bpftool", "net", "detach", "xdp", "dev", IFACE],
    capture_output=True, timeout=10,
)

result = subprocess.run(
    ["bpftool", "net", "attach", "xdp", "id", str(prog_id), "dev", IFACE],
    capture_output=True, timeout=10, text=True,
)

if result.returncode == 0:
    print(f"✅ XDP attached to {IFACE} (prog_id={prog_id})")
else:
    print(f"❌ bpftool attach failed: {result.stderr}")
    print("Trying ip link pinned approach...")

    # 4. Try pinning to bpffs
    p = subprocess.run(
        ["bpftool", "prog", "pin", str(xdp.prog_fd), f"/sys/fs/bpf/lidra_{IFACE}"],
        capture_output=True, timeout=10, text=True,
    )
    if p.returncode == 0:
        print("Pinned to /sys/fs/bpf/")
        # Detach existing
        subprocess.run(["/sbin/ip", "link", "set", "dev", IFACE, "xdp", "off"],
                       capture_output=True, timeout=10)
        # Attach via pinned
        result2 = subprocess.run(
            ["/sbin/ip", "link", "set", "dev", IFACE, "xdp", "pinned",
             f"/sys/fs/bpf/lidra_{IFACE}"],
            capture_output=True, timeout=10, text=True,
        )
        if result2.returncode == 0:
            print(f"✅ XDP attached via pinned path")
        else:
            print(f"❌ ip link pinned failed: {result2.stderr}")
    else:
        print(f"❌ Pin failed: {p.stderr}")

# 5. Verify attachment
result = subprocess.run(
    ["/sbin/ip", "-details", "link", "show", IFACE],
    capture_output=True, timeout=10, text=True,
)
for line in result.stdout.split("\n"):
    if "xdp" in line.lower():
        print(f"  {line.strip()}")

# 6. Test block
print(f"\nBlocking 10.0.0.1...")
xdp.block_ip("10.0.0.1")
print(f"  Blocked. Stats: {xdp.get_stats()}")

# 7. Keep running for a bit to test, then detach
print(f"\nXDP is active. Detaching in 3 seconds...")
time.sleep(3)

print(f"Detaching...")
xdp.detach()
xdp.cleanup()
print("Done.")
