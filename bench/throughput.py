"""LIDRA throughput bench: paced SYNs -> NIC TX vs engine packets_in + agent CPU."""
import json
import os
import socket
import subprocess
import sys
import time

IFACE = "eth0"
TARGET = "192.168.1.1"
PORT = 45678  # closed on router: SYN egresses, RST returns, no service impact
SOCK = os.environ.get("LIDRA_TUI_SOCKET") or __import__("glob").glob("/tmp/lidra_tui_*.sock")[0]
AGENT_PID = int(subprocess.run(["pgrep", "-f", "lidra_agent_v3.*--no-tui"],
                               capture_output=True, text=True).stdout.split()[0])
CLK = os.sysconf("SC_CLK_TCK")
# ponytail: sudo password comes from the environment, never hardcoded —
# a committed password is a leaked credential. Run with:
#   LIDRA_SUDO_PASSWORD='<pw>' python3 bench/throughput.py
SUDO_PW = os.environ.get("LIDRA_SUDO_PASSWORD")
if not SUDO_PW:
    sys.exit("Set LIDRA_SUDO_PASSWORD to run the flood sender (bench only — never commit it).")


def nic_tx():
    with open("/proc/net/dev") as f:
        for line in f:
            if line.strip().startswith(IFACE + ":"):
                # [0]=iface: [1..8]=rx [9]=tx_bytes [10]=tx_packets
                return int(line.split()[10])
    raise RuntimeError("no iface")


def engine_packets():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.sendall(b'{"command": "SNAPSHOT"}\n')
    s.settimeout(5)
    buf = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            for line in buf.split(b"\n"):
                try:
                    m = json.loads(line)
                except ValueError:
                    continue
                if m.get("type") == "snapshot":
                    return m["data"]["stats"]["total_packets"]
    except socket.timeout:
        pass
    raise RuntimeError("no snapshot")


def proc_jiffies():
    with open(f"/proc/{AGENT_PID}/stat") as f:
        p = f.read().rsplit(")", 1)[1].split()
    return int(p[11]) + int(p[12])  # utime + stime


def cpu_pct(dproc, elapsed):
    return round(dproc / CLK / elapsed * 100, 1)


print(f"{'rate':>6} {'sent':>6} {'NIC_TX':>8} {'ENG':>8} {'capture%':>9} {'cpu%':>6}")
for rate in [200, 500, 1000, 2000, 5000]:
    count = rate * 5
    interval = max(int(1_000_000 / rate), 200)
    tx0, eng0, j0 = nic_tx(), engine_packets(), proc_jiffies()
    t0 = time.time()
    subprocess.run(["sudo", "-S", "-E", "hping3", "-S", "-p", str(PORT),
                    "-i", f"u{interval}", "-c", str(count), TARGET],
                   input=SUDO_PW + "\n", capture_output=True, text=True)
    el = time.time() - t0
    time.sleep(1)
    txd, engd, jd = nic_tx() - tx0, engine_packets() - eng0, proc_jiffies() - j0
    print(f"{rate:>6} {count:>6} {txd:>8} {engd:>8} "
          f"{(engd / txd * 100 if txd else 0):>8.1f}% {cpu_pct(jd, el):>6}", flush=True)
