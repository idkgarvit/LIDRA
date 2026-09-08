#!/bin/bash
# LIDRA Demo 2: Port scan detection
#
# What this does:
#   1. Single port probe (control: should NOT trigger)
#   2. Full TCP SYN scan against the target
#   3. UDP scan (top 20 ports)
#   4. Service version detection on the open port
#
# What to look for in the LIDRA TUI:
#   - port_scan and port_hopping fire on the full scan
#   - syn_burst fires (volume-based)
#   - syn_flood may fire if scan is very fast
#   - If auto-block is enabled, scanner IP gets dropped
#
# Usage:
#   ./demo/run_portscan_demo.sh [TARGET_IP]
#   defaults to 127.0.0.1

set -e

TARGET="${1:-127.0.0.1}"
SLEEP_BETWEEN=2

red()    { printf "\033[31m%s\033[0m\n" "$*"; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
bold()   { printf "\033[1m%s\033[0m\n" "$*"; }

bold "=== LIDRA Demo 2: Port Scan Detection ==="
echo "Target: $TARGET"
echo

yellow "[1/4] Single port probe (control - should NOT trigger)..."
nmap -Pn -p 8081 --max-retries 0 "$TARGET" >/dev/null 2>&1 || true
green "    -> probe sent, no detection expected"
sleep $SLEEP_BETWEEN

yellow "[2/4] Full TCP SYN scan (1000 ports)..."
nmap -Pn -sS -p 1-1000 --max-retries 0 -T4 "$TARGET" >/dev/null 2>&1 || true
green "    -> 1000 SYNs sent, expect 'port_scan', 'port_hopping', 'syn_burst'"
sleep $SLEEP_BETWEEN

yellow "[3/4] UDP scan (top 20 ports)..."
nmap -Pn -sU --top-ports 20 --max-retries 0 "$TARGET" >/dev/null 2>&1 || true
green "    -> UDP probes sent (NB: UDP scan detection is a known gap)"
sleep $SLEEP_BETWEEN

yellow "[4/4] Service version detection on the open port..."
nmap -Pn -sV -p 8081 "$TARGET" >/dev/null 2>&1 || true
green "    -> service probe sent, expect 'port_hopping' (single port but verbose)"
echo

bold "==> Open the LIDRA TUI. You should see port_scan + port_hopping alerts."
bold "==> Top sources: your scanner IP (or the loopback if scanning localhost)"
