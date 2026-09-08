#!/bin/bash
# LIDRA Master Demo: runs all three demos in sequence.
#
# Pre-req: LIDRA TUI is running in another terminal.
#
# This script:
#   1. Starts the vuln_server.py on port 8081 (in background)
#   2. Runs the SQLi demo
#   3. Runs the port scan demo
#   4. Skips the DNS tunnel demo (heavy install) — run it manually
#   5. Cleans up
#
# Usage:
#   ./demo/run_all.sh
#   or open another terminal and:
#     Terminal 1: ./demo/run_all.sh
#     Terminal 2: lidra tui  (or python -m src.lidra_agent_v3 --tui)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

red()    { printf "\033[31m%s\033[0m\n" "$*"; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
bold()   { printf "\033[1m%s\033[0m\n" "$*"; }

bold "=========================================="
bold "  LIDRA — Full Demo (3 attacks, ~60s)"
bold "=========================================="
echo

# Start the vuln server
yellow "[setup] Starting vuln_server.py on :8081..."
python3 "$SCRIPT_DIR/vuln_server.py" 8081 >/tmp/lidra_vuln.log 2>&1 &
VULN_PID=$!
sleep 1
if ! curl -s http://127.0.0.1:8081/healthz >/dev/null 2>&1; then
    red "[!] vuln_server did not start. Check /tmp/lidra_vuln.log"
    kill $VULN_PID 2>/dev/null
    exit 1
fi
green "[setup] vuln_server ready (pid $VULN_PID)"
echo

cleanup() {
    echo
    yellow "[cleanup] Stopping vuln_server..."
    kill $VULN_PID 2>/dev/null || true
    wait $VULN_PID 2>/dev/null || true
    green "[cleanup] Done"
}
trap cleanup EXIT

# Run the SQLi demo
echo
bash "$SCRIPT_DIR/run_sqli_demo.sh"
echo

# Run the port scan demo
echo
bash "$SCRIPT_DIR/run_portscan_demo.sh"
echo

# DNS tunnel demo skipped — manual run required
echo
yellow "[skip] DNS tunnel demo requires iodine + a real authoritative DNS."
yellow "[skip] Run: ./demo/run_dns_tunnel_demo.sh"
echo

bold "=========================================="
bold "  Demo complete. Check the LIDRA TUI:"
bold "    - 3x sql_injection (critical)"
bold "    - port_scan, port_hopping, syn_burst"
bold "    - (DNS tunnel if you ran demo 3)"
bold "=========================================="
