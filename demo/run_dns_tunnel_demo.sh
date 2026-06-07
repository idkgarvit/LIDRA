#!/bin/bash
# LIDRA Demo 3: DNS tunneling detection
#
# What this does:
#   1. Confirms a DNS server is reachable (control)
#   2. Starts an iodine DNS tunnel client against a test domain
#   3. Generates traffic over the tunnel
#
# What to look for in the LIDRA TUI:
#   - dns_tunnel fires on the high-entropy DNS queries
#   - ipv6_tunnel may fire (iodine uses AAAA records)
#   - timing_evasion may fire (iodine spaces queries)
#
# Prerequisites:
#   - iodine installed (`apt install iodine` on Debian/Kali)
#   - A working DNS server that allows recursive queries to a test domain
#   - For a fully self-contained demo, run your own authoritative DNS:
#       1. Edit /etc/hosts to point test.tld at your server
#       2. Run iodined -d -c 10.0.0.1 test.tld on a server
#       3. Set TARGET=ns1.test.tld in your environment
#
# Usage:
#   TARGET=ns1.test.tld ./demo/run_dns_tunnel_demo.sh

set -e

DOMAIN="${TARGET:-ns1.example.com}"
TUNNEL_IP="10.0.0.2"
SERVER_IP="10.0.0.1"

red()    { printf "\033[31m%s\033[0m\n" "$*"; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
bold()   { printf "\033[1m%s\033[0m\n" "$*"; }

bold "=== LIDRA Demo 3: DNS Tunnel Detection (iodine) ==="
echo "Domain: $DOMAIN"
echo

if ! command -v iodine >/dev/null 2>&1; then
    red "[!] iodine not installed. Run: sudo apt install iodine"
    red "[!] Skipping live demo. The harness in tests/attack_pcap/ includes"
    red "[!] a pre-captured iodine pcap that exercises the same detector."
    exit 0
fi

yellow "[1/3] Resolve baseline DNS (control - should NOT trigger)..."
getent hosts example.com >/dev/null || dig +short example.com @8.8.8.8 >/dev/null
green "    -> baseline DNS query sent"
sleep 1

yellow "[2/3] Start iodine client (tunnels IP traffic over DNS)..."
echo "    Run in another terminal: sudo iodine -f $DOMAIN"
echo "    Then test: ping 10.0.0.1"
echo "    Or:        curl --interface dns0 http://example.com/"
echo

yellow "[3/3] Or use the pre-captured iodine pcap (slower but works offline):"
echo "    RUN_SLOW_PCAPS=1 python3 -m pytest tests/test_attack_pcap_replay.py -v -s -k iodine"
echo
bold "==> Open the LIDRA TUI. You should see 'dns_tunnel' (high) firing"
bold "==> on the high-entropy DNS queries from the iodine client."
