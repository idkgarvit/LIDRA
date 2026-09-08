#!/bin/bash
# LIDRA Demo 1: SQL injection detection
#
# What this does:
#   1. Confirms the vuln server is reachable
#   2. Sends a normal request (control: should NOT trigger)
#   3. Sends a classic boolean SQLi payload (should trigger)
#   4. Sends a UNION-based SQLi (should trigger)
#   5. Sends a time-based blind SQLi (should trigger)
#
# What to look for in the LIDRA TUI:
#   - Stats counter for "sql_injection" should increment 3x
#   - Detail panel should show source IP, URI, severity=critical
#   - If auto-block is enabled, the source IP gets dropped
#
# Usage:
#   ./demo/run_sqli_demo.sh [TARGET_URL]
#   defaults to http://127.0.0.1:8081

set -e

TARGET="${1:-http://127.0.0.1:8081}"
SLEEP_BETWEEN=1.5

red()    { printf "\033[31m%s\033[0m\n" "$*"; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
bold()   { printf "\033[1m%s\033[0m\n" "$*"; }

bold "=== LIDRA Demo 1: SQL Injection ==="
echo "Target: $TARGET"
echo

yellow "[1/4] Health check (control - should NOT trigger)..."
curl -s "$TARGET/" >/dev/null
green "    -> 200 OK, no detection expected"
sleep $SLEEP_BETWEEN

yellow "[2/4] Boolean SQLi: ' OR '1'='1"
curl -s -G "$TARGET/search" --data-urlencode "q=' OR '1'='1" >/dev/null
green "    -> sent, expect 'sql_injection' (critical)"
sleep $SLEEP_BETWEEN

yellow "[3/4] UNION-based SQLi"
PAYLOAD="1 UNION SELECT username,password FROM users--"
curl -s -G "$TARGET/search" --data-urlencode "q=$PAYLOAD" >/dev/null
green "    -> sent, expect 'sql_injection' (critical)"
sleep $SLEEP_BETWEEN

yellow "[4/4] Time-based blind SQLi"
PAYLOAD="1; WAITFOR DELAY '0:0:5'--"
curl -s -G "$TARGET/search" --data-urlencode "q=$PAYLOAD" >/dev/null
green "    -> sent, expect 'sql_injection' (critical)"
echo

bold "==> Open the LIDRA TUI. You should see 3 sql_injection alerts."
bold "==> Detail panel: attack_type=sql_injection, severity=critical, confidence=0.9"
