#!/bin/bash
# response.sh - apply responses to IPs using helper (dry_run by default)

set -euo pipefail

# Load directories
BASE_DIR="$(git rev-parse --show-toplevel 2>/dev/null || echo "$(cd "$(dirname "$0")/../.." && pwd)")"
CFG="${BASE_DIR}/config/config.yaml"
STATE_DIR="${BASE_DIR}/state"
LOG_DIR="${BASE_DIR}/logs"

# Create required dirs
mkdir -p "$LOG_DIR"
mkdir -p "$STATE_DIR"

# Already-blocked tracking file
ALREADY_BLOCKED_FILE="${STATE_DIR}/blocked_ips.txt"
touch "$ALREADY_BLOCKED_FILE"

# Read dry-run mode
DRY_RUN=$(grep "dry_run:" "$CFG" | awk '{print $2}')

# Files and helpers
ATTACKERS="${STATE_DIR}/attackers.txt"
BLOCK_HELPER="${BASE_DIR}/src/helpers/block_ip.sh"
RESPONSE_LOG="${LOG_DIR}/response.log"

# Wait for attackers.txt to be created (up to 5 seconds)
for i in {1..5}; do
    if [ -f "$ATTACKERS" ]; then
        break
    fi
    sleep 1
done

# If no attackers list, exit
if [ ! -f "$ATTACKERS" ]; then
  echo "[INFO] No attackers file yet"
  exit 0
fi

# Main IP processing
while read -r IP; do
  [ -z "$IP" ] && continue

  # Skip if already blocked
  if grep -Fxq "$IP" "$ALREADY_BLOCKED_FILE"; then
    echo "[INFO] Skipping already-blocked IP: $IP" >> "$RESPONSE_LOG"
    continue
  fi

  # Log timestamp
  ts=$(date -Iseconds)

  if [ "$DRY_RUN" = "true" ]; then
    echo "$ts [DRY-RUN] Would block $IP" >> "$RESPONSE_LOG"
  else
    echo "$ts [ACTION] Blocking $IP" >> "$RESPONSE_LOG"
    "$BLOCK_HELPER" "$IP" 3600 >> "$RESPONSE_LOG" 2>&1
  fi

  # Mark IP as blocked to prevent double-blocking
  echo "$IP" >> "$ALREADY_BLOCKED_FILE"

done < "$ATTACKERS"

