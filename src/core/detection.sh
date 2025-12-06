#!/bin/bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
STATE_DIR="${BASE_DIR}/state"

# Default real log
LOG_FILE="/var/log/auth.log"

# If real log doesn't exist → use fake log
FAKE_LOG="${BASE_DIR}/tests/fake_logs/auth.log"

if [ ! -f "$LOG_FILE" ]; then
    if [ -f "$FAKE_LOG" ]; then
        LOG_FILE="$FAKE_LOG"
        echo "[INFO] Using fake log: $LOG_FILE"
    else
        echo "[WARN] No auth.log and no fake log found."
        exit 0
    fi
fi

# ---------------------------------------------------
# Count failed SSH login attempts by IP
# ---------------------------------------------------

# Extract only "Failed password" lines
FAILED_LINES=$(grep "Failed password" "$LOG_FILE" || true)

# No failures at all?
if [ -z "$FAILED_LINES" ]; then
    echo "[INFO] No failed login attempts found."
    exit 0
fi

# Count fails per IP
declare -A FAIL_COUNTS=()

while read -r line; do
    IP=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if ($i=="from") {print $(i+1); exit}}')
    if [[ -n "$IP" ]]; then
        FAIL_COUNTS["$IP"]=$((FAIL_COUNTS["$IP"]+1))
    fi
done <<< "$FAILED_LINES"

# Threshold from config (default 5)
THRESHOLD="${THRESHOLD:-5}"

# Decide if attacker should be added
for IP in "${!FAIL_COUNTS[@]}"; do
    COUNT=${FAIL_COUNTS[$IP]}

    echo "[DEBUG] $IP → $COUNT failures"

    # Only proceed if COUNT is a number
    if ! [[ "$COUNT" =~ ^[0-9]+$ ]]; then
        echo "[WARN] Non-numeric fail count for $IP: $COUNT"
        continue
    fi

    if (( COUNT >= THRESHOLD )); then
        grep -qx "$IP" "$STATE_DIR/attackers.txt" || echo "$IP" >> "$STATE_DIR/attackers.txt"
        echo "[INFO] Attacker detected: $IP (failed $COUNT times)"
    fi
done
