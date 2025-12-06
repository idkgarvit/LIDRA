#!/bin/bash
# block_ip.sh - safe blocker helper (demo by default)

set -euo pipefail

# Compute directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
STATE_DIR="${BASE_DIR}/state"

LOG_DIR="${BASE_DIR}/logs/block_logs"
BLOCKS_LOG="${LOG_DIR}/blocks.log"
BLOCKS_DB="${STATE_DIR}/blocks.db"

# --------------------------
#  Args
# --------------------------
if [ $# -lt 1 ]; then
    echo "[ERROR] Usage: $0 <IP> [TTL] [--apply]" >&2
    exit 2
fi

IP="$1"
TTL="${2:-3600}"
APPLY="${3:-false}"

# Validate IP
if ! [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "[ERROR] Invalid IP: $IP"
    exit 3
fi

# --------------------------
#   Ensure paths exist
# --------------------------
mkdir -p "$LOG_DIR"
touch "$BLOCKS_LOG"
chmod 666 "$BLOCKS_LOG"

mkdir -p "$STATE_DIR"
touch "$BLOCKS_DB"

TS="$(date -Iseconds)"

# --------------------------
#  Logging (visible + file)
# --------------------------
echo "[INFO] Blocking $IP (TTL=$TTL)"

echo "$TS BLOCK $IP TTL=$TTL" >> "$BLOCKS_LOG"
echo "$IP,$TS,$TTL" >> "$BLOCKS_DB"

# --------------------------
#  Real firewall block (demo)
# --------------------------
if [ "$APPLY" = "--apply" ]; then
    echo "[ACTION] Applying real firewall block on $IP"
else
    echo "[DRY-RUN] Firewall NOT applied (demo mode)." >> "$BLOCKS_LOG"
fi

