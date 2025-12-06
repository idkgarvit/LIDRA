#!/bin/bash
# deception.sh – Honeyfile watcher + Honeypot listener
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
LOG_DIR="${BASE_DIR}/logs"
STATE_DIR="${BASE_DIR}/state"
CFG="${BASE_DIR}/config/config.yaml"

mkdir -p "$LOG_DIR" "$STATE_DIR/honey"

HONEYFILE="${STATE_DIR}/honey/secret.txt"
HONEYPOT_LOG="${LOG_DIR}/honeypot.log"

########################################
# 1. CREATE HONEYFILE IF NOT EXISTS
########################################
if [ ! -f "$HONEYFILE" ]; then
  echo "TOP_SECRET_PASSWORDS=change-me" > "$HONEYFILE"
  chmod 600 "$HONEYFILE"
fi

########################################
# 2. HONEYFILE WATCHER (inotifywait)
########################################
echo "[+] Honeyfile watcher started..."

inotifywait -m -e open,modify,attrib,delete "$HONEYFILE" \
  --format '%T %w %e %f' --timefmt '%F %T' \
  | while read -r TIMESTAMP PATH EVENT FILE; do
      echo "$TIMESTAMP [HONEYFILE] $EVENT $PATH$FILE" >> "$HONEYPOT_LOG"
      echo "$TIMESTAMP HONEYFILE_HIT $PATH$FILE" >> "$STATE_DIR/honey_hits.db"
    done &

########################################
# 3. HONEYPOT (PORT TRAP)
########################################
HONEY_PORT=$(grep "honeypot_port" "$CFG" | grep -o '[0-9]\+')

echo "[+] Starting netcat honeypot on port $HONEY_PORT..."

start_honeypot() {
  while true; do
    echo "$(date -Iseconds) [HONEYPOT] listener starting on $HONEY_PORT" >> "$HONEYPOT_LOG"

    # -k keeps netcat open even after a client disconnects
    # 2>&1 so errors also go to the log
    nc -lvnp "$HONEY_PORT" -k 2>&1 | while read -r line; do
        echo "$(date -Iseconds) [HONEYPOT][CONN] $line" >> "$HONEYPOT_LOG"
    done

    # sleep avoids tight loop if nc crashes
    sleep 1
  done
}

# Start honeypot if not already running
if ! pgrep -f "nc -lvnp $HONEY_PORT" >/dev/null; then
  start_honeypot &
fi

# Keep script alive to maintain background jobs
wait

