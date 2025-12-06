#!/bin/bash
# reporting.sh - generate daily CSV report (attacker IP, geo info)
# Writes reports/reports/daily/report_YYYY-MM-DD.csv
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")/../.." && pwd)"   # <--- correct for Project/LIDRA layout
STATE_DIR="${BASE_DIR}/state"
REPORT_DIR="${BASE_DIR}/reports/daily"
TMP_OUT="$(mktemp "${REPORT_DIR}/report_$(date +%F).csv.XXXX")"
OUT="${REPORT_DIR}/report_$(date +%F).csv"

mkdir -p "$REPORT_DIR"

echo "ip,city,region,country,org" > "$TMP_OUT"

# basic dependency checks
if ! command -v curl >/dev/null 2>&1; then
  echo "[ERROR] curl is required. Install: sudo apt install curl" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "[ERROR] jq is required. Install: sudo apt install jq" >&2
  exit 1
fi

if [ ! -f "$STATE_DIR/attackers.txt" ]; then
  echo "[INFO] No attackers file found; creating empty report: $OUT"
  mv "$TMP_OUT" "$OUT"
  exit 0
fi

# process each attacker IP
while IFS= read -r IP || [ -n "$IP" ]; do
  IP="${IP##*( )}"   # trim leading spaces (bash extglob)
  IP="${IP%%*( )}"  # trim trailing spaces
  [ -z "$IP" ] && continue

  # Query ipinfo.io with timeout and small user-agent
  JSON="$(curl -sS --max-time 5 -A "LIDRA-Agent/1.0" "https://ipinfo.io/${IP}/json" 2>/dev/null || echo '{}')"

  # safely extract fields with jq; default to empty string
  CITY="$(echo "$JSON" | jq -r '.city // ""' 2>/dev/null || echo "")"
  REGION="$(echo "$JSON" | jq -r '.region // ""' 2>/dev/null || echo "")"
  COUNTRY="$(echo "$JSON" | jq -r '.country // ""' 2>/dev/null || echo "")"
  ORG="$(echo "$JSON" | jq -r '.org // ""' 2>/dev/null || echo "")"

  # escape double quotes in fields
  CITY="${CITY//\"/\"\"}"
  REGION="${REGION//\"/\"\"}"
  COUNTRY="${COUNTRY//\"/\"\"}"
  ORG="${ORG//\"/\"\"}"

  # write CSV line (fields quoted)
  printf '%s,"%s","%s","%s","%s"\n' "$IP" "$CITY" "$REGION" "$COUNTRY" "$ORG" >> "$TMP_OUT"
done < "$STATE_DIR/attackers.txt"

# atomically move temp report to final location
mv "$TMP_OUT" "$OUT"
echo "[✓] Report written to $OUT"
