#!/usr/bin/env bash
# Stage 2 live-matrix harness — real packets through LIDRA's real capture path.
#
# This wrapper creates ONE user+network namespace and runs the driver inside it.
# The driver then makes a *sibling* network namespace for the attacker, which is
# what makes frames genuinely cross the wire — see _in_ns.sh for the traps that
# rule out the simpler topologies (all of them measured, all of them useless).
#
# Why this works without root:
#   `unshare --user --map-root-user` gives uid 0 and full capabilities inside the
#   namespace, while leaving the host untouched — no sudo, no host firewall, no
#   changes to the machine's networking.
#
# What this does NOT cover (needs a second machine or a VM, by design):
#   S6 (a kernel without `nft ... bypass` — containers share the host kernel),
#   the distro matrix, the uninstaller residue test, and real-LAN confirmation.
#
# Usage:
#   tests/live/matrix.sh <case>     run one case
#   tests/live/matrix.sh all        run the runnable subset
#   tests/live/matrix.sh list       show cases
#
# Each case prints exactly one line: "RESULT: PASS <case> ..." or
# "RESULT: FAIL <case> <why>". That line is the machine-readable contract.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NS_SCRIPT="$REPO/tests/live/_in_ns.sh"

case_list() { sed -n 's/^#CASE:\([a-z0-9_-]*\).*/\1/p' "$NS_SCRIPT"; }

run_case() {
  local case="$1"
  echo "=== case: $case ==="
  # --pid --fork so the sibling attacker namespace can be reaped; --mount so
  # /run/netns-style paths do not leak (they are refused anyway).
  #
  # NOTE: no --pid here. Under an outer --pid namespace the sibling's PID is a
  # *local* PID (e.g. 6), and `ip link set atk0 netns 6` is rejected with
  # "Invalid netns value" because the kernel resolves it in the wrong namespace.
  # Measured both ways: with --pid the move fails, without it it succeeds.
  timeout 300 unshare --user --map-root-user --net --mount \
      env LIDRA_REPO="$REPO" bash "$NS_SCRIPT" "$case"
  local rc=$?
  [ $rc -eq 124 ] && echo "RESULT: FAIL $case timeout(300s)"
  return $rc
}

case "${1:-list}" in
  list) case_list ;;
  all)
    rc=0; pass=0; fail=0
    for c in $(case_list); do
      out=$(run_case "$c")
      echo "$out"
      if echo "$out" | grep -q "^RESULT: PASS $c"; then pass=$((pass+1)); else fail=$((fail+1)); rc=1; fi
      echo
    done
    echo "===================="
    echo "live matrix: $pass passed, $fail failed"
    exit $rc
    ;;
  *) run_case "$1" ;;
esac