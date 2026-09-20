#!/usr/bin/env bash
# LIDRA installer — one script, two doors.
#
#   curl -fsSL <url>/install.sh | bash                  # asks: laptop or gateway?
#   curl -fsSL <url>/install.sh | bash -s -- --laptop   # laptop, non-interactive
#   curl -fsSL <url>/install.sh | bash -s -- --gateway  # gateway, non-interactive
#   ./install.sh --laptop --enforce                     # from a clone
#   ./install.sh --uninstall                            # remove LIDRA (escape route)
#
# Flags:
#   --laptop | --gateway     deployment mode (default: ask; required when non-interactive)
#   --enforce | --monitor    block attacks, or accept-all + log what WOULD drop (default: --monitor)
#   --prefix PATH            install root (default: /opt/lidra)
#   --uninstall              remove LIDRA (delegates to install/uninstall.sh)
#   --purge                  with --uninstall: also delete the database
#   --yes                    with --uninstall: answer yes to prompts
# Env passthrough to install/post_install.sh: LIDRA_NO_DEPS, LIDRA_NO_SERVICE,
# LIDRA_NO_XDP, LIDRA_NO_ENABLE — all honored.
#
# What each door does:
#   laptop  — local mode: shields INCOMING traffic to this machine, drops
#             attacks before your apps. No bridge questions, no second NIC.
#   gateway — company second line: transparent bridge AFTER the firewall and
#             BEFORE the servers. Needs 2 NICs (or 1 + VLAN trunk) + nftables.

set -euo pipefail

MODE=""          # laptop | gateway
ENFORCE="monitor"
PREFIX="${LIDRA_PREFIX:-/opt/lidra}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { printf "${BLUE}[lidra-install]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[  ok  ]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[ warn ]${NC} %s\n" "$*" >&2; }
err()  { printf "${RED}[ fail ]${NC} %s\n" "$*" >&2; }

usage() {
    # Everything between the shebang and the first line of code, so the help can
    # never drift from the flags the script actually accepts.
    awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --laptop)  MODE="laptop" ;;
        --gateway) MODE="gateway" ;;
        --enforce) ENFORCE="enforce" ;;
        --monitor) ENFORCE="monitor" ;;
        --prefix)  PREFIX="$2"; shift ;;
        --uninstall) UNINSTALL=true ;;
        --purge)   PURGE=true ;;
        --yes|-y)  YES=true ;;
        --help|-h) usage; exit 0 ;;
        *) err "Unknown flag: $1"; usage; exit 1 ;;
    esac
    shift
done

# ----- uninstall door --------------------------------------------------------
# An operator whose network is misbehaving reads this command from a phone and
# types one line, so --uninstall has to work before anything else: no mode
# questions, no dependency checks, no clone. Hand it to the uninstaller in
# whichever tree is present and pass the same flags through.
if [ "${UNINSTALL:-false}" = true ]; then
    for candidate in "$SCRIPT_DIR/install/uninstall.sh" "$PREFIX/install/uninstall.sh"; do
        if [ -f "$candidate" ]; then
            uninstall_args=(--prefix "$PREFIX")
            [ "${PURGE:-false}" = true ] && uninstall_args+=(--purge)
            [ "${YES:-false}" = true ] && uninstall_args+=(--yes)
            log "Delegating to $candidate"
            exec bash "$candidate" "${uninstall_args[@]}"
        fi
    done
    err "install/uninstall.sh not found (looked in $SCRIPT_DIR and $PREFIX)."
    err "Run it directly:  sudo bash <checkout>/install/uninstall.sh"
    exit 1
fi

# ----- door choice -----
if [ -z "$MODE" ]; then
    if [ ! -t 0 ]; then
        err "No TTY — re-run with --laptop or --gateway."
        err "  curl -fsSL <url>/install.sh | bash -s -- --laptop"
        exit 1
    fi
    echo "Where is LIDRA standing guard?"
    echo "  1) laptop   — shield THIS machine's incoming traffic (personal)"
    echo "  2) gateway  — bridge AFTER firewall, BEFORE servers (company)"
    printf "Choice [1/2]: "; read -r CHOICE
    case "$CHOICE" in
        1|"") MODE="laptop" ;;
        2)    MODE="gateway" ;;
        *)    err "Pick 1 or 2."; exit 1 ;;
    esac
    printf "Block attacks right away, or monitor-first (log what WOULD drop)? [monitor/enforce, default monitor]: "
    read -r ECHOICE
    case "$ECHOICE" in
        enforce) ENFORCE="enforce" ;;
        *)       ENFORCE="monitor" ;;
    esac
fi
log "Mode=${MODE} enforcement=${ENFORCE} prefix=${PREFIX}"

# ----- source: repo clone if present, else git clone to tmp -----
if [ -f "$SCRIPT_DIR/install/post_install.sh" ] && [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    SRC_DIR="$SCRIPT_DIR"
else
    command -v git >/dev/null 2>&1 || { err "git not found — clone the repo and run ./install.sh instead."; exit 1; }
    SRC_DIR="${LIDRA_SRC_TMP:-/tmp/lidra-src}"
    if [ ! -f "$SRC_DIR/install/post_install.sh" ]; then
        log "Fetching LIDRA source..."
        git clone --depth 1 "${LIDRA_REPO:-https://github.com/idkgarvit/LIDRA.git}" "$SRC_DIR"
    fi
fi

# ----- gateway preflight (before touching anything) -----
WAN=""; LAN=""
if [ "$MODE" = "gateway" ]; then
    command -v nft >/dev/null 2>&1 || warn "nftables not found — post-install will try to add it (required for gateway)."
    NICS="$(ls /sys/class/net | grep -v '^lo$' || true)"
    log "Interfaces seen: $(echo "$NICS" | tr '\n' ' ')"
    if [ "$(echo "$NICS" | wc -l)" -lt 2 ]; then
        warn "Only one NIC visible — gateway normally wants two (WAN from firewall, LAN to servers)."
        warn "Continuing anyway (VLAN trunk or lab setup possible)."
    fi
    if [ -t 0 ]; then
        printf "WAN interface (faces firewall) [%s]: " "$(echo "$NICS" | head -1)"; read -r WAN
        printf "LAN interface (faces servers)  : "; read -r LAN
        WAN="${WAN:-$(echo "$NICS" | head -1)}"
    fi
    [ -n "$LAN" ] || warn "No LAN given — you'll set bridge.interfaces in $PREFIX/config/config.yaml manually."
fi

# ----- core install (shared) -----
log "Running core install from $SRC_DIR ..."
LIDRA_PREFIX="$PREFIX" LIDRA_SRC="$SRC_DIR" bash "$SRC_DIR/install/post_install.sh"

# ----- mode config patch -----
log "Writing ${MODE} configuration..."
# ponytail: venv python (has PyYAML via requirements) first; system python3
# often lacks it — and without `set -e` a failed patch must NOT print ok.
PYBIN="$PREFIX/venv/bin/python"
[ -x "$PYBIN" ] || PYBIN="python3"
# ponytail: `if !` — under `set -e` a bare failing command exits before any `$?` check.
if ! "$PYBIN" - "$PREFIX/config/config.yaml" "$MODE" "$ENFORCE" "$WAN" "$LAN" <<'PY'
import sys
try:
    import yaml
except ImportError:
    sys.exit("PyYAML not installed for %s" % sys.executable)
path, mode, enforce, wan, lan = sys.argv[1:6]
with open(path) as f:
    cfg = yaml.safe_load(f) or {}
enforce = (enforce == "enforce")
resp = cfg.setdefault("response", {})
if mode == "laptop":
    cfg["mode"] = "local"
    cfg.setdefault("local", {})["inline"] = True
    cfg["local"]["monitor_only"] = not enforce
    resp["dry_run"] = not enforce
    # A laptop is WiFi more often than not, so the queue rule would sit on the
    # same physical link the operator needs to look up a fix. Fail open unless
    # they asked for enforcement explicitly.
    if not enforce:
        cfg["local"]["inline"] = False
else:
    cfg["mode"] = "inline"
    resp["dry_run"] = not enforce
    cfg.setdefault("local", {})["monitor_only"] = not enforce
    br = cfg.setdefault("bridge", {})
    br.setdefault("interfaces", {})
    if wan: br["interfaces"]["wan"] = wan
    if lan: br["interfaces"]["lan"] = lan
    br["nfqueue_num"] = br.get("nfqueue_num", 0) or 0
with open(path, "w") as f:
    yaml.safe_dump(cfg, f, default_flow_style=False)
print(f"  mode={cfg['mode']} dry_run={cfg['response']['dry_run']} monitor_only={cfg.get('local', {}).get('monitor_only')}")
PY
then
    ok "Configuration written."
else
    echo "[ fail ] mode patch failed (PyYAML missing?) — edit $PREFIX/config/config.yaml by hand." >&2
    exit 1
fi

# ----- closing brief -----
if [ "$MODE" = "laptop" ]; then
    cat <<EOF

${GREEN}LIDRA laptop shield installed.${NC}
$([ "$ENFORCE" = "enforce" ] && echo "  Enforcement ON: attacks are dropped before your apps." || echo "  Monitor-only: attacks are detected and logged, nothing dropped yet,
  and no kernel queue rule is installed (so your network cannot break
  because of LIDRA). To enforce: set local.inline: true and
  local.monitor_only: false + response.dry_run: false
  in $PREFIX/config/config.yaml, then: systemctl restart lidra")
EOF
else
    cat <<EOF

${GREEN}LIDRA gateway installed — wire it AFTER the firewall, BEFORE the servers:${NC}
  [Internet] -> [Firewall] -> [THIS box: ${WAN:-wan} <-> ${LAN:-lan}] -> [Servers]
$([ "$ENFORCE" = "enforce" ] && echo "  Enforcement ON." || echo "  Monitor-first: Tune in this mode, then set response.dry_run: false
  + local.monitor_only: false in $PREFIX/config/config.yaml.")
  Know before you rack it:
  - Throughput per box: ~500-600 pps per core (measured). Size accordingly;
    the XDP fast path (optional build) raises the ceiling.
  - Fail-closed: if this box dies, the segment goes dark. For HA use a
    bypass NIC or a redundant pair. Under LOAD it fails open (--queue-bypass).
  - Invisible at L2: no IP on the bridge path; manage the box via the
    management_ip on br_lidra or a separate MGMT NIC.
EOF
fi
