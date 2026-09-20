#!/usr/bin/env bash
# LIDRA uninstaller — mirrors install/post_install.sh, in reverse.
#
#   sudo ./install/uninstall.sh                  # interactive (asks before deleting data)
#   sudo ./install/uninstall.sh --prefix /path   # custom install root
#   sudo ./install/uninstall.sh --purge          # also delete data/, state/, /var/log/lidra
#   sudo ./install/uninstall.sh --yes            # non-interactive; keeps data
#   sudo ./install/uninstall.sh --yes --purge    # non-interactive; removes everything
#
# Behaviour:
#   1. Stop + disable the lidra service, verify it is actually dead.
#   2. Remove the systemd unit, the sleep hook, the logrotate file.
#   3. Flush every LIDRA firewall artifact (nft lidra_* tables, iptables LIDRA_* chains,
#      orphaned NFQUEUE rules) — and fail LOUDLY if any cannot be removed, because an
#      orphaned queue rule without a consumer is the connectivity outage this project
#      fixed once already (see docs/SAFE_LINK.md).
#   4. Keep the database by default (it is the operator's evidence). --purge removes it
#      after an explicit confirmation unless --yes is also given.
#
# Idempotent: safe to run twice. Every step reports what it did or skipped.

set -euo pipefail

PREFIX="${LIDRA_PREFIX:-/opt/lidra}"
PURGE=false
YES=false

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { printf "${BLUE}[lidra-uninstall]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[  ok  ]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[ warn ]${NC} %s\n" "$*" >&2; }
err()  { printf "${RED}[ fail ]${NC} %s\n" "$*" >&2; }
skip() { printf "  [skip] %s\n" "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift ;;
        --purge)  PURGE=true ;;
        --yes|-y) YES=true ;;
        --help|-h)
            sed -n '2,20p' "$0" | sed 's/^# //; s/^#//'
            exit 0 ;;
        *) err "Unknown flag: $1"; exit 1 ;;
    esac
    shift
done

[ "$(id -u)" -eq 0 ] || { err "Must be run as root (systemd units, firewall rules)."; exit 1; }

FAILURES=0
fail() { err "$*"; FAILURES=$((FAILURES + 1)); }

confirm() {
    # confirm <prompt> ; returns 0 on yes. --yes answers yes to everything.
    if [ "$YES" = true ]; then return 0; fi
    if [ ! -t 0 ]; then return 1; fi
    printf "%s [y/N]: " "$1"
    read -r ans || return 1
    case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# ----- 1. service -----------------------------------------------------------
log "Stopping lidra service..."
if systemctl is-active --quiet lidra 2>/dev/null; then
    systemctl stop lidra || fail "systemctl stop lidra failed"
fi
if systemctl is-enabled --quiet lidra 2>/dev/null; then
    systemctl disable lidra >/dev/null 2>&1 || fail "systemctl disable lidra failed"
fi
if pgrep -f lidra_agent_v3 >/dev/null 2>&1; then
    warn "agent processes still alive after stop; killing"
    pkill -9 -f lidra_agent_v3 2>/dev/null || true
    sleep 2
fi
if pgrep -f lidra_agent_v3 >/dev/null 2>&1; then
    fail "agent processes survived SIGKILL — inspect manually before rebooting"
else
    ok "Service stopped and disabled."
fi

# ----- 2. unit files --------------------------------------------------------
for f in /etc/systemd/system/lidra.service \
         /usr/lib/systemd/system-sleep/lidra \
         /etc/systemd/system-sleep/lidra \
         /etc/logrotate.d/lidra; do
    if [ -e "$f" ]; then
        rm -f "$f" && ok "Removed $f" || fail "Could not remove $f"
    else
        skip "$f not present"
    fi
done
if [ -d /etc/systemd/system ]; then
    systemctl daemon-reload || fail "systemctl daemon-reload failed"
fi

# ----- 3. firewall artifacts — fail LOUD if any remain ----------------------
log "Removing LIDRA firewall rules (this restores direct network access)..."

# nftables: delete every lidra_* table in both families we use
if command -v nft >/dev/null 2>&1; then
    for family in inet bridge; do
        for table in lidra_nfqueue lidra_bridge; do
            if nft list table "$family" "$table" >/dev/null 2>&1; then
                nft delete table "$family" "$table" \
                    && ok "Removed nft table $family $table" \
                    || fail "Could not delete nft table $family $table — connectivity may be affected"
            fi
        done
    done
    if nft list tables 2>/dev/null | grep -qi lidra; then
        fail "lidra_* nftables tables still present after cleanup:"
        nft list tables 2>/dev/null | grep -i lidra | sed 's/^/  /' >&2
    else
        ok "No lidra_* nftables tables remain."
    fi
else
    skip "nft not installed"
fi

# iptables (covers iptables-legacy and iptables-nft): flush our chains + rules
if command -v iptables >/dev/null 2>&1; then
    for chain in LIDRA_BLOCK LIDRA; do
        for builtin in INPUT FORWARD OUTPUT; do
            iptables -D "$builtin" -j "$chain" >/dev/null 2>&1 || true
        done
        iptables -F "$chain" >/dev/null 2>&1 || true
        iptables -X "$chain" >/dev/null 2>&1 || true
    done
    # NFQUEUE rules. LIDRA tags its own with `lidra_nfqueue`, so remove exactly
    # those. A pre-tag release left an untagged rule whose only handle is the
    # queue number; that case gets one explicit confirmation and nothing more.
    # Rules LIDRA cannot claim are NEVER deleted — breaking another tool's queue
    # is not ours to decide, and an orphaned queue rule without a consumer is
    # the connectivity outage this project already fixed once (docs/SAFE_LINK.md).
    LIDRA_QUEUE_NUM="$(grep -E '^[[:space:]]*nfqueue_num:' "$PREFIX/config/config.yaml" 2>/dev/null \
        | head -1 | sed 's/[^0-9]*\([0-9][0-9]*\).*/\1/')"
    [ -n "$LIDRA_QUEUE_NUM" ] || LIDRA_QUEUE_NUM=0

    if iptables -S INPUT 2>/dev/null | grep -qF -- "lidra_nfqueue"; then
        removed=0
        while iptables -S INPUT 2>/dev/null | grep -qF -- "lidra_nfqueue"; do
            rule=$(iptables -S INPUT 2>/dev/null | grep -F -- "lidra_nfqueue" | head -1 | sed 's/^-A INPUT/-D INPUT/')
            # shellcheck disable=SC2086
            iptables $rule >/dev/null 2>&1 || break
            removed=$((removed + 1))
        done
        ok "Removed $removed LIDRA-tagged NFQUEUE rule(s)."
    elif iptables -S INPUT 2>/dev/null | grep -q -- "--queue-num ${LIDRA_QUEUE_NUM}\b"; then
        warn "Untagged NFQUEUE rule(s) on LIDRA's configured queue ($LIDRA_QUEUE_NUM) — pre-tag install:"
        iptables -S INPUT 2>/dev/null | grep "NFQUEUE" | sed 's/^/  /' >&2
        if confirm "Delete the untagged NFQUEUE rule(s) on queue $LIDRA_QUEUE_NUM?"; then
            while iptables -S INPUT 2>/dev/null | grep -q -- "--queue-num ${LIDRA_QUEUE_NUM}\b"; do
                rule=$(iptables -S INPUT 2>/dev/null | grep -- "--queue-num ${LIDRA_QUEUE_NUM}\b" | head -1 | sed 's/^-A INPUT/-D INPUT/')
                # shellcheck disable=SC2086
                iptables $rule >/dev/null 2>&1 || break
            done
            ok "Removed NFQUEUE rule(s) on queue $LIDRA_QUEUE_NUM."
        else
            warn "Left in place at your request. They carry --queue-bypass, so traffic still flows."
        fi
    else
        ok "No LIDRA NFQUEUE rules."
    fi

    # Whatever is still queued is not ours. Report it; do not touch it.
    if iptables -S INPUT 2>/dev/null | grep -q "NFQUEUE"; then
        warn "NFQUEUE rule(s) in INPUT that LIDRA does not own (left untouched):"
        iptables -S INPUT 2>/dev/null | grep "NFQUEUE" | sed 's/^/  /' >&2
    fi
else
    skip "iptables not installed"
fi

# ----- 4. files -------------------------------------------------------------
if [ -d "$PREFIX" ]; then
    DB="$PREFIX/data/lidra.db"
    if [ "$PURGE" = true ]; then
        if [ -f "$DB" ]; then
            if confirm "Delete the detection database $DB (your evidence history)?"; then
                rm -f "$DB" "$DB-wal" "$DB-shm" && ok "Database deleted."
            else
                cp "$DB" "$DB.uninstall-backup-$(date +%Y%m%d)" && ok "Database kept; copied to $DB.uninstall-backup-*"
            fi
        fi
        rm -rf "$PREFIX" && ok "Removed $PREFIX" || fail "Could not remove $PREFIX"
    else
        BACKUP="$PREFIX.data-keep-$(date +%Y%m%d-%H%M%S)"
        if [ -f "$DB" ]; then
            # Data is the operator's evidence; keep it beside the removed tree.
            cp -a "$PREFIX/data" "$BACKUP" 2>/dev/null && ok "Database preserved at $BACKUP" \
                || warn "Could not preserve $PREFIX/data — inspect before deleting"
        fi
        rm -rf "$PREFIX" && ok "Removed $PREFIX (data kept at ${BACKUP:-<none>})" \
            || fail "Could not remove $PREFIX"
        if [ "$YES" = false ] && [ -t 0 ] && [ -d "$BACKUP" ]; then
            printf "Also delete the preserved data at %s? [y/N]: " "$BACKUP"
            read -r ans || true
            case "$ans" in y|Y|yes|YES) rm -rf "$BACKUP" && ok "Preserved data deleted." ;; esac
        fi
    fi
else
    skip "$PREFIX not present"
fi

if [ -d /var/log/lidra ]; then
    if [ "$PURGE" = true ] || confirm "Delete log directory /var/log/lidra?"; then
        rm -rf /var/log/lidra && ok "Removed /var/log/lidra" || fail "Could not remove /var/log/lidra"
    else
        skip "/var/log/lidra kept"
    fi
else
    skip "/var/log/lidra not present"
fi

# ----- 5. verification ------------------------------------------------------
echo
log "Verifying uninstall..."
fail_total_before=$FAILURES
systemctl status lidra >/dev/null 2>&1 && fail "lidra.service still registered" || ok "No lidra.service"
pgrep -f lidra_agent_v3 >/dev/null 2>&1 && fail "agent processes still running" || ok "No agent processes"
command -v nft >/dev/null 2>&1 && nft list tables 2>/dev/null | grep -qi lidra && fail "lidra nftables tables remain" || ok "No lidra nftables tables"
if command -v iptables >/dev/null 2>&1; then
    if iptables -S INPUT 2>/dev/null | grep -qF -- "lidra_nfqueue"; then
        fail "LIDRA-tagged NFQUEUE rules remain in INPUT"
    else
        ok "No LIDRA NFQUEUE rules"
    fi
fi
[ -d "$PREFIX" ] && fail "$PREFIX still exists" || ok "Install root gone"
test -S /run/lidra/lidra_tui_*.sock 2>/dev/null && fail "IPC sockets remain" || ok "No IPC sockets"

echo
if [ "$FAILURES" -gt 0 ]; then
    err "Uninstall finished with $FAILURES unresolved issue(s) — see [ fail ] lines above."
    exit 1
fi
echo -e "${GREEN}LIDRA uninstalled cleanly.${NC} Your network path is untouched (direct access restored)."
