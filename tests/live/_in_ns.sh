#!/usr/bin/env bash
# Stage 2 live matrix — real packets through LIDRA's real capture path.
#
# TOPOLOGY (this took several wrong attempts; the traps are documented because
# they are the reason the naive version silently proves nothing):
#
#   outer namespace (uid 0, mapped)          sibling namespace
#   ┌──────────────────────────┐             ┌──────────────────┐
#   │ lidra0  10.88.0.1/24     │◄────veth───►│ atk0  10.88.0.66 │
#   │ LIDRA captures HERE      │             │ attacker runs    │
#   └──────────────────────────┘             └──────────────────┘
#
# The attack is aimed AT lidra0, so LIDRA sees genuine kernel-delivered frames
# arriving on a real interface from a different source IP. That is the T1-T6
# design from the plan ("the spare only sees attacks aimed at itself — it is the
# target").
#
# TRAPS (each measured, each cost a cycle):
#   * BOTH ends in ONE netns -> the kernel short-circuits same-subnet traffic,
#     ARP is never answered, `ping` gives 100% loss and the capture port sees
#     only ARP requests. Useless.
#   * `ip netns add` -> refused unprivileged; it writes /run/netns, owned by
#     real root, not the mapped user.
#   * nested `unshare --user` in the child -> the child gets a NEW user ns with
#     caps only inside itself, so `ip link set X netns PID` fails ("Invalid
#     netns value" is how that surfaces).
#   * The child must unshare ONLY `--net`, sharing the parent's user namespace.
#     Then both net namespaces are owned by the same user ns and the move works.
set -uo pipefail

REPO="${LIDRA_REPO:-/path/to/LIDRA}"
PY="$REPO/.venv/bin/python"

LIDRA_IP=10.88.0.1
ATK_IP=10.88.0.66
IFACE=lidra0
ROOT=/tmp/lidra_live
ATK_PID=

cleanup() {
  [ -n "${AGENT_PID:-}" ] && kill "$AGENT_PID" 2>/dev/null
  [ -n "${ATK_PID:-}" ] && kill "$ATK_PID" 2>/dev/null
  pkill -f "src.lidra_agent_v3" 2>/dev/null
  mkdir -p "$ROOT"; : > "$ROOT/atk.stop"
}
trap cleanup EXIT

# The attacker namespace exits as soon as $ROOT/atk.stop exists, and cleanup
# leaves that file behind for the NEXT process to find — every case shares
# /tmp/lidra_live and matrix.sh runs each case as a separate process. Left
# alone, a new case's attacker namespace saw the stale flag and quit within
# 0.2 s, so the precheck's ping failed and the case reported
# "capture-precheck" — a harness artifact, not a detector failure.
rm -f "$ROOT/atk.stop"

# ── topology ───────────────────────────────────────────────────────────────

setup_net() {
  # Clean none of $ROOT here: write_config owns it, and must run FIRST. Wiping
  # it here (or arming a flag write_config later deletes) was a real bug — the
  # flag vanished and every capture precheck failed with a misleading message.
  ip link add "$IFACE" type veth peer name atk0 || return 1
  ip addr add "$LIDRA_IP/24" dev "$IFACE"
  ip link set "$IFACE" up
  ip link set lo up
  # Sibling network namespace for the attacker — shares OUR user namespace, so
  # we keep CAP_NET_ADMIN over both and can hand atk0 across. It must unshare
  # ONLY --net: a nested --user would give the child caps in its own user ns
  # only, and the move below would fail with "Invalid netns value".
  #
  # Use the PARENT-visible PID ($!), not the child's own $$ — with an outer
  # --pid --fork the child's $$ is a PID inside that namespace and the kernel
  # rejects it ("Invalid netns value"). That mistake cost a full cycle.
  #
  # The child signals readiness by creating atk.up, and ONLY after verifying
  # that atk0 really exists and carries the address.
  #
  # ORDERING (the real bug this fixes). `unshare --net ... &` forks and returns
  # immediately, but the CHILD HAS NOT ENTERED ITS NAMESPACE YET — unshare(2)
  # runs inside the child. The parent then reads /proc/$ATK_PID/ns/net, and if
  # the child has not got there yet that path still names the PARENT's
  # namespace, so `ip link set atk0 netns $ATK_PID` is a no-op: atk0 "moves" to
  # where it already was. The child then enters a fresh empty namespace and
  # atk0 never appears. Observed as the attacker ns showing only `lo`, with the
  # case failing "capture-precheck" — intermittently, a different case each run,
  # because it is a pure race.
  #
  # Fix: the child writes ns.ready as its FIRST action, after unshare has
  # happened. The parent waits for that file before touching atk0.
  rm -f "$ROOT/atk.up" "$ROOT/ns.ready"
  unshare --net bash -c '
    : > '"$ROOT"'/ns.ready
    ip link set lo up 2>/dev/null
    ok=0
    for _ in $(seq 1 150); do
      if ip link show atk0 >/dev/null 2>&1; then
        ip addr add '"$ATK_IP"'/24 dev atk0 2>/dev/null
        ip link set atk0 up 2>/dev/null
        if ip -4 addr show dev atk0 2>/dev/null | grep -q '"$ATK_IP"'; then
          ok=1; break
        fi
      fi
      sleep 0.1
    done
    if [ "$ok" = "1" ]; then : > '"$ROOT"'/atk.up; fi
    while [ ! -f '"$ROOT"'/atk.stop ]; do sleep 0.2; done
  ' &
  ATK_PID=$!
  [ -n "$ATK_PID" ] || { echo "  !! attacker ns did not start"; return 1; }

  # Wait until the child is genuinely inside its new network namespace before
  # handing atk0 over; otherwise the move lands in the wrong place.
  local i
  for i in $(seq 1 100); do [ -f "$ROOT/ns.ready" ] && break; sleep 0.1; done
  if [ ! -f "$ROOT/ns.ready" ]; then
    echo "  !! attacker ns never signalled readiness"; return 1
  fi
  # The child's namespace must now DIFFER from ours, or the move is pointless.
  if [ "$(readlink /proc/$ATK_PID/ns/net)" = "$(readlink /proc/self/ns/net)" ]; then
    echo "  !! attacker ns shares ours — atk0 would not cross a namespace"
    return 1
  fi

  ip link set atk0 netns "$ATK_PID" || { echo "  !! could not move atk0 to ns $ATK_PID"; return 1; }
  # Verify readiness instead of assuming it: this used to wait for atk.up and
  # then `return 0` unconditionally, so a failed setup was reported as success.
  for i in $(seq 1 100); do [ -f "$ROOT/atk.up" ] && break; sleep 0.1; done
  if [ ! -f "$ROOT/atk.up" ]; then
    echo "  !! attacker ns never configured atk0 ($ATK_IP)"
    echo "     atk ns: $(in_atk ip -br addr 2>&1 | tr '\n' ' ')"
    return 1
  fi
  sleep 0.5   # let the interface settle before the first ping
  return 0
}

# Run a command inside the attacker namespace.
in_atk() {
  nsenter --net="/proc/$ATK_PID/ns/net" "$@" 2>/dev/null
}

# ── agent under test ────────────────────────────────────────────────────────

write_config() {
  # NOTE: this wipes $ROOT, and setup_net used $ROOT for its handshake flag.
  # Recreate the handshake file's directory and re-arm the flag so a later
  # `[ -f "$ROOT/atk.up" ]` check cannot be silently false — that ordering bug
  # made T7 report "attacker cannot reach the sensor" when the topology was fine.
  rm -rf "$ROOT"; mkdir -p "$ROOT/config" "$ROOT/data" "$ROOT/logs" "$ROOT/state"
  "$PY" - "$REPO/config/config.yaml" "$ROOT/config/config.yaml" "$IFACE" <<'PYEOF'
import sys, yaml
src, dst, iface = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = yaml.safe_load(open(src))
cfg["mode"] = "local"
cfg.setdefault("local", {})
cfg["local"]["interface"] = iface
cfg["local"]["inline"] = False        # monitor only: never arm a kernel queue rule
cfg.setdefault("response", {})["dry_run"] = True   # never write real rules
cfg.setdefault("tui", {})["enabled"] = False
cfg.setdefault("collectors", {}).setdefault("network", {})["interface"] = iface
cfg.setdefault("general", {})["verbose"] = False
yaml.safe_dump(cfg, open(dst, "w"), sort_keys=False)
PYEOF
}

start_agent() {
  cd "$REPO" || return 1
  LIDRA_ROOT="$ROOT" LIDRA_INTERFACE="$IFACE" LIDRA_DRY_RUN=1 \
    "$PY" -m src.lidra_agent_v3 --interface "$IFACE" --no-tui \
    >"$ROOT/agent.log" 2>&1 &
  AGENT_PID=$!
  # Wait for the DB, then for the capture socket to actually bind — polling both
  # rather than sleeping a fixed amount. A fixed `sleep 4` made t7_ja4 fail
  # intermittently inside `matrix.sh all` (it passed alone): under sequential
  # load the agent takes longer to bind, verify_capture greps once, and the case
  # reports "capture-precheck" — a harness timing flake wearing the costume of a
  # detector failure. Same lesson as the precheck itself: never assert a negative
  # on a deadline you guessed.
  local _
  for _ in $(seq 1 120); do
    [ -f "$ROOT/data/lidra.db" ] && break
    sleep 0.5
  done
  [ -f "$ROOT/data/lidra.db" ] || {
    echo "  !! agent did not start"; tail -15 "$ROOT/agent.log"; return 1; }

  for _ in $(seq 1 60); do
    grep -q "Bound raw socket to $IFACE" "$ROOT/agent.log" && return 0
    kill -0 "$AGENT_PID" 2>/dev/null || {
      echo "  !! agent exited before binding"; tail -15 "$ROOT/agent.log"; return 1; }
    sleep 0.5
  done
  echo "  !! agent never bound $IFACE within 30s"; tail -15 "$ROOT/agent.log"; return 1
}

stop_agent() {
  [ -n "${AGENT_PID:-}" ] && kill "$AGENT_PID" 2>/dev/null
  wait "$AGENT_PID" 2>/dev/null
  pkill -f "src.lidra_agent_v3" 2>/dev/null
}

verify_capture() {
  # Prove the socket works before claiming a negative result. A test that cannot
  # see traffic reports "no detection" identically to a detector that is broken.
  local n
  n=$(in_atk ping -c 3 -W 2 "$LIDRA_IP" | grep -c "bytes from")
  if [ "${n:-0}" -lt 1 ]; then
    echo "  !! attacker cannot reach $LIDRA_IP — capture cannot be tested"
    echo "     atk ns: $(in_atk ip -br addr 2>&1 | tr '\n' ' ')"
    echo "     pid=$ATK_PID alive=$(kill -0 "$ATK_PID" 2>/dev/null && echo yes || echo no)"
    return 1
  fi
  # Retry the bind check rather than grepping once: agent startup time varies
  # with system load, and a single grep turns that variance into a spurious
  # "capture-precheck" failure. start_agent already waits for the bind, so this
  # is a second, shorter grace period.
  local i
  for i in $(seq 1 20); do
    grep -q "Bound raw socket to $IFACE" "$ROOT/agent.log" && return 0
    sleep 0.5
  done
  echo "  !! agent did not bind $IFACE"; tail -5 "$ROOT/agent.log"; return 1
}

# ── db readers ──────────────────────────────────────────────────────────────

db_count() {  # db_count <attack_type_like> [source_ip]
  "$PY" - "$ROOT/data/lidra.db" "$1" "${2:-}" <<'PYEOF'
import sqlite3, sys
db, atype = sys.argv[1], sys.argv[2]
src = sys.argv[3] if len(sys.argv) > 3 else ""
try:
    c = sqlite3.connect(db)
    if src:
        q = ("SELECT COUNT(*) FROM attacks a JOIN attackers t ON a.attacker_id=t.id "
             "WHERE a.attack_type LIKE ? AND t.ip_address = ?")
        print(c.execute(q, (f"%{atype}%", src)).fetchone()[0])
    else:
        print(c.execute("SELECT COUNT(*) FROM attacks WHERE attack_type LIKE ?",
                        (f"%{atype}%",)).fetchone()[0])
except Exception:
    print(0)
PYEOF
}

db_types() {
  "$PY" - "$ROOT/data/lidra.db" <<'PYEOF'
import sqlite3, sys
try:
    c = sqlite3.connect(sys.argv[1])
    rows = c.execute("SELECT attack_type, COUNT(*) FROM attacks "
                     "GROUP BY 1 ORDER BY 2 DESC").fetchall()
    print(", ".join(f"{a}:{n}" for a, n in rows) or "(none)")
except Exception as e:
    print(f"(error: {e})")
PYEOF
}

report() {
  local case="$1" verdict="$2"; shift 2
  echo "  recorded: $(db_types)"
  echo "RESULT: $verdict $case $*"
  [ "$verdict" = PASS ]
}

# Serve a one-shot TCP listener on the sensor so attacks have a target that
# answers (a completed request is what the DPI path needs).
#
# Writes the PID to a file rather than echoing it: `echo $!` also captured the
# listener's stdout ("BOUND ok"), so the caller's PID variable was mult-line
# garbage and the port never stayed up — which surfaced as "no JA4 detection"
# for a fixture that was actually fine.
# NOTE: do NOT call this as `X=$(serve_tcp ...)`. Command substitution holds the
# listener's stdout open and therefore blocks until the listener *exits* (its
# full lifetime), so the attack ran after the port had closed — which cost a
# cycle chasing "connection refused". Call it plainly and read $ROOT/listener.pid.
serve_tcp() {  # serve_tcp <port> <seconds>  -> sets LISTENER_PID
  local port="$1" secs="$2" pidfile="$ROOT/listener.pid"
  rm -f "$pidfile"
  "$PY" - "$LIDRA_IP" "$port" "$secs" "$pidfile" <<'PYEOF' &
import os, socket, sys, threading, time
ip, port, secs, pidfile = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((ip, port)); s.listen(16)
open(pidfile, "w").write(str(os.getpid()))
def loop():
    end = time.time() + secs
    while time.time() < end:
        try:
            s.settimeout(0.5); c, _ = s.accept()
            try: c.settimeout(0.2); c.recv(2048)
            except Exception: pass
            c.close()
        except Exception: pass
threading.Thread(target=loop, daemon=True).start()
time.sleep(secs)
PYEOF
  for _ in $(seq 1 30); do [ -s "$pidfile" ] && break; sleep 0.1; done
  sleep 0.5
  LISTENER_PID=$(cat "$pidfile" 2>/dev/null)
}

# ── cases ───────────────────────────────────────────────────────────────────

#CASE:t1_portscan  nmap -sS aimed at the sensor -> port_scan/port_hopping/syn_burst
case_t1_portscan() {
  write_config && setup_net && start_agent || { echo "RESULT: FAIL t1_portscan setup"; return 1; }
  verify_capture || { echo "RESULT: FAIL t1_portscan capture-precheck"; return 1; }
  in_atk nmap -sS -Pn -p 1-200 --min-rate 400 "$LIDRA_IP" >/dev/null 2>&1
  sleep 8; stop_agent
  local a b c
  a=$(db_count port_scan "$ATK_IP")
  b=$(db_count port_hopping "$ATK_IP")
  c=$(db_count syn_burst "$ATK_IP")
  [ $((a + b + c)) -gt 0 ] && report t1_portscan PASS "(port_scan=$a port_hopping=$b syn_burst=$c)" \
                           || report t1_portscan FAIL "no port-scan detection from $ATK_IP"
}

#CASE:t2_synflood  hping3 SYN flood -> syn_flood/syn_burst
case_t2_synflood() {
  write_config && setup_net && start_agent || { echo "RESULT: FAIL t2_synflood setup"; return 1; }
  verify_capture || { echo "RESULT: FAIL t2_synflood capture-precheck"; return 1; }
  in_atk timeout 8 hping3 --flood -S -p 80 "$LIDRA_IP" >/dev/null 2>&1
  sleep 8; stop_agent
  local a b
  a=$(db_count syn_flood "$ATK_IP")
  b=$(db_count syn_burst "$ATK_IP")
  [ $((a + b)) -gt 0 ] && report t2_synflood PASS "(syn_flood=$a syn_burst=$b)" \
                       || report t2_synflood FAIL "no SYN detection from $ATK_IP"
}

#CASE:t3_web  SQLi/XSS/CMDi/traversal at a local web server
case_t3_web() {
  write_config && setup_net || { echo "RESULT: FAIL t3_web setup"; return 1; }
  "$PY" - "$LIDRA_IP" 8080 <<'PYEOF' &
import http.server, socketserver, sys, threading, time
ip, port = sys.argv[1], int(sys.argv[2])
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
threading.Thread(target=S((ip, port), H).serve_forever, daemon=True).start()
time.sleep(50)
PYEOF
  WEB_PID=$!
  sleep 2
  start_agent || { echo "RESULT: FAIL t3_web setup"; kill $WEB_PID 2>/dev/null; return 1; }
  verify_capture || { echo "RESULT: FAIL t3_web capture-precheck"; kill $WEB_PID 2>/dev/null; return 1; }
  in_atk bash -c '
    for p in "id=1+UNION+SELECT+user,pass+FROM+users--" \
             "q=<script>alert(1)</script>" \
             "cmd=;cat+/etc/passwd" \
             "f=../../etc/passwd"; do
      curl -s -o /dev/null "http://'"$LIDRA_IP"':8080/?$p"
      curl -s -o /dev/null "http://'"$LIDRA_IP"':8080/$p"
    done
  ' >/dev/null 2>&1
  sleep 8; stop_agent; kill $WEB_PID 2>/dev/null
  local s x c
  s=$(db_count sql_injection "$ATK_IP")
  x=$(db_count xss "$ATK_IP")
  c=$(db_count command_injection "$ATK_IP")
  [ $((s + x + c)) -gt 0 ] && report t3_web PASS "(sql=$s xss=$x cmd=$c)" \
                           || report t3_web FAIL "no web-attack detection from $ATK_IP"
}

#CASE:t5_dns  benign DNS to a local resolver -> must stay quiet (no tunnel FP)
case_t5_dns() {
  write_config && setup_net || { echo "RESULT: FAIL t5_dns setup"; return 1; }
  "$PY" - "$LIDRA_IP" 53 <<'PYEOF' &
import socket, sys, threading, time
ip, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((ip, port))
def loop():
    end = time.time() + 45
    while time.time() < end:
        try:
            s.settimeout(0.5); data, peer = s.recvfrom(512)
            resp = data[:2] + b"\x81\x80" + data[4:6] + b"\x00\x01\x00\x00\x00\x00" + data[12:]
            s.sendto(resp, peer)
        except Exception: pass
threading.Thread(target=loop, daemon=True).start()
time.sleep(45)
PYEOF
  DNS_PID=$!
  sleep 2
  start_agent || { echo "RESULT: FAIL t5_dns setup"; kill $DNS_PID 2>/dev/null; return 1; }
  verify_capture || { echo "RESULT: FAIL t5_dns capture-precheck"; kill $DNS_PID 2>/dev/null; return 1; }
  "$PY" - "$LIDRA_IP" "$ATK_PID" <<'PYEOF'
import subprocess, sys
tgt, atkpid = sys.argv[1], sys.argv[2]
code = f'''
import socket, struct, time, random
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
for i in range(40):
    tid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for part in ("host%d" % i, "example", "com"):
        q += bytes([len(part)]) + part.encode()
    q += b"\\x00" + struct.pack(">HH", 1, 1)
    try: s.sendto(q, ("{tgt}", 53))
    except Exception: pass
    time.sleep(0.05)
'''
subprocess.run(["nsenter", f"--net=/proc/{atkpid}/ns/net", "python3", "-c", code])
PYEOF
  sleep 6; stop_agent; kill $DNS_PID 2>/dev/null
  local n sc
  n=$(db_count dns_tunnel "$ATK_IP")
  sc=$(db_count session_correlated "$ATK_IP")
  if [ "$n" -eq 0 ] && [ "$sc" -eq 0 ]; then
    report t5_dns PASS "(benign DNS quiet on the real port-53 path)"
  else
    report t5_dns FAIL "benign DNS raised dns_tunnel=$n session_correlated=$sc"
  fi
}

#CASE:t7_ja4  known-bad JA4 ClientHello -> malicious_tls_fingerprint
case_t7_ja4() {
  write_config && setup_net || { echo "RESULT: FAIL t7_ja4 setup"; return 1; }
  "$PY" - "$ROOT/config/config.yaml" "$REPO" <<'PYEOF'
import sys, yaml, struct
cfg_path, repo = sys.argv[1], sys.argv[2]
sys.path.insert(0, repo + "/src")
from detection.fingerprint.tls_fingerprinter import parse_tls_client_hello
def hello(ciphers, exts, version=0x0303):
    body = struct.pack(">H", version) + b"\x00"*32 + b"\x00"
    body += struct.pack(">H", len(ciphers)*2)
    for c in ciphers: body += struct.pack(">H", c)
    body += b"\x01\x00"
    blob = b"".join(struct.pack(">HH", t, len(d)) + d for t, d in exts)
    body += struct.pack(">H", len(blob)) + blob
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
ja4 = parse_tls_client_hello(
    hello([0x1301], [(0x0B, b"\x01\x00"), (0x2B, b"\x03\x04\x03\x04")]))["ja4"]
cfg = yaml.safe_load(open(cfg_path))
cfg.setdefault("tls_fingerprints", {})["malicious_ja4"] = [ja4]
yaml.safe_dump(cfg, open(cfg_path, "w"), sort_keys=False)
print("  fixture ja4:", ja4)
PYEOF
  serve_tcp 443 45; TLS_PID=$LISTENER_PID
  sleep 2
  start_agent || { echo "RESULT: FAIL t7_ja4 setup"; kill $TLS_PID 2>/dev/null; return 1; }
  verify_capture || { echo "RESULT: FAIL t7_ja4 capture-precheck"; kill $TLS_PID 2>/dev/null; return 1; }
  "$PY" - "$LIDRA_IP" "$ATK_PID" <<'PYEOF'
import subprocess, sys
tgt, atkpid = sys.argv[1], sys.argv[2]
code = f'''
import socket, struct, time
def hello(ciphers, exts, version=0x0303):
    body = struct.pack(">H", version) + b"\\x00"*32 + b"\\x00"
    body += struct.pack(">H", len(ciphers)*2)
    for c in ciphers: body += struct.pack(">H", c)
    body += b"\\x01\\x00"
    blob = b"".join(struct.pack(">HH", t, len(d)) + d for t, d in exts)
    body += struct.pack(">H", len(blob)) + blob
    hs = b"\\x01" + len(body).to_bytes(3, "big") + body
    return b"\\x16\\x03\\x01" + len(hs).to_bytes(2, "big") + hs
pkt = hello([0x1301], [(0x0B, b"\\x01\\x00"), (0x2B, b"\\x03\\x04\\x03\\x04")])
for _ in range(4):
    try:
        s = socket.socket(); s.settimeout(2); s.connect(("{tgt}", 443))
        s.send(pkt); time.sleep(0.3); s.close()
    except Exception as e: print("client:", e)
    time.sleep(0.4)
'''
subprocess.run(["nsenter", f"--net=/proc/{atkpid}/ns/net", "python3", "-c", code])
PYEOF
  sleep 8; stop_agent; kill $TLS_PID 2>/dev/null
  local m
  m=$(db_count tls_fingerprint "$ATK_IP")
  [ "$m" -gt 0 ] && report t7_ja4 PASS "(tls_fingerprint=$m)" \
                 || report t7_ja4 FAIL "no JA4 detection from $ATK_IP"
}

#CASE:t6_beacon  steady beaconing -> gate must not duplicate alerts
case_t6_beacon() {
  write_config && setup_net || { echo "RESULT: FAIL t6_beacon setup"; return 1; }
  serve_tcp 4444 45; SRV_PID=$LISTENER_PID
  sleep 2
  start_agent || { echo "RESULT: FAIL t6_beacon setup"; kill $SRV_PID 2>/dev/null; return 1; }
  verify_capture || { echo "RESULT: FAIL t6_beacon capture-precheck"; kill $SRV_PID 2>/dev/null; return 1; }
  "$PY" - "$LIDRA_IP" "$ATK_PID" <<'PYEOF'
import subprocess, sys
tgt, atkpid = sys.argv[1], sys.argv[2]
code = f'''
import socket, time
for i in range(12):
    try:
        s = socket.socket(); s.settimeout(1); s.connect(("{tgt}", 4444)); s.close()
    except Exception: pass
    time.sleep(1.5)
'''
subprocess.run(["nsenter", f"--net=/proc/{atkpid}/ns/net", "python3", "-c", code])
PYEOF
  sleep 6; stop_agent; kill $SRV_PID 2>/dev/null
  local total
  total=$("$PY" - "$ROOT/data/lidra.db" <<'PYEOF'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
rows = c.execute("SELECT attack_type, COUNT(*) FROM attacks GROUP BY 1").fetchall()
print(sum(n for _, n in rows))
PYEOF
)
  # 12 beacons must not become hundreds of rows.
  [ "${total:-0}" -le 30 ] && report t6_beacon PASS "(total attack rows=$total, no storm)" \
                           || report t6_beacon FAIL "alert storm: $total rows for 12 beacons"
}

#CASE:f4_ownip  blocking the sensor's own address must be refused
case_f4_ownip() {
  write_config && setup_net || { echo "RESULT: FAIL f4_ownip setup"; return 1; }
  cd "$REPO" || return 1
  out=$(LIDRA_ROOT="$ROOT" LIDRA_DRY_RUN=1 "$PY" -m src.cli.main block "$LIDRA_IP" 2>&1 | grep -v RuntimeWarning)
  echo "  cli: $(echo "$out" | head -2 | tr '\n' ' ')"
  if echo "$out" | grep -qi "refus"; then report f4_ownip PASS "(refused own address)"
  else report f4_ownip FAIL "did not refuse $LIDRA_IP"; fi
}

#CASE:f1_block  dry-run block writes no kernel rule
case_f1_block() {
  write_config && setup_net || { echo "RESULT: FAIL f1_block setup"; return 1; }
  cd "$REPO" || return 1
  out=$(LIDRA_ROOT="$ROOT" LIDRA_DRY_RUN=1 "$PY" -m src.cli.main block 203.0.113.9 2>&1 | grep -v RuntimeWarning)
  echo "  cli: $(echo "$out" | head -1)"
  rules=$(iptables -S 2>/dev/null | grep -c "203.0.113.9")
  if echo "$out" | grep -qi "DRY-RUN\|would block" && [ "${rules:-0}" -eq 0 ]; then
    report f1_block PASS "(dry-run reported, no kernel rule)"
  else report f1_block FAIL "unexpected (rules=$rules)"; fi
}

#CASE:s7_restarts  two rapid starts leave no queue rules
case_s7_restarts() {
  write_config && setup_net || { echo "RESULT: FAIL s7_restarts setup"; return 1; }
  start_agent || { echo "RESULT: FAIL s7_restarts start1"; return 1; }
  stop_agent; sleep 2
  start_agent || { echo "RESULT: FAIL s7_restarts start2"; return 1; }
  stop_agent
  local n
  n=$(iptables -S 2>/dev/null | grep -c NFQUEUE)
  [ "${n:-0}" -eq 0 ] && report s7_restarts PASS "(monitor mode: no queue rules left)" \
                      || report s7_restarts FAIL "$n NFQUEUE rule(s) left"
}

#CASE:s8_diskfull  survives an unwritable data dir with the DB intact
case_s8_diskfull() {
  write_config && setup_net || { echo "RESULT: FAIL s8_diskfull setup"; return 1; }
  start_agent || { echo "RESULT: FAIL s8_diskfull start"; return 1; }
  chmod 500 "$ROOT/data"
  in_atk nmap -sS -Pn -p 1-80 --min-rate 200 "$LIDRA_IP" >/dev/null 2>&1
  sleep 6
  local alive=0
  kill -0 "$AGENT_PID" 2>/dev/null && alive=1
  chmod 700 "$ROOT/data"
  stop_agent
  local integrity
  integrity=$("$PY" - "$ROOT/data/lidra.db" <<'PYEOF'
import sqlite3, sys
try:
    c = sqlite3.connect(sys.argv[1])
    print(c.execute("PRAGMA integrity_check").fetchone()[0])
except Exception as e: print(f"corrupt: {e}")
PYEOF
)
  if [ "$alive" -eq 1 ] && [ "$integrity" = ok ]; then
    report s8_diskfull PASS "(survived unwritable data dir, DB intact)"
  else report s8_diskfull FAIL "alive=$alive integrity=$integrity"; fi
}

echo "--- ns driver: case=$1 ---"
"case_$1" 2>&1