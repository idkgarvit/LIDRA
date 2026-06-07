# LIDRA — 60-Second Demo

This walkthrough lets you demo LIDRA end-to-end in about a minute.
You'll see three real attack types get detected, the alert panel
populate, the detail panel light up, and (if auto-block is enabled)
the offending IP get dropped at the firewall.

## 0. Pre-flight (10 seconds)

Two terminals. Or one terminal + one tmux pane.

```bash
# Terminal 1: clone the repo + start LIDRA TUI
cd LIDRA
sudo -E python3 -m src.lidra_agent_v3 --tui
```

You should see the TUI dashboard with all green KPIs.
The attackers table should be empty.

```bash
# Terminal 2: start the vuln server (port 8080)
cd LIDRA
./demo/run_all.sh
```

`run_all.sh` starts `vuln_server.py`, runs the SQLi demo, runs
the port scan demo, then exits. Total runtime: ~30 seconds.

## 1. Watch the SQLi demo (0:00 – 0:08)

What `run_sqli_demo.sh` sends:

| # | Payload | URI | Why |
|---|---|---|---|
| 1 | (control) | `GET /` | baseline, should NOT trigger |
| 2 | `' OR '1'='1` | `GET /search?q=...` | boolean SQLi |
| 3 | `1 UNION SELECT username,password FROM users--` | `GET /search?q=...` | UNION-based |
| 4 | `1; WAITFOR DELAY '0:0:5'--` | `GET /search?q=...` | time-based blind |

**What to say:**
> "Three SQL injection payloads. Notice LIDRA caught all three at
> severity=critical, confidence=0.9. The detail panel shows the
> source IP, the URI, and a snippet of the payload."

**What to look for in the TUI:**
- Status bar: `☠ 3 crit` (or `→ critical` if your version doesn't have the dead-skull variant)
- Attackers table: 1 row, severity=critical
- Detail panel: `attack_type=sql_injection`, `severity=critical`,
  `confidence=0.9`, `payload_snippet` shows the SQL

## 2. Watch the port scan demo (0:08 – 0:25)

What `run_portscan_demo.sh` sends:

| # | nmap command | Effect |
|---|---|---|
| 1 | `nmap -Pn -p 8080` | single-port probe, control |
| 2 | `nmap -Pn -sS -p 1-1000` | full TCP SYN scan |
| 3 | `nmap -Pn -sU --top-ports 20` | UDP scan |
| 4 | `nmap -Pn -sV -p 8080` | service version detection |

**What to say:**
> "LIDRA is watching TCP SYN flags. A full port scan sends 1000 SYNs
> to the target in a few seconds. The detector counts unique
> destination ports from a single source within a sliding window.
> When that crosses the threshold — fire."

**What to look for in the TUI:**
- `port_scan` and `port_hopping` alerts appear (severity=high)
- `syn_burst` may also fire (volume-based, independent detector)
- Attackers table: same IP shows multiple alert types

## 3. (Optional) Watch the DNS tunnel demo (0:25 – 0:60)

This one needs a real authoritative DNS + iodine client. The
pre-captured iodine pcap in `tests/attack_pcap/` exercises the
same detector without needing a live server.

```bash
RUN_SLOW_PCAPS=1 python3 -m pytest \
  tests/test_attack_pcap_replay.py -v -s -k iodine
```

**What to say:**
> "DNS tunneling is what attackers use when all other egress is
> blocked. iodine encodes IP traffic as DNS queries. LIDRA looks
> for high-entropy query names and a high query rate from a single
> source."

**What to look for in the TUI (live) or the harness output:**
- `dns_tunnel` (severity=high, confidence=0.85)
- `ipv6_tunnel` may also fire (iodine uses AAAA records)

## 4. The 60-second run-down (read this to a room)

> "LIDRA is a passive inline network intrusion detection and
> response system. It reads packets off the wire, runs them
> through 13 analyzers — protocol parsers, behavioral detectors,
> entropy checks, threat intel lookups — and fires alerts.
>
> We just ran three real attacks against a target on this
> network. SQLi: caught, three for three, critical. Port scan:
> caught, plus two correlated detectors (port_hopping and
> syn_burst) fired automatically. The IP would already be
> blocked at the firewall if auto-block were on.
>
> False-positive rate on benign traffic: under 10 percent.
> That's the result of the FP-rate fixes we landed after
> replaying 14 real attack pcaps and 2 benign pcaps through
> the detector. The harness lives in
> `tests/test_attack_pcap_replay.py` and runs in CI.
>
> Total detection surface: 30+ attack types, 13 analyzers,
> 1 inline engine, 1 TUI."

## Files in this demo

```
demo/
├── vuln_server.py          # tiny http server, /search, /login, /healthz
├── run_sqli_demo.sh        # 4 curls, last 3 are SQLi payloads
├── run_portscan_demo.sh    # 4 nmap invocations
├── run_dns_tunnel_demo.sh  # iodine client (needs auth DNS)
└── run_all.sh              # master script — starts server, runs 1+2
```

## Cleaning up

```bash
# Stop the vuln server
pkill -f vuln_server.py

# Or it auto-cleans via trap on Ctrl+C / normal exit of run_all.sh

# Wipe the demo attacks from the DB (optional)
sqlite3 data/lidra.db "DELETE FROM attacks WHERE src_ip = '127.0.0.1';"
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Connection refused` on /search | vuln_server not running | `python3 demo/vuln_server.py 8080 &` |
| TUI shows no alerts | LIDRA not seeing the traffic | Confirm TUI is on the same network segment as the demo traffic (use `lo` for local) |
| Port scan not detected | nmap too slow (default) | Add `-T4 --max-retries 0` (already in the script) |
| DNS tunnel demo does nothing | iodine not installed | `sudo apt install iodine` |
| Detail panel is empty | No row selected | Use arrow keys to select a row in the attackers table |
