# LIDRA

**Lightweight Intrusion Detection and Response for a single host or a small network.**

LIDRA watches real packets and real logs on a Linux box, decides what is an
attack and what is ordinary traffic, and can block the source — with a firewall
rule you can audit afterwards.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-377%20passing-brightgreen.svg)](#testing)
[![CI](https://github.com/idkgarvit/LIDRA/actions/workflows/tests.yml/badge.svg)](https://github.com/idkgarvit/LIDRA/actions/workflows/tests.yml)

---

## Why this project is interesting

Most intrusion-detection demos show a screenshot of an alert. The hard problem
is the opposite one: **not** alerting. A detector that flags ordinary HTTPS as an
attack is not a weak detector, it is a useless one, because an operator stops
reading the alerts.

So LIDRA is built around a single rule: **a pattern alone must never accuse a
host.** An accusation needs corroboration — a completed handshake, a repeated
sample, a consistent timeline. The numbers below are what that rule is worth.

---

## Measured results

Everything here is reproducible with the commands in [Testing](#testing). Nothing
is an estimate.

| Measurement | Result | How to reproduce |
|---|---|---|
| **Benign web traffic** — `web_traffic.pcap`, 1200 packets | **0 flagged** (was 46; budget pinned at 5 as headroom) | `pytest tests/test_attack_pcap_replay.py -v` |
| **Benign DNS/TLS capture** — `clean.pcap`, 4956 packets | **6 flagged** — the residual noisy corpus; budget pinned at 8 so it cannot silently grow | same |
| **Benign TLS** — `https_traffic.pcap`, 60 ClientHellos | 12 flagged, all `tls_fingerprint` at severity `info` — an observation, never an alert | same |
| **Handshake completion** — benign vs. attacker | benign **100%**, `nmap_syn_scan` **0.45%**, `syn_flood` **0%** | asserted behaviourally in `tests/test_false_positive_fixes.py` (see note) |
| **Live traffic matrix** — 10 cases, real packets, no root | **10 / 10 pass** | `bash tests/live/matrix.sh all` |
| **Test suite** | **377 passed, 1 skipped** | `pytest tests/ -q` |

**Note on the handshake row.** The three percentages were measured ad-hoc while
diagnosing the false positives, and the *behaviour* they describe is what the
committed tests assert (`test_completed_handshakes_veto_the_alert`,
`test_all_zero_isns_never_flag`, `test_unanswered_syn_flood_still_flags`). The
percentages are reported as measured, not as a reproducible suite output — that
distinction is deliberate.

### The false-positive work

The starting point: a detector that flagged **46 of 1200** packets (3.83%) on the
bundled benign web capture. Reporting that number is easy; attributing it is the
work. Instrumenting the pipeline showed **five unrelated causes**:

| Cause | Hits | What was actually wrong |
|---|---:|---|
| `/*` matched `Accept: */*` | 18 | An SQL-comment pattern matched a media-range wildcard, so every ordinary `GET / HTTP/1.1` became a high-severity SQL attack |
| Zero ISNs read as spoofing | 24 | pcap writers emit `seq=0`; identical ISNs are not evidence of replay without failed handshakes |
| Timing measured the CPU, not the network | 4 | 1200 packets replayed in 0.095 s — so the detectors must use capture timestamps, not `time.time()` |
| "Low-volume host" window too short | — | A DNS resolver sending **2477 packets** looked quiet, because only the last 60 were inspected |
| `unusual_hours_activity` with no baseline | — | `hour < 6 or hour > 22` flagged the hour the sensor was *installed* in, for every host |

In each case the fix went into the detector, not into a wider suppression filter.
Widening the filter would have hidden the real findings along with the noise.

---

## Bug hunt: what I found in my own code

This table may be the most useful thing in the repository. Every row is a real
defect, found by auditing rather than by a crash, and fixed with a test that fails
if it returns.

| # | Defect | Why it mattered |
|---|---|---|
| 1 | **Observation-severity leak** — the row write sat *above* the `high/critical` gate | Every ordinary TLS ClientHello grew the attackers table, so the attacker count was meaningless and grew without bound under normal HTTPS |
| 2 | **Alert-throttle reboot blindness** — a `dict.get(key, 0)` sentinel compared against `time.monotonic()` | With the shipped 900 s cooldown there was **no alert of any kind for the first 15 minutes after every reboot** |
| 3 | **SMTP channel never instantiated** — config documented it; nothing read it | The documented email alert channel could not be enabled by any configuration |
| 4 | **No SMTP timeout** — measured **133 seconds** blocked | Alerts are sent on the detection worker, the same thread that writes rows: an unreachable mail host backpressured the verdict path for two minutes |
| 5 | **Unconditional `starttls()`** | Only port 587 could ever work; ports 25 and 465 were silently broken |
| 6 | **Own-address guard used only the primary egress IP** | On a gateway sensor a host could block its own secondary address and take that segment down |
| 7 | **Firewall rules were not identifiably ours** | Teardown matched on queue number alone and would delete another tool's rule; the uninstaller offered to delete *all* NFQUEUE rules on that basis |
| 8 | **TUI recorded refused blocks as successes** | A refused block (own gateway) appeared in the block list as though a rule existed |
| 9 | **Four version strings, already drifted** | The product could advertise different builds in the CLI, banner, status bar and emitted syslog events |
| 10 | **Actor not attributable** | Any user in the `lidra` group could block an IP with no record of who did it |

Further defects of the same kind — dead config implying a security control, a
hardcoded author path in the source, a stale duplicate unit file, and the five
false-positive causes above — are in the commit history with their measurements.

A detector that has never been wrong is a detector that has never been checked.

---

## What it actually does

Everything below is wired into the running agent — checked by following the import
graph from the entry point, not by reading a feature list.

**Packet-level detection**, from real `AF_PACKET` capture (or NFQUEUE inline for a
gateway). Classes emitted by the wired analyzers:

| Area | Detections |
|---|---|
| Scanning | `port_scan`, `port_hopping`, `service_mismatch`, `proto_scan` |
| Floods | `syn_flood`, `icmp_flood`, `connection_flood`, `bandwidth_attack`, `syn_burst`, `packet_burst` |
| TCP fingerprinting | `invalid_tcp_flags`, `low_entropy_isn`, `ttl_inconsistency`, `rare_port_pairing` |
| Timing | `slow_loris`, `timed_probe`, `timing_evasion`, `short_connection`, `slow_drip` |
| Tunnelling | `dns_tunnel`, `http_tunnel`, `icmp_tunnel` |
| Covert channels | `ack_covert_channel`, `seq_covert_channel`, `ttl_covert_channel`, `header_covert_channel` |
| Fragmentation | `tiny_fragment`, `fragment_overlap`, `fragment_oversize`, `fragment_storm` |
| Layer 2 | `arp_spoofing`, `mac_spoofing`, `broadcast_storm`, `jumbo_frame` |
| Proxy / VPN | `proxy_traffic`, `tor_traffic`, `vpn_traffic` |
| TLS | `tls_fingerprint`, `malicious_tls_fingerprint` (JA4) |

**Payload inspection (DPI)** — `sql_injection`, `xss_attempt`,
`command_injection`, `path_traversal`, `cookie_injection`, plus TLS ClientHello
parsing for JA4 fingerprinting against a configurable malicious-JA4 blocklist.

**Log detection** — LIDRA tails `journalctl` and log files, and can also listen on
a syslog UDP port. It parses SSH/auth failures, MySQL and PostgreSQL, Postfix, and
web-server access logs for brute-force, injection and scanner activity.

**Deception** — an SSH-banner honeypot on a configurable port plus decoy
honeyfiles monitored for access (`honeyfile_hits` in the database).

**Response** — `iptables`/`nftables` blocking with a TTL, a protected-address set
(never block yourself, your gateway or your resolvers), a dry-run mode, and an
audit log recording every block, unblock and *refused* block with the acting user.

**Surfaces** — a terminal UI, a `lidra` CLI, Prometheus metrics, and Slack /
Discord / SMTP alerts.

---

## Quick Start

```bash
git clone https://github.com/idkgarvit/LIDRA.git && cd LIDRA
./install.sh              # asks: laptop shield, or company gateway? (or --laptop / --gateway)
```

Then watch it:

```bash
sudo lidra --tui          # or: lidra-cli dashboard   (join the `lidra` group once, then no sudo)
```

The installer creates a dedicated `lidra` group so the TUI can attach to the
agent's socket without root, and prints what it changed. Run `lidra-cli doctor`
for a read-only health check.

<details>
<summary>Manual install (if you would rather not run the script)</summary>

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
sudo apt install -y iptables nftables
mkdir -p data logs state
sudo -E .venv/bin/python src/lidra_agent_v3.py --tui
```
</details>

### Uninstalling

One line, and it works even if this machine's network is misbehaving:

```bash
sudo ./install/uninstall.sh          # interactive; keeps your database
sudo ./install.sh --uninstall        # same thing, via the installer
```

It stops the service and verifies it is dead, removes the unit, sleep hook and
logrotate config, flushes every LIDRA firewall artifact, and **fails loudly** if a
rule cannot be removed — an orphaned NFQUEUE rule with no consumer is a
connectivity outage, not a warning. It will not touch a rule it cannot attribute
to LIDRA. Your database is kept unless you pass `--purge`, and a service restart
leaves no orphaned rules behind.

---

## Configuration

```bash
$EDITOR config/config.yaml     # the installer places one; the repo ships config/config.yaml
```

Secrets can come from the environment instead of the file:

| Variable | Purpose |
|---|---|
| `LIDRA_SMTP_PASSWORD` | SMTP password for email alerts |
| `LIDRA_ABUSEIPDB_KEY` | IP reputation lookups |
| `LIDRA_VT_KEY` | VirusTotal enrichment |
| `LIDRA_DRY_RUN` | `1` = detect and log, never touch the firewall |
| `LIDRA_METRICS_HOST` | Metrics bind address (**default `0.0.0.0`** — use `127.0.0.1` unless you mean it) |
| `LIDRA_LOG_LEVEL` | `DEBUG` for verbose logging |

> **Before you enable blocking:** start with `response.dry_run: true` and watch the
> TUI for a day. LIDRA deliberately refuses to block its own addresses, its
> gateway and its DNS resolvers, but that guard reflects what the host can see —
> check it against your own topology.

---

## Architecture

```
   packets ──▶  AF_PACKET / NFQUEUE  ──┐
                                      │
   logs    ──▶  journalctl / log files ─┤
                                        ▼
        ┌───────────────────────────────────────────────┐
        │   Analyzers  →  verdict  →  severity gate     │
        │   scan · flood · timing · DPI · JA4 · baseline│
        └───────────────────────┬───────────────────────┘
                                │  only high/critical AND a
                                │  drop verdict get through
                ┌───────────────┼───────────────┐
                ▼               ▼               ▼
            SQLite DB        alerts         firewall
          (audit trail)   (Slack/…)     (iptables/nftables)
```

Three details worth knowing:

- **The severity gate is a choke point.** One place decides whether a detection
  becomes a row, an alert and a block. Detections at severity `info` are
  *observations*: they still reach the TUI and the metrics, and stop there. This
  is the fix for defect #1.
- **Capture timestamp, not wall clock.** Timing detectors receive the moment a
  packet was *observed*, so replaying a capture at CPU speed does not change what
  the detector concludes.
- **Rules carry a comment tag** (`lidra_nfqueue`), so teardown removes exactly
  LIDRA's rules rather than whatever else happens to share the queue number.

---

## Testing

```bash
.venv/bin/pip install -r requirements-test.txt
.venv/bin/python -m pytest tests/ -q          # 377 passed, 1 skipped
```

The suite includes a **pcap replay harness** that runs real captures through the
real engine and enforces an upper bound on false positives per capture, so a
regression in detection quality fails CI instead of being noticed in production.
Run it verbosely to see the per-capture numbers:

```bash
.venv/bin/python -m pytest tests/test_attack_pcap_replay.py -v
```

### Live traffic, without root

Replay cannot catch a bug in the capture path itself. `tests/live/matrix.sh` puts
real traffic through the **real AF_PACKET capture path** in a network namespace,
using unprivileged user namespaces — no root, no VM:

```bash
bash tests/live/matrix.sh all      # or: bash tests/live/matrix.sh list
```

| Case | What it checks |
|---|---|
| `t1_portscan` | a real `nmap` SYN scan is detected |
| `t2_synflood` | a real flood is detected |
| `t3_web` | web attack classes fire (SQLi, XSS, command injection) |
| `t5_dns` | **negative control** — benign DNS is *not* flagged |
| `t6_beacon` | 12 beacons produce exactly **1** row (the gate holds live) |
| `t7_ja4` | a malicious JA4 reaches the block decision |
| `f1_block` | dry-run writes no kernel rule |
| `f4_ownip` | blocking your own address is refused |
| `s7_restarts` | restarts leave no orphaned firewall rule |
| `s8_diskfull` | an unwritable data directory does not corrupt the database |

`t5` and `t6` are the important ones — they are negative controls, and they are
what makes the false-positive work hold on live traffic rather than only on the
corpus.

---

## Limitations

Stated plainly: a limitation you find yourself is worth more than one someone else
finds for you.

- **Not production-hardened.** This is a working, tested detector — not a system
  that has survived a hostile deployment. No fuzzing campaign, no soak test beyond
  a few hours, no independent security review.
- **Single-host scope.** Tuned for one machine or a small network. No distributed
  collection, no central console, no high availability.
- **Inline mode is the least-exercised path.** `NFQUEUE` inline operation, the
  kernel bypass, and suspend/resume have not been tested on real gateway hardware:
  that needs a second machine or a VM.
- **The live matrix has not seen a genuinely full disk** (it simulates an
  unwritable directory) and has not been run across distributions.
- **Alert delivery is verified against local endpoints** that faithfully reproduce
  each provider's contract, but not against live Slack/Discord/SMTP servers.
- **CIDR blocking is not implemented.** Blocks are per-IP; there is no
  subnet-level rule.
- **CI covers Python 3.11–3.13** while `pyproject.toml` declares `>=3.10`. The
  3.10 claim is currently unverified.
- **Some modules ship unreachable.** `src/ebpf/`, `src/soar/`, `src/policy/` and
  others are present but imported by no entry point. Treat them as candidates for
  wiring or deletion, not as features.
- **Dependencies are floors, not a lockfile.** `requirements.txt` uses `>=`, so
  builds are not bit-reproducible.

Non-goals: LIDRA is not a full SIEM, not an endpoint agent, and does not attempt
distributed correlation.

---

## Documentation

| Document | Contents |
|---|---|
| `docs/PRODUCTION_READINESS.md` | The audit — every finding, its evidence, and its status |
| `docs/SAFE_LINK.md` | Inline-mode safety: how a queue rule with no consumer took a network down, and the guard added |
| `docs/HANDOFF.md` | Ground rules for working in this repository |
| `DEMO.md` | A 60-second end-to-end demo |
| `tests/attack_pcap/COVERAGE.md` | Which attack classes have captures — and which do not |

---

## Contributing

Issues and pull requests are welcome. The ground rules are short:

- **Verify, don't restate.** If you change behaviour a document asserts, correct
  the document in the same change.
- **Say whether a number was measured or inferred.** Both are fine; confusing them
  is not.
- **A bug fix comes with a test that fails without it.**

## License

MIT — see [LICENSE](LICENSE).

## Author

**Garvit Kanojia** ([@idkgarvit](https://github.com/idkgarvit))