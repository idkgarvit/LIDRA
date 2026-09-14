# LIDRA — Production Readiness Plan

**Status of this document:** final plan. The intent is that when every item marked
`[blocking]` is done, LIDRA is releasable as a real product for the audience it
targets, and nothing material is left to discover later.

**Author's note on how this was built:** every claim below was checked against the
repository, the running agent and this machine, not inferred from
`MASTER_PLAN.md`. Where a plan document and the code disagreed, the code won.
Line references and measurements are real. Items carried over from
`MASTER_PLAN.md` that are already done, or that are not needed for this product,
are moved to §10 with a reason rather than silently dropped.

---

## 0. What "production ready" means here — the exit criteria

LIDRA has three deployment shapes with different bars. A feature that is
production ready for one is not necessarily ready for another, and conflating
them is how projects end up claiming more than they can support.

| Class | Who | Bar to ship |
|---|---|---|
| **A. Single-device shield** | one person, one laptop/server | Detects attacks on its own host, never breaks the host's networking, installs and uninstalls in one command, survives reboot/suspend/upgrade |
| **B. Small-company sensor** | a startup with a few servers | A installs, plus: multi-host log ingestion, retention, alert delivery that is actually received, and an operator can answer "what happened" from the UI |
| **C. Inline gateway** | LIDRA box between firewall and servers | B installs, plus: verified forwarding, fail-open under load, tested on real 2-NIC hardware, and an HA/bypass story |

**LIDRA today is pre-A.** The plan below is ordered so A ships first, then B,
then C — but §1–§4 are prerequisites for all three, and none of them can be
skipped for the first release.

### The nine gates (all must be green to call it shipped)

1. No known defect that can take the host's network down.
2. Install → run → uninstall → reinstall all work cleanly on a clean machine.
3. No advertised capability that does not work on the machine it is advertised for.
4. Detection numbers published per attack class, with false positives, reproducible.
5. An operator can tell it is alive, and can tell when it stops protecting them.
6. Data survives upgrades; no silent data loss.
7. Secrets are not world-readable; privileged surfaces are not world-writable.
8. Every module in `src/` is either wired into the agent, or deleted.
9. Documented behaviour matches measured behaviour.

---

## 1. [blocking] Correctness defects that must be fixed first

These are things I found while reading and verified. Each one is a shipping
blocker or a credibility blocker.

### 1.1 `PrivateTmp=true` makes the documented TUI unusable — [blocking, S]

`install/systemd/lidra.service:35` sets `PrivateTmp=true`. The agent creates its
IPC socket at `/tmp/lidra_tui_<pid>.sock` (`src/tui/ipc_server.py:44`), and the
README tells the user to attach the TUI with
`LIDRA_TUI_SOCKET=$(ls -t /tmp/lidra_tui_*.sock | head -1)` (README:41).

`PrivateTmp=true` gives the service its **own** `/tmp` namespace. A user-shell
TUI and the systemd service see different `/tmp` directories. **The documented
attach path cannot work on any systemd install**, which is the install path the
installer creates.

*Verified, not inferred* — reproduced the namespace split with
`unshare --mount --propagation private` writing `/tmp/lidra_tui_99999.sock`:
inside the private namespace **1** file visible, from the user shell **0**.

- Fix: move the socket to `/run/lidra/` (or `/var/lib/lidra/run/`), which is the
  correct location for daemon runtime state, and point `SOCKET_DIR` there.
  Update README and `install/systemd/lidra-sleep` accordingly.
- Acceptance: `systemctl start lidra` then `lidra tui` as a normal user
  shows live data on a clean install; an automated test asserts the socket path
  is outside any private tmp namespace.

### 1.2 The IPC socket is world-writable with no authentication — [blocking, S]

`src/tui/ipc_server.py:57` does `os.chmod(self._socket_path, 0o666)`. The socket
accepts commands including block/unblock. Any local user can drive the IDS.

*Verified on this machine* — a live agent creates
`/tmp/lidra_tui_92391.sock` with mode **`666 root:root`**.

- Fix: create `/run/lidra/` mode `0750` owned by the service user/group
  (`lidra`), set the socket to `0660`, and add a group-based access path for
  operators who need the TUI. If the dashboard is ever exposed over a network,
  it needs real auth — `dashboard.api_key` already exists in the config schema
  and in `src/utils/paths.py:51` (`LIDRA_API_KEY`) but **nothing reads it**; wire
  it or delete it (see §1.6).
- Acceptance: a test asserts socket mode is `0660`; a second local user cannot
  connect.

### 1.3 No uninstall path — [blocking, S]

There is no `--uninstall` in `install.sh`, no `make uninstall`, and no
`UNINSTALL.md`. A security tool that installs a root systemd service, edits
`/etc/` and adds firewall rules must be removable. This is also the reason the
"it broke my internet" class of bug is so damaging: the user's escape route is
editing files by hand as root with no network.

- Fix: `install.sh --uninstall` that stops and disables the unit, removes
  `/etc/systemd/system/lidra.service`, the sleep hook, logrotate config, any
  `lidra_*` nftables tables and iptables rules, and **asks** before deleting
  `/opt/lidra` (preserving `data/lidra.db` to a backup path by default).
- Acceptance: install → uninstall → install on a clean VM leaves no residue
  (`systemctl status` clean, `nft list tables` clean, `iptables -S` clean).

### 1.4 Web UI is claimed but does not exist — [blocking, S]

README:28 advertises "**Live Dashboard** — Web UI with real-time attack
monitoring". README:51 and :219 contradict it ("Dashboard: TUI mode"). There is a
text CLI dashboard (`src/dashboard/cli.py`); there is no served web UI.

- Fix: delete the web-UI bullet and describe what exists. If a web view is
  wanted, that is §3.4, not a claim on the current README.
- Acceptance: every bullet in the feature list can be demonstrated from a clean
  install; a checklist test walks the README and fails on any undemonstrable claim.

### 1.5 No schema migration path — [blocking, M]

Schema lives in `src/database/schema.sql` and `_init_schema()`
(`src/database/db.py:53`) calls `executescript` then **swallows any
"already exists" error**. There is no schema version, no `user_version`, no
migration runner. The moment a release changes a table, existing installs either
silently keep the old schema (and queries fail at runtime) or crash on startup.

- Fix: add `PRAGMA user_version`, a `migrations/` directory of idempotent
  numbered SQL steps, and run them on open inside a transaction with a backup
  copy of the DB taken first. Fail loudly if the DB is newer than the binary.
- Acceptance: a test builds a DB at schema v1, applies the binary expecting v2,
  and asserts data is preserved and columns added.

### 1.6 Config keys that nothing reads — [non-blocking, S]

`dashboard.api_key` is in `config/config.yaml`, `config_loader.py:37` and
`paths.py:51`, but no code consumes it. Dead config is worse than no config: it
implies a security control that does not exist.

- Fix: delete, or wire it in §1.2.
- Acceptance: a test enumerates config keys and fails on any with zero readers
  outside the config module.

### 1.7 Background behaviour that silently stops — [blocking, M]

`SafeLink` (§ my prior fix, `src/bridge/safe_link.py`) proves the *inline queue*
is alive. Nothing proves the **agent as a whole** is still doing anything. If the
capture thread dies on an interface error, the AF_PACKET socket is closed by the
kernel, or the log tailer's file is rotated away, the process stays up and
reports health while doing nothing.

- Fix: a liveness heartbeat the operator can check — `lidra status` reporting
  last-packet-seen wall time per capture source, and a systemd-visible health
  signal. If no packets and no log lines have been seen for N minutes while the
  interface is up, log CRITICAL and surface it.
- Acceptance: kill the capture thread in a test; `lidra status` reports DEGRADED
  within one interval.

---

## 2. [blocking] Live testing — the matrix that has not been run

Everything so far exercises the pipeline in-process (`_parse_packet` +
`_run_detection_pipeline`) or replays pcaps. **The capture path, the firewall
path and the alert-delivery path have never been validated end-to-end on real
traffic.** This is the largest single body of unverified behaviour.

### 2.1 Detection on real traffic — [blocking, L]

| # | Test | Method | Pass condition |
|---|---|---|---|
| T1 | Port scan from another host | `nmap -sS` from a second box on the LAN | `port_scan` alert within 60s, source IP correct |
| T2 | SYN flood | `hping3 --flood -S` from a second host | `syn_flood` alert, and in inline mode the source is blocked |
| T3 | SQLi / XSS / CMDi against a local web server | `nikto`, `sqlmap`, the `demo/vuln_server.py` | Correct class, severity, and a forensic pcap attached |
| T4 | SSH brute force | `hydra -l root -P` against local `sshd` | `ssh_bruteforce` from `auth.log` correlator |
| T5 | DNS tunnel | `iodine`/`dnscat2` client to a controlled endpoint | `dns_tunnel` alert, **verified via the port-53 path fixed in §prior work** |
| T6 | Beaconing | a script hitting an endpoint every 30s for 10 min | `timed_probe` or baseline anomaly, and **no duplicate alerts** (gate working live) |
| T7 | Encrypted C2 | a TLS client using a known-bad JA4 (in `config.yaml`) | JA4 alert — **requires §3.2, currently unwired, so this test cannot pass yet** |
| T8 | Benign soak | 24h of normal use on this laptop | Alert count is small and every alert is explicable by hand |

T8 is the one that decides whether a human would keep it installed. It cannot be
shortcut.

### 2.2 The internet-safety cases — [blocking, L]

These are the tests that prevent a repeat of the reported outage. All on a
machine where a rollback path is known.

| # | Scenario | Expected |
|---|---|---|
| S1 | Inline mode, `kill -9` the agent mid-traffic | Kernel rule carries `bypass`; connectivity never drops |
| S2 | Inline mode, agent alive, `nft flush ruleset` by hand | SafeLink logs CRITICAL within 5s, operator is told, traffic flows |
| S3 | Inline mode, WiFi interface goes down and up | Capture rebinds, no stale queue rule left behind |
| S4 | Suspend / resume | `lidra-sleep` hook restarts; capture works after resume |
| S5 | Reboot with the service enabled | Comes up, rules present, TUI attachable |
| S6 | Inline mode on WiFi with an old kernel lacking `bypass` | Refuses to arm and says why, rather than black-holing the host |
| S7 | Two restarts in quick succession | No stacked/duplicate nft rules or iptables rules |
| S8 | Full disk | Agent keeps detecting, logs rotate, DB does not corrupt, and it does not spin on a write error |

### 2.3 Firewall and response path — [blocking, M]

| # | Test | Expected |
|---|---|---|
| F1 | Block an IP, verify it is dropped | iptables/nftables rule exists, traffic actually dropped |
| F2 | TTL expiry | Rule removed at TTL without leaving orphans |
| F3 | `lidra unblock` | Rule removed; traffic restored immediately |
| F4 | Block an IP that is the operator's own gateway/DNS | Refuses (the `own_ips` guard) — **test it, do not assume** |
| F5 | nftables backend on a Debian/Ubuntu box | Same behaviour as Kali |
| F6 | iptables *legacy* backend (no nft) | Falls back correctly or refuses cleanly |

F4 matters especially: blocking your own resolver is a self-inflicted outage and
is exactly the failure class that erodes trust fastest.

### 2.4 Cross-distribution — [blocking for B/C, M]

Tested so far: Kali only. The README implies broader support.

| Distro | Why | Pass condition |
|---|---|---|
| Kali/Debian 13 | current dev target | full suite + T1–T8 |
| Ubuntu 24.04 LTS | most likely small-company host | install, run, detect, uninstall |
| Debian 12 | conservative servers | install, run, detect |
| Fedora/RHEL 9 | SELinux + nftables-only | must not require iptables; SELinux denials documented |
| Raspberry Pi OS (aarch64) | plausible cheap sensor | install + detect, or documented as unsupported |

Fedora is the interesting one: `iptables` may be absent entirely, and SELinux may
block raw sockets. Either support it or say it is unsupported — do not ship a
silent failure.

### 2.5 Alert delivery — [blocking for B, S each]

`alerts/slack.py`, `discord.py`, `email_alert.py` exist. None has been observed
delivering to a real endpoint in this session.

- Verify: Slack webhook, Discord webhook, SMTP, each end-to-end.
- Verify: behaviour when the webhook 500s, times out, or the host has no route.
  An alerting failure must not delay a verdict or crash the agent.
- Verify: the throttle (`alerts/alert_throttle.py`) does not suppress the first
  alert of a genuinely new incident.

---

## 3. [blocking] Detection completeness — dead code and unwired features

The most significant structural finding: **a large share of `src/` is not
reachable from the running agent.** It is written, sometimes tested, and never
called. For a security product this is worse than absence, because the README and
the plan imply the coverage exists.

| Module | Size | Reachable from agent? | Action |
|---|---|---|---|
| `detection/fingerprint/tls_fingerprinter.py` (JA4) | present, `tests/test_ja4.py` passes | **No** — not referenced in `inline_engine.py` or the agent | §3.2 wire, or delete |
| `intel/federated.py` | 78 LOC | **No** — zero importers | delete or defer (§10) |
| `detection/analyzer/fp_feedback.py` | 66 LOC | **No** — self-references only | wire (it is the auto-FP-dampening the FP work needs) or delete |
| `ebpf/xdp_loader.py` | 966 LOC, `XDP_README.md`, `Makefile` target | **No** — and `tracer.py` fails on missing `bcc`, so the whole eBPF path is inert | §8.1 |
| `detection/countermeasures/` | dir exists, zero importers | **No** | delete |
| `soar/engine.py` | 316 LOC | **Not wired into the agent** — no reference from `lidra_agent_v3.py`, `core/`, or `inline_engine` | delete or defer |
| `policy/enforcer.py` | present | unclear — 3 references, not in the packet path | resolve: wire or delete |
| `src/utils/{parser,notifier,metrics}.py` | 0 bytes | dead files | delete |
| `docs/architecture.md` | referenced by `MASTER_PLAN.md`, does not exist | missing | §7.1 |
| `COVERAGE.md` | **referenced by 5 pcap `.meta.yaml` files, does not exist** | missing | §7.1 — those metas point readers at a file that isn't there |

**Rule to adopt: every module in `src/` is either wired into the agent, or
deleted.** A CI check can enforce it (import-graph reachability from
`lidra_agent_v3.py`, with an explicit allowlist for `cli/` and `tui/`).

### 3.1 Wire or delete, module by module — [blocking, M]

For each row above, decide once and record the decision in `ARCHITECTURE.md`:
- Wired → a test proves it fires on its own fixture.
- Deleted → remove the file, the config keys, the plan references and the
  README claims.

### 3.2 Wire JA4 into the detection path — [blocking, M]

`config.yaml` ships a curated `malicious_ja4` list (Cobalt Strike, Sliver,
Havoc, etc.). `tls_fingerprinter.py` implements JA4 and `tests/test_ja4.py`
passes. **Nothing calls it during detection**, so the configured list has no
effect. This is arguably the highest-value detection feature in the repo — it is
the only thing that works on encrypted traffic.

Wire it, and add the missing half: a **per-host expected-JA4 baseline**. A bad-JA4
blocklist catches known tools; a baseline catches *new* ones, which is where the
points above 90% live.

- Acceptance: T7 in §2.1 passes; a fixture with a known-bad ClientHello raises
  `tls_fingerprint_mismatch`; a normal browser does not.

### 3.3 Remaining false positives — [blocking for A, M]

Measured after the alert-gate and detector fixes:

| Capture | Now | Residual cause |
|---|---|---|
| `clean.pcap` (benign DNS) | 6 / 4956 (0.12%) | `dns_tunnel` borderline on high-entropy queries |
| `web_traffic.pcap` (benign HTTP) | 46 / 1200 (3.8%) | `low_entropy_isn` (highest severity of the FPs — reports "spoofed" high) and `session_correlated_sql_attack` on base64-looking CDN bodies |

The 3.8% is still too high for a tool a person leaves running. `low_entropy_isn`
in particular fires at **high** severity on replay/synthetic ISNs, and its
window does not reset on alert.

- Fix: treat `low_entropy_isn` as requiring corroboration before high severity
  (a real spoofed-ISN attack has other marks — RST storms, no handshake
  completion). Require the session correlator to see the pattern across distinct
  connections, not within one.
- Fix: `session_correlated_*` must not fire on responses (server→client); it is
  currently judging CDN payloads as if they were requests.
- Target: **<0.5% on both benign captures**, with the numbers recorded in the
  meta files (the `fp_rate_baseline` fields already exist for this).

### 3.4 The evidence table — [blocking for A, M]

The single most credibility-critical deliverable, and the thing that makes every
percentage claim defensible. See `docs/STRATEGY_REVIEW.md` §3 for the argument.

Produce **`docs/DETECTION.md`**: one row per attack class × corpus, with FN and FP
counts and the exact command to reproduce.

| Attack class | Corpus (name + version + source) | Detected / total | Missed | FP per 100k benign | Reproduce command |
|---|---|---|---|---|---|
| SQLi | in-repo pcaps + fuzzed variants | | | | |
| XSS | | | | | |
| Command injection | | | | | |
| Port scan / recon | | | | | |
| SYN flood / DoS | | | | | |
| SSH/DB brute force | | | | | |
| DNS tunnel | | | | | |
| Brute force (generic) | | | | | |
| TLS/C2 via JA4 | | | | | |
| Beaconing | | | | | |
| Malware / payload | — | out of scope | | | state this explicitly |

Rules for this table, adopted from the review:
- No CIC-IDS2017 headline number without noting its documented labelling errors
  (Engelen et al., Springer 2023).
- Detection rate and FP rate are published together, always.
- Attack coverage needs **at least 3 independent scanners** per web class
  (`sqlmap`, `nikto`, `custom fuzz`) — one tool proves nothing about the class.
- Reproduce commands must work from a clean clone.

### 3.5 Evasion test suite — [blocking for B, L]

Detection claims are meaningless without adversarial testing. Build
`tests/evasion/` with a generator that produces encoded variants and asserts
each is still caught:

- SQLi/XSS/CMDi through: URL encoding (single/double/triple), UTF-7, UTF-16,
  hex, HTML entities, Base64, case randomisation, comment injection
  (`UN/**/ION`), whitespace/`+` substitution, null bytes, overlong UTF-8.
- HTTP-level: chunked transfer, multipart, `Content-Length`/`Transfer-Encoding`
  conflict (smuggling), duplicate headers, `X-Forwarded-For` /
  `X-Original-URL` override, HP splitting.
- TCP/IP-level: fragmentation overlap, tiny fragments, TTL manipulation,
  out-of-order and retransmitted segments against the reassembler, PAWS/timestamp
  tricks, checksum-invalid packets.
- Report a **bypass count**, and treat any bypass as a bug with a fixture.

This file is what turns "85%" into a number someone can trust.

### 3.6 QUIC / HTTP3 — [non-blocking for A, L]

Named in `MASTER_PLAN.md` (C6) and untouched. An attacker tunnelling over HTTP/3
is currently invisible. Either implement metadata-only detection (QUIC packet
sizes/timing, JA4 over the QUIC ClientHello) or document the blind spot
prominently in the README's limitations.

---

## 4. [blocking] Operability

What separates something that runs from something someone maintains.

| # | Item | Why it blocks | Effort |
|---|---|---|---|
| 4.1 | `lidra uninstall` (§1.3) | escape route | included above |
| 4.2 | **Backup / restore of `data/lidra.db`** — documented and scripted | an operator will lose their history otherwise | S |
| 4.3 | **Retention policy verified** — `cleanup_days` actually prunes; DB does not grow unbounded | a laptop DB filling the disk is a self-inflicted outage | S |
| 4.4 | **Upgrade path** — `install.sh` re-run on an existing install preserves config and data; version recorded in the DB | silent config clobber on upgrade is unacceptable | M |
| 4.5 | **Version everywhere** — `pyproject` says 3.0.0, nothing else does; no git tag; no `CHANGELOG.md` | cannot say what a user is running | S |
| 4.6 | **`lidra status` as the single health answer** — mode, capture source, packets/sec, last alert, queue rule state, DB size, uptime, version | first thing support asks | S |
| 4.7 | logrotate verified on a real rotation | see §2.2 S8 | S |
| 4.8 | Prometheus endpoint documented, with a working Grafana dashboard JSON | the metrics were just wired; the dashboard is still empty of panels | M |
| 4.9 | Service hardening review — `NoNewPrivileges=false` is currently needed for what? Document or reduce | least privilege | S |

---

## 5. [blocking] Security of the product itself

A security tool is a high-value target: it runs as root, sits in the packet path
and holds threat-intel keys.

| # | Item | Detail | Effort |
|---|---|---|---|
| 5.1 | IPC socket permissions (§1.2) | currently `0666`, world-writable | S |
| 5.2 | **Least privilege**: run as root only for the capabilities needed, or document precisely why root is required; use systemd `AmbientCapabilities`/`CapabilityBoundingSet` (`CAP_NET_RAW`, `CAP_NET_ADMIN`) rather than full root where possible | `lidra_agent_v3.py:55` hard-requires euid 0 | M |
| 5.3 | **Config/secret file permissions** — `config.yaml` holds SMTP password, webhooks, API keys; verify mode and warn if world-readable | credential leak | S |
| 5.4 | **Secrets never logged** — grep the codebase for key/webhook/password reaching a log line; add a test | common bug | S |
| 5.5 | **Webhook/TI request safety** — TLS verification on, timeouts set, no unbounded response reads, no user-controlled URL | SSRF/DoS | S |
| 5.6 | **Dependency pinning + a lockfile** — `requirements.txt` sets floors only; a supply-chain compromise or a breaking minor ships straight to users | reproducibility | M |
| 5.7 | **Automated dependency/vuln scanning** in CI (`pip-audit`), plus a `SECURITY.md` with a disclosure process | expected of a security project | S |
| 5.8 | **Threat-intel cache poisoning** review — `intel/` results influence blocking; confirm a bad upstream answer cannot cause a mass-block (`no_block`, `own_ips` guards hold) | self-inflicted outage | M |
| 5.9 | **Audit log for operator actions** — block/unblock/whitelist changes recorded with who/when | accountability | S |

---

## 6. [blocking] Packaging, release and supply chain

| # | Item | Detail | Effort |
|---|---|---|---|
| 6.1 | `CHANGELOG.md`, semantic version, git tag `v3.0.0` | users need release notes | S |
| 6.2 | Tagged releases with a **pinned install** — `install.sh` currently `git clone --depth 1` from `main`, i.e. every install is HEAD-of-branch | reproducibility and safe rollback | M |
| 6.3 | CI green across 3.11–3.13 (matrix exists) — **plus add 3.14**, which is what this machine runs | the dev box is ahead of CI | S |
| 6.4 | CI job for the §3.5 evasion suite and the §2.4 distro smoke test (containers) | regressions caught before users | M |
| 6.5 | Release artifact: tarball + checksum (and signature if practical) | verifiable download | M |
| 6.6 | `docker/Dockerfile` vs `Dockerfile` vs `docker-compose.yml` vs `docker/docker-compose.yaml` — **four files, two Dockerfiles, two compose files, inconsistent `privileged: true` vs `cap_add: NET_ADMIN`** | decide one path or delete the rest | S |
| 6.7 | Decide the **platform support matrix** and put it in the README: Linux only, which distros, container caveats (`--network=host` needed; NFQUEUE cannot work in a container unless the host's netns is used) | avoid silent unsupported installs | S |

---

## 7. [blocking] Documentation

| # | Item | Why | Effort |
|---|---|---|---|
| 7.1 | **`COVERAGE.md`** — referenced by 5 pcap metadata files, **does not exist**. Either write it (attack-class coverage, honestly, including gaps) or remove the references | broken docs are a credibility leak | M |
| 7.2 | **`ARCHITECTURE.md`** — the reference `MASTER_PLAN.md` points at, missing. Include the module-wiring table from §3.1 | contributors | M |
| 7.3 | **`README` rewrite pass**: every claim demonstrable; add a **Limitations** section (encrypted traffic visibility, QUIC, host-level blindness, packet-loss under extreme load) | trust | M |
| 7.4 | `CONTRIBUTING.md`, issue/PR templates | people will file bugs | S |
| 7.5 | **`SECURITY.md`** with disclosure policy | a security tool needs one | S |
| 7.6 | `docs/recursive-sinkhole.md` describes files that do not exist (`src/honeypot/tarpit.py`, `src/dashboard/main.py`, a `sinkhole_sessions` table) — mark as **design, not implemented**, or implement | dead design docs are misleading | S |
| 7.7 | `MASTER_PLAN.md` reconciliation: mark Phases A–E as done/not-done/deferred, so it stops reading as a spec of shipped features | the plan currently overstates | M |
| 7.8 | A **5-minute quickstart** that has been followed by someone who is not the author, on a clean VM | the actual UX test | S |

---

## 8. Performance and scale (release-gating for C, tracked for A/B)

Measured today: 5.2k–17k pps replay; ~1.9k events/s sustained end-to-end; ~29k
events/s alert drain; ~32 MB RSS. The bottleneck is Python per-packet work.

| # | Item | Detail | Effort |
|---|---|---|---|
| 8.1 | **Wire the XDP path** — `xdp_loader.py` (966 LOC) is unreachable and `tracer.py` depends on `bcc`, absent here. Decide: finish XDP (kernel blocklist + SYN-flood drop at line rate) or delete it and stop advertising eBPF/XDP | the only route past ~50–100 Mbps | L |
| 8.2 | If XDP is kept: **pre-compiled BPF objects** — the target audience must not need `clang` + headers to run an IDS | usability | M |
| 8.3 | Benchmark harness in CI with a **regression gate** (fail if p50 latency or pps degrades >20%) | catch perf regressions | M |
| 8.4 | Capacity statement: "sustains N Mbps / M pps on a 4-core box with all analyzers on; degrades to <X> without XDP" — measured, in the README | sizing | M |
| 8.5 | Multi-core scaling: capture thread + N detection workers (currently the verdict path is single-threaded by design) | C-class throughput | L |

---

## 9. Final validation — the go/no-go checklist

Run on a **clean VM** and on **real hardware**, by someone who did not write the
code. Every line must be verified, not assumed.

- [ ] `curl … | sudo bash` → prompts are clear → service is running → TUI shows live data
- [ ] README followed top to bottom; every claim demonstrated
- [ ] T1–T8 pass; every alert from T8 explained by hand
- [ ] S1–S8 pass (the internet-safety cases) — **this is the gate that matters most**
- [ ] F1–F6 pass
- [ ] Install → uninstall → reinstall, no residue
- [ ] Upgrade from the previous tag preserves DB + config
- [ ] `docs/DETECTION.md` table reproduces from a clean clone in under an hour
- [ ] `tests/evasion/` bypass count is published and non-zero items have fixtures
- [ ] Prometheus + Grafana dashboard shows real data
- [ ] Alerts arrive on Slack/Discord/email, and a broken webhook does not stall verdicts
- [ ] Module-wiring CI check passes (no orphan modules)
- [ ] 24h soak on real traffic: no memory growth, no unbounded queue, DB size sane
- [ ] No known defect that can take the host offline
- [ ] A second person has run it and kept it running for a day

---

## 10. Explicitly out of scope for "production ready"

Carried from `MASTER_PLAN.md`, deliberately deferred. Stated so their absence is
a decision, not an oversight. Each needs a one-line note in the README's roadmap.

| Item | Reason |
|---|---|
| Federated intel exchange (`intel/federated.py`) | Unwired, no trust model tested, and a P2P IoC network is its own security problem. Delete or defer. |
| SOAR playbooks / LLM triage (`soar/engine.py`) | Not wired into the agent. Valuable later; not needed for A/B. |
| TLS MITM proxy (`MASTER_PLAN` D2) | Massive scope (CA management, pinning breakage, legal). Out. |
| Adaptive honeypot / T-Pot (D3) | The existing honeypot is enough for v1. |
| Graph analytics, GNN lateral-movement (E1) | Research project, not a release. |
| Hardware acceleration, DPDK/100G (E3) | Not the audience. |
| Zero-trust / LDAP integration (E4) | Enterprise scope, contradicts "lightweight for one person". |
| Full package-manager distribution (apt/rpm repos) | Nice-to-have; the curl installer covers A/B. |
| Windows/macOS support | AF_PACKET and NFQUEUE are Linux-only. **Do not advertise cross-platform.** |

---

## 11. Suggested order, with a dependency-honest sequence

Do not start detection work before the trust-critical items; a shipped defect in
the network path poisons every later number.

**Stage 1 — stop the bleeding (blocking, ~1 week)**
§1.1–1.5 (TUI socket, socket perms, uninstall, web-UI claim, schema migration),
§4.4–4.6 (upgrade, version, status).
*Exit: install/uninstall/upgrade cycle clean; operator can tell it is alive.*

**Stage 2 — live truth (~2–3 weeks)**
§2.1 T1–T8 on this laptop + a second host; §2.2 S1–S8; §2.3 F1–F6.
*Exit: the capture, firewall and alert paths are verified end-to-end or the
failures are written down.*

**Stage 3 — detection integrity (~3–4 weeks)**
§3.1 module decisions, §3.3 FP work, §3.2 JA4 wiring, §3.5 evasion suite,
§3.4 the evidence table.
*Exit: `docs/DETECTION.md` is reproducible and the benign FP rate is <0.5%.*

**Stage 4 — ship shape (~2 weeks)**
§3.6/§7 docs, §5 security hardening, §6 packaging and release, §4.7–4.9.
*Exit: tag `v3.0.0`, one pinned install path, CI green on 3.11–3.14.*

**Stage 5 — C-class only (~4+ weeks)**
§8.1–8.5 XDP, multi-core, §2.4 distro matrix.
*Exit: a real 2-NIC gateway tested with real traffic, or the gateway mode is
marked experimental.*

---

## 12. The honest summary

LIDRA is a genuinely unusual project: the detection pipeline is well-organised,
the test fixtures are real, the failure-mode documentation (added this session)
is better than most commercial tools', and the safety work around the queue rule
addresses the exact class of bug that kills trust in an IDS.

What stands between it and "production ready" is not more detectors. It is:

1. **A handful of real defects** (§1) — most importantly that the documented TUI
   attach path cannot work on a systemd install, and the socket is world-writable.
2. **The live path has never been tested** (§2). Everything so far is in-process.
3. **A lot of code is not wired to anything** (§3) — including JA4, the single
   best feature in the repo.
4. **Numbers that cannot yet be defended** (§3.4/§3.5).
5. **Operability** — no uninstall, no migration, no upgrade, no version (§4/§6).

Items 1 and 5 are days of work and are the difference between "a good repo" and
"something a stranger installs on a machine they care about". Items 2–4 are the
weeks that make the detection claims mean something. Nothing here requires a
rewrite, and nothing here is speculative — every item is a defect, a gap or a
measurement I could point at in the repository today.