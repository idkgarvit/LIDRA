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

## 0.1 Status corrections — re-read on 2026-09-18

This plan's method is "where the plan and the code disagreed, the code won".
Re-reading the tree found several claims that were wrong when written or had
gone stale. They are recorded with evidence, because a plan that calls a fixed
item broken re-orders work around a non-problem.

**A note on method, because it matters for two rows below.** A correction is
only as good as the measurement behind it. Where a claim was tested, say how;
where it was reasoned, mark it inference — the JA4-alert row below is a
disproved *inference* that would have caused a real regression if written down
as a finding.

| Claim | Reality (verified) | Effect |
|---|---|---|
| §1.5 no migration path; `schema.sql` *is* the schema | `database/migrations.py` runs `PRAGMA user_version` + ordered steps, takes a backup, refuses a newer DB. `schema.sql` is **deleted** — statement-identical to migration v1, imported by nothing. | §1.5 done |
| §1.6 `dashboard.api_key` dead key | Deleted from `config_loader.py` and `paths.py` (with `LIDRA_API_KEY`). It was never in `config.yaml`. | §1.6 done |
| §2.3 F4 "refuses (the `own_ips` guard) — test it, do not assume" | The guard existed **only** in `bridge_block_ip()`. `block_ip()` — the path `lidra block`, the TUI and the IPC socket take — had no own-IP check, so dropping the default route was possible. Now: `protected_ips()` (own + gateway + resolvers) enforced in both entry points, with an explicit refusal. | F4 was a **fix**, not a verification; fixed, live run outstanding |
| §3.2 "nothing calls JA4 during detection" | Wired: `inline_engine` → `dpi_engine.inspect_stream(..., "tls")` → `TLSFingerprinter.analyze()`, and its constructor loads the 9 hashes from `tls_fingerprints.malicious_ja4`. | T7 is **not** blocked on §3.2; it needs a ClientHello fixture. The per-host baseline half stands |
| §7.1 `COVERAGE.md` does not exist | It exists: `tests/attack_pcap/COVERAGE.md`, referenced by 6 meta YAMLs. | §7.1 is reconciliation, not authoring |
| §1.4 web-UI claim | README was fixed, but the product still printed "LIDRA v3 - eBPF-Powered Detection System" on the dashboard, the CLI banner and `--help`. eBPF needs `bcc` and otherwise falls back to log monitoring; `soar/` LLM triage is unwired. Claims removed; the agent docstring now states what is not wired. | §1.4 re-opened and closed; a test scans for the phrases |
| §4.5 one version string (claimed done) | Still drifted: `tui/widgets/status_bar.py` hardcoded `v3.0.0`, and the TUI logo art carried a baked-in caption. Both now read `utils/version.py`; a tree-scanning test fails on any version literal outside it. | §4.5 closed for real |

### 0.1.1 NEW — a confirmed defect the plan did not know about

| Claim | Reality (verified) | Effect |
|---|---|---|
| **(not previously claimed anywhere) ordinary HTTPS creates attackers/attacks rows** | **CONFIRMED DEFECT, now fixed.** `TLSFingerprinter.analyze()` returns a `tls_fingerprint` detection at severity `info` for **any** parseable ClientHello (`dpi_engine.py` passes it through). `core/agent_base.py` wrote the attacker+attack row at `:264`, three lines **above** the `severity in ("high","critical") and verdict == "drop"` gate at `:267`, so the gate never saw it. Every ordinary HTTPS connection grew `attackers`/`attacks`, making the "attackers" figure in `lidra status` grow with normal browsing.<br><br>Reproduce (before fix): build an engine, `_run_detection_pipeline` a TCP/443 packet carrying a ClientHello → `[('tls_fingerprint','info')]` → `analyze_packet_event` returns a `DetectedAttack` → `record_attack` runs. Measured: 5 benign HTTPS connections produced 5 attacker rows and 5 attack rows.<br><br>Fixed: `utils/severity.py` (`is_actionable_severity`) gates the response path in `core/agent_base.py` (both `_handle_detection_event` and the eBPF/log path) and in `lidra_agent_v3._process_network_detection`. The observation is **kept** — still returned by the DPI layer, still counted in Prometheus, still pushed to the TUI as an `observation` event. Pinned both directions by `tests/test_observation_severity.py` (15 tests). | Fixed, verified end-to-end: 20 benign HTTPS connections → 0 rows; known-bad JA4 → attacker + attack + alert |
| **"JA4 cannot fire an alert — the malicious case never alerts or blocks"** | **DISPROVED. Do not "fix" this — the alert path works.** This was an *inference*, not a measurement: the engine's verdict was assumed to come only from the built-in packet analyzers. It does not. `response/verdict.py::decide_verdict()` scans **all** detections and returns `DROP` if any is high/critical, and the JA4 detection is in that list.<br><br>Verified: `detections: [('malicious_tls_fingerprint','high')]`, `verdict: Verdict.DROP`, gate → alert/block = **True**. Encoded as `tests/test_observation_severity.py::TestMaliciousJA4StillAlerts` and `::TestMaliciousTlsCaptureAlerts` (the latter replays a real capture), so the evidence is collected and cannot go stale silently.<br><br>**The trap that produces the false conclusion:** `TLSFingerprinter.__init__` calls `_load_ja4_db()`, which **rebinds** `_KNOWN_MALICIOUS_JA4` from config. Patch the blocklist and *then* build the engine and the constructor wipes the patch, so everything looks benign. Build the engine first, patch second, then feed the packet. `tests/test_ja4.py` does it in the patched order against a `__new__`-constructed object, which is why it passes. | **No action.** Recorded so the wrong conclusion cannot be re-derived |
| **`alert_throttle` silently suppressed the first alert after every reboot** | **CONFIRMED DEFECT, now fixed.** `AlertThrottle.allow()` used `self._last.get(key, 0)` as the never-seen sentinel, but `time.monotonic()` is **seconds-since-boot** on Linux. For the first `cooldown_seconds` of uptime, `now - 0 = uptime < cooldown`, so a genuinely first-ever alert was suppressed. With the shipped 900 s alert cooldown, **LIDRA raised no alert at all for the first 15 minutes after a reboot**; and because `LIDRADatabase` reuses this class for record dedupe with a 60 s cooldown, **attack rows were dropped for the first minute** too (proven: a `critical` `sql_injection` recorded 0 rows at uptime < 60 s, 1 row at ≥ 60 s).<br><br>Found by running the suite on a freshly-booted machine, where `tests/test_alert_throttle.py` failed 4/4 and then passed unprompted once uptime crossed 900 s — a flaky-looking failure that was a real bug. | Fixed; regression test `test_first_alert_fires_on_a_freshly_booted_machine` (simulated clock, so it works on long-running CI) |
| **F4 guard missed every address except the primary egress IP** | **CONFIRMED DEFECT, now fixed (found by the live matrix, case F4).** `protected_ips()` was built from `local_ips()`, which returns only the *primary egress* address (found by UDP-connecting to a public IP) plus hostname addresses. On a single-NIC laptop those coincide — which is why it looked correct. On any box with a second NIC, a VLAN, a bridge or an alias (a Class-C gateway sensor, exactly what this project targets) the secondary addresses were absent, so `lidra block <own-secondary-ip>` was **allowed** and would have taken that segment down.<br><br>Measured in the netns harness: with `10.88.0.1` on a veth, `lidra block 10.88.0.1` reported "DRY-RUN: would block" instead of refusing. Fixed by adding `all_local_ipv4()`, which enumerates every configured IPv4 address from `/proc/net/fib_trie` (world-readable, no subprocess, works under a hardened unit). | Fixed; `tests/test_self_protection.py::test_secondary_interface_addresses_are_protected` |
| **`unusual_hours_activity` fired on ordinary traffic at night** | **CONFIRMED DEFECT, now fixed (found by running the suite at 04:00).** Two causes: (1) the "near midnight" test was `hour < 6 or hour > 22`, which made 00:00-05:59 an anomaly for *every* host — night shifts, backups, cron and late-night browsing all alerted; (2) there was no floor on observations, so a fresh sensor (few active hours ⇒ tiny `ratio`) reported unusual hours for whatever hour it happened to be installed in. A benign TLS ClientHello and benign DNS both tripped it. | Fixed: a minimum observation count plus a minimum number of active hours before the hour claim is allowed; a host broadly active across the day is no longer flagged for being awake at 4 AM. `tests/test_false_positive_fixes.py::TestUnusualHoursNeedsARealBaseline` |

Fixed alongside, all previously unnoticed:

- `lidra help` crashed on a mismatched Rich tag (`[yellow]Actions:[/green]`)
  and no test rendered the help text, so it survived.
- A block was recorded as `applied=1` in dry-run — the shipped default — so
  `lidra status` reported an active block the kernel never had.
- NFQUEUE teardown and the uninstaller matched rules by queue number alone; the
  uninstaller offered to delete *every* NFQUEUE rule in INPUT. LIDRA's rule is
  now tagged `lidra_nfqueue` and only rules it can prove it owns are removed.
- The `audit_log` table (schema v2) had no writers. Block/unblock from CLI, TUI
  and IPC are recorded now; the IPC actor comes from `SO_PEERCRED`, not from the
  client. `lidra audit` reads it.
- `install.sh --uninstall`, `make uninstall` and a README **Uninstall** section
  exist, so the escape route is discoverable.
- `install/lidra.service` (stale duplicate, wrong user, pre-rename path) deleted;
  the unit's `install/default/lidra` reference pointed at a file that never
  existed.

Suite: **377 passed, 1 skipped** (was 312/1 before the observation-severity fix
and its tests). `tests/conftest.py` fails any test that writes to the
repository's real database.

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

### 2.1 Detection on real traffic — [blocking, L] — **RUN 2026-09-20, see §2.1.1**

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

### 2.1.1 LIVE MATRIX — first real-traffic run (2026-09-20)

**Everything before this was in-process or pcap replay. This is the first time
LIDRA detected anything arriving on a real interface.** Harness:
`tests/live/matrix.sh` (10 cases, `bash tests/live/matrix.sh all`).

Result: **10 passed, 0 failed.** Cases run, and what was actually observed in
the agent's database afterwards:

| Case | Result | Evidence recorded |
|---|---|---|
| T1 port scan (`nmap -sS` at the sensor) | PASS | `port_scan`, `port_hopping`, `syn_burst` from the attacker IP |
| T2 SYN flood (`hping3 --flood -S`) | PASS | `syn_flood`, `syn_burst` |
| T3 web attacks (SQLi/XSS/CMDi/traversal over live HTTP) | PASS | `sql_injection`, `xss_attempt`, `command_injection`, `path_traversal` — all four classes |
| T5 DNS, benign half (real port-53 path) | PASS | **quiet** — no `dns_tunnel`, no `session_correlated_*` |
| T6 beaconing (12 connections, 1.5 s apart) | PASS | detected, and **1 attack row for 12 beacons** — the alert gate holds live |
| T7 encrypted C2 (known-bad JA4) | PASS | `malicious_tls_fingerprint` |
| F4 own-address block | PASS | refused |
| F1 dry-run block | PASS | reported, and **no kernel rule written** |
| S7 two rapid restarts | PASS | no NFQUEUE rule left behind |
| S8 unwritable data dir | PASS | agent survived, DB integrity ok |

**How, without root.** `sudo` needs a password on this box, but
`unshare --user --map-root-user --net` provides uid 0 *and* full capabilities in
a private network namespace. The sensor captures on a veth; the attacker runs in
a **sibling** network namespace behind the other end of that pair, so frames
genuinely cross the wire.

Four topologies were tried and three are **wrong** — recorded because each one
silently proves nothing:

1. Both endpoints in one namespace → the kernel short-circuits same-subnet
   traffic, ARP is never answered, `ping` is 100% loss and the capture port sees
   only ARP requests. Measured, not assumed.
2. `ip netns add` → refused unprivileged (writes `/run/netns`, owned by real
   root).
3. A child that unshares `--user` as well as `--net` → it gets caps in its own
   user namespace only, so `ip link set X netns PID` fails with "Invalid netns
   value".
4. Working arrangement: the child unshares **only `--net`**, sharing the parent's
   user namespace. Also: the wrapper must **not** pass `--pid`, or `$!` is a
   namespaced PID and the move fails the same way.

**Not covered here, and still needing real hardware or a VM:** S1-S6 (inline
mode, kernel `bypass`, suspend/resume, reboot, old-kernel refusal), S8 as a
genuinely full filesystem, F2/F3 (TTL expiry, unblock — they write real rules),
F5/F6 (nft/iptables-legacy backends), §2.4 cross-distro, §2.5 alert delivery to
real Slack/Discord/SMTP endpoints, and T8's 24-hour soak. Those are not made
less necessary by this run.

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

### 2.5 Alert delivery — [blocking for B, S each] — **RUN 2026-09-20, see below**

`alerts/slack.py`, `discord.py`, `email_alert.py` exist. None had been observed
delivering to a real endpoint before this run.

**Result: Slack, Discord and SMTP all deliver; failure modes are contained.
Three real defects were found and fixed.**

| Requirement | State |
|---|---|
| Slack webhook delivers | **Yes** — payload verified well-formed (`attachments[0].title`, severity/ip fields) |
| Discord webhook delivers | **Yes** — `embeds[0]` verified; a `200` is correctly treated as *failure* (Discord returns 204) |
| SMTP delivers | **Yes, after a fix** — it could never have worked before (see defect 1) |
| Webhook 500 | returns False, no raise, caller unaffected |
| Webhook hangs | bounded by the 10 s client timeout; the notifier still returns, other channels still send |
| Host has no route | fails in bounded time; measured with TEST-NET-1 |
| A raising channel does not stop the others | verified |
| Throttle does not suppress a new incident | verified through the real notifier: 50 repeats → 1 alert; a new source or a new attack type each get through |
| **Live end-to-end** | **real `nmap -sS` against the sensor → `low_entropy_isn` + `syn_flood` recorded → 2 webhook payloads delivered** with the forensics pcap path in the message body; agent still alive afterwards |

#### Defects found (all fixed)

1. **`EmailChannel` was never instantiated.** `config/config.yaml` documents a
   complete `alerts.email` block (`enabled`, `smtp_host`, `smtp_port`,
   `username`, `password`, `from_addr`, `to_addrs`) but `_init_alerting()` read
   only Slack and Discord — the documented SMTP channel was unreachable. Now
   wired, with the password resolved through `resolve_secret` so
   `LIDRA_SMTP_PASSWORD` works instead of a plaintext config value.

2. **`smtplib.SMTP()` had no timeout — measured a 133-second block.** The
   default is *infinite*, and `notify()` runs on the detection worker, the same
   thread that writes rows and pushes TUI events. An unreachable mail host did
   not merely lose an alert; it backpressured the verdict path for over two
   minutes. Now an explicit 10 s default.

3. **`starttls()` was unconditional**, so only port 587 could ever work: port 25
   (plain relay) failed outright and port 465 (implicit TLS) failed on the
   STARTTLS handshake. Transport is now derived from the port
   (465 → `SMTP_SSL`, 587 → STARTTLS, anything else → plain) with an override.

Evidence: `tests/test_alert_delivery.py` (19 tests) — real listeners on
localhost, the real channel classes, the real `AlertNotifier`. Each fix was
falsified by reverting it and confirming the test fails.

---

## 3. [blocking] Detection completeness — dead code and unwired features

The most significant structural finding: **a large share of `src/` is not
reachable from the running agent.** It is written, sometimes tested, and never
called. For a security product this is worse than absence, because the README and
the plan imply the coverage exists.

| Module | Size | Reachable from agent? | Action |
|---|---|---|---|
| `detection/fingerprint/tls_fingerprinter.py` (JA4) | present, `tests/test_ja4.py` passes | **Yes** — `inline_engine` → `dpi_engine.inspect_stream(..., "tls")` → `TLSFingerprinter.analyze()` (this row said "No" and was stale; corrected 2026-09-18, see §0.1) | wired; the per-host baseline half remains (§3.2) |
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
  `malicious_tls_fingerprint`; a normal browser does not.

  **§3.2 acceptance name corrected 2026-09-18:** this originally said
  `tls_fingerprint_mismatch`, which **no code emits**. The strings the code
  actually produces are `tls_fingerprint` (severity `info`, any parseable
  ClientHello) and `malicious_tls_fingerprint` (severity `high`, hash in
  `tls_fingerprints.malicious_ja4`). An acceptance criterion naming a
  non-existent attack type cannot be satisfied, and someone would have
  "fixed" the mismatch by inventing the string.

  Note the interaction with §0.1.1: `tls_fingerprint` at `info` is now
  deliberately non-actionable, so "a normal browser does not [raise]" holds in
  the response sense (no row, no alert, no block) while the DPI layer still
  reports the observation. See `tests/test_observation_severity.py`.

### 3.3 Remaining false positives — [blocking for A, M]

Measured after the alert-gate and detector fixes:

| Capture | Before 2026-09-19 | **Now** | Residual cause |
|---|---|---|---|
| `clean.pcap` (benign DNS) | 6 / 4956 (0.12%) | **6 / 4956 (0.12%)** | `dns_tunnel` 2, `session_correlated_cmd_attack` 2, `session_correlated_sql_attack` 2 — all at the borderline; see note below |
| `web_traffic.pcap` (benign HTTP) | 46 / 1200 (3.8%) | **0 / 1200 (0.00%)** | none — cleared |
| `https_traffic.pcap` (benign TLS) | 0 / 60 actionable | **0 / 60** | 12 packets carry a severity-`info` `tls_fingerprint` observation, non-actionable by design (§0.1.1) |

**Target met: both benign captures are now ≤0.5% actionable, and the HTTP
capture is at zero.** `web_traffic` went 3.83% → 0.00%; `clean.pcap` was already
inside budget and did not regress.

### What the four defects actually were

Every one was found by diagnosis — reading the capture, instrumenting the
detector, and checking the claim. None was fixed by widening the severity
filter, and no detector's severity was changed.

1. **`session_correlated_sql_attack` (18 of 46) — `/*` matched `Accept: */*`.**
   The SQL-fragment regex treated the comment opener `/*` as a fragment, and
   `Accept: */*` is the most common HTTP header value in existence. Every
   `GET / HTTP/1.1` counted as SQL, so after 5 requests in 30 s the host was
   reported at **high** severity. Fixed with a negative lookbehind.

2. **`low_entropy_isn` (24 of 46) — a zero ISN is not spoofing.** The detector
   flagged identical ISNs as "possible replay/spoofing", but most pcap writers
   (and scapy's default) emit `seq=0`, and `web_traffic`, `syn_flood` and
   `nmap_syn_scan` *all* carry zero ISNs — so the check distinguished nothing.
   It now requires a non-zero sample **and** failed-connection evidence: a host
   whose handshakes complete is talking to a real peer. This is the corroboration
   §3.3 predicted it needed.

3. **Timing detectors measured the wrong clock.** `slow_loris`,
   `short_connection` and `timing_evasion` read `time.time()` — *when the
   pipeline ran*. A pcap replay runs at CPU speed (1,200 packets in **0.095 s**),
   so every connection looked like a sub-500 ms scan. They now take the capture
   timestamp the engine passes in (`_parse_packet(capture_ts=...)`). This matters
   in production too: under a capture backlog the live path had the same defect
   in the other direction.

4. **"Low-volume host" only inspected 60 packets.** `clean.pcap`'s DNS resolver
   sends **2,477** packets but counted as quiet, so its ordinary query/response
   bursts (0 ms apart, then 10 s idle, repeated) read as scripted pacing.
   Measuring the host's real volume plus requiring bursts to be *runs* of ≥3
   packets removed it (measured on the capture: 2 alerts → 0).

### Evidence

`tests/test_false_positive_fixes.py` (19 tests) pins each fix **in both
directions** — benign input is silent, and the attack each detector exists for
still fires (`unanswered SYN flood`, `non-zero predictable counter`, `real paced
evasion`, `real SQLi`). Each was verified to fail when its fix is reverted. The
corpus harness also tightened: `expected_max_false_positives` on the HTTP capture
went from 150 (a budget that could not fail at 3.8%) to 5.

**What is still outstanding:** the 6 `clean.pcap` hits are borderline detector
calls on a synthetic DNS corpus, and `session_correlated_*` still judges
content without regard to direction — the plan's original note that it should
not treat server→client responses as requests remains true and unaddressed.
Neither is in the benign-HTTP path that gates T8.

**Status: the [blocking for A] part of this section is done.** The two things
the target asked for were exactly the two things that turned out to be the
defects, and both are implemented:

- ~~`low_entropy_isn` requires corroboration before high severity~~ — **done.**
  A non-zero ISN sample plus failed-handshake evidence. A real spoofed-ISN
  attack still flags; a host whose connections complete does not.
- ~~`session_correlated_*` must not fire on responses~~ — **partially done.**
  The `/*` collision that caused 18 of the 18 HTTP hits is fixed, but the
  direction-blindness itself is still there: the correlator has no notion of
  request vs response. It no longer fires on this corpus, but for the wrong
  reason (the token no longer matches), not because direction was considered.
  **This remains open and is the next real improvement here.**

Remaining, and not blocking: the 6 `clean.pcap` hits are borderline calls on a
synthetic DNS corpus (`dns_tunnel`, `session_correlated_*`), all at the
detector's own threshold.

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