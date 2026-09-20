# Architecture

How LIDRA is put together, and *why* it is put together that way. The design
decisions here were mostly forced by real failures — where that is true, the
failure is named.

- [Process model](#process-model)
- [The data path](#the-data-path)
- [The severity gate](#the-severity-gate)
- [Module map](#module-map)
- [Storage](#storage)
- [Time handling](#time-handling)
- [Response path](#response-path)
- [Failure containment](#failure-containment)
- [What is not wired](#what-is-not-wired)

---

## Process model

One Python process, `src/lidra_agent_v3.py`, running as root because reading raw
packets (`AF_PACKET`) and manipulating the firewall both require it.

Inside that process, three things happen concurrently:

| Thread | Job |
|---|---|
| **Capture** | `AF_PACKET` socket (or NFQUEUE in gateway mode) → parse → analyzers → detections |
| **Log/trace** | `journalctl` or log-file tailing → parse → detector → detections |
| **IPC server** | Unix socket accepting TUI commands (`block`, `unblock`) |

All three converge on the same object: `LIDRACore._handle_detection_event`.

```
                       ┌──────────────────────────────┐
   capture thread ─────▶                              │
                       │   _handle_detection_event    │──▶ DB row
   log thread     ─────▶   (the choke point)          │──▶ alert
                       │                              │──▶ firewall block
   IPC commands   ─────▶                              │
                       └──────────────────────────────┘
```

Two agent subclasses specialise this:

- **`LIDRAPersonal`** — laptop mode. `AF_PACKET` capture on one interface, plus
  log tailing.
- **`LIDRAGateway`** — gateway mode. NFQUEUE inline, so packets can be dropped
  before they are forwarded.

The choice is made by `mode:` in the config and can be overridden with
`--mode laptop|gateway`.

---

## The data path

**Capture → parse → analyze.** `bridge/inline_engine.py` owns the packet path
end to end. For each packet it:

1. parses the raw frame (`_parse_packet`, passing `capture_ts` through);
2. asks `detection/packet_analyzer.py` for a **header-only** verdict
   (`analyze_header` — it does not run the analyzer chain);
3. runs **DPI** separately when there is payload — stream-reassembled messages on
   TCP, the raw payload on UDP/other, and the ClientHello path for TLS;
4. runs the rest of the analyzers as a tuple, each returning a list of detections.

```
inline_engine._parse_packet(packet, capture_ts)
        │
        ├─ packet_analyzer.analyze_header()      (header only)
        │
        ├─ dpi_engine.inspect_stream() / inspect_packet()   ← payload
        │     SQLi · XSS · RCE · traversal · cookie injection
        │     TLS ClientHello → JA4
        │
        └─ for analyzer in (dos, fragment, port, tunnel, covert, ipv6,
                            l2, timing, proxy, tcp_fingerprinter,
                            behavioral, session_correlator, per_ip_baseline):
                 analyzer.analyze(packet) → detections
                     │
                     ▼
        alert_gate.filter(detections)   ← dedupe per (source, type)
```

Two filters in that path are themselves bug fixes, worth knowing about:

- **Solicited replies.** Session-correlator and IPv6-tunnel heuristics judge
  *content*, and both produced false positives on DNS/TLS replies the host had
  asked for. For solicited traffic those two analyzers are skipped: rates are
  still measured, content is not judged.
- **The alert gate.** Without it, every detector repeats itself on every packet
  its window still matches — measured *3,202 `syn_flood` alerts* for a single
  attacker in one scan. Raw detections still increment counters; only alerts are
  deduplicated per `(source, attack type)`.

Each analyzer call is wrapped in `try/except`: a crashing analyzer logs a warning
and the pipeline continues with the others.

**Log path.** `collectors/syslog/server.py` can listen on a UDP port for syslog
frames, and `ebpf/tracer.py` (used by laptop mode) tails `journalctl` or log
files. Both feed `detection/attack_detector.py`, which recognises auth failures,
MySQL/Postgres brute-force, Postfix, and web access-log patterns.

**Enrichment.** `intel/` can query AbuseIPDB and VirusTotal for IP reputation.
Both are optional and off unless keys are configured.

---

## The severity gate

This is the single most important design point in the codebase, and it exists
because of a real bug.

**A detection's severity answers two different questions:**

1. *How interesting is this?* — for the operator, the TUI and the metrics.
2. *Should we act on this?* — write an attacker row, alert, block.

Conflating them produced a defect where **every ordinary TLS ClientHello created
an attacker row**, because a `tls_fingerprint` observation at severity `info` was
persisted before the `high/critical` check ran.

The rule now: **severity `info` is an observation, not an attack.** It is
reported, counted and displayed; it is never persisted and never acted on.

`src/utils/severity.py` holds the predicate. It is applied at the choke point
(`agent_base._handle_detection_event`) and at the two mirrored write paths
(`agent_base._on_security_event`, `lidra_agent_v3._process_network_detection`),
because all three shared the identical bug shape.

```
detection ──▶ is_actionable_severity(severity)?
                 │
        no ──────┴──▶ TUI event "observation" + Prometheus counter   (stop)
                 │
        yes ─────────▶ DB row ─▶ alert ─▶ verdict ─▶ firewall
```

The observation is deliberately **not deleted**: `tests/test_dpi_regressions.py`
asserts the DPI layer still emits it, and the test suite checks the observation
still reaches the TUI. Silencing it would trade one bug for another.

---

## Module map

```
src/
├── lidra_agent_v3.py      entry point: parses CLI, builds the agent, runs it
├── core/
│   ├── agent_base.py      LIDRACore: the choke point, alerting, periodic loops
│   ├── personal_agent.py  laptop mode (AF_PACKET + log tailing)
│   ├── gateway_agent.py   gateway mode (NFQUEUE inline)
│   └── start_honeypot.py  SSH-banner honeypot + honeyfile creation
├── bridge/
│   ├── inline_engine.py   packet capture → parse → analyze (~1000 LOC, the core)
│   └── safe_link.py       inline-queue safety: consumer liveness, fail-open policy
├── detection/
│   ├── packet_analyzer.py runs the analyzer chain
│   ├── dpi_engine.py      payload inspection + TLS ClientHello → JA4
│   ├── attack_detector.py log-derived detections
│   ├── analyzer/          14 packet analyzers (see data path above)
│   ├── detector/          DNS tunnel detection
│   ├── baseline/          per-IP behavioural baseline
│   ├── fingerprint/       TLS/JA4 fingerprinting and the blocklist
│   └── mitre.py           attack type → MITRE ATT&CK mapping
├── response/
│   ├── verdict.py         decide_verdict(): scans ALL detections for high/critical
│   ├── firewall.py        iptables/nftables rules, protected-IP guard, dry-run
│   └── rate_limiter.py    per-IP rate tracking
├── alerts/
│   ├── notifier.py        AlertNotifier: fans out to channels, isolates failures
│   ├── slack.py           webhook (200 = ok)
│   ├── discord.py         webhook (204 = ok — 200 is a failure)
│   └── email_alert.py     SMTP (465 implicit TLS / 587 STARTTLS / else plain)
├── collectors/
│   ├── network/           AF_PACKET sniffer
│   └── syslog/            UDP syslog listener
├── database/
│   ├── db.py              LIDRADatabase: all queries live here
│   ├── migrations.py      PRAGMA user_version, ordered steps, pre-migration backup
│   └── (schema.sql)       removed — statement-identical to migration v1
├── tui/                   Textual UI (24 files): tables, detail panel, command bar
├── cli/                   lidra / lidra-cli console commands
├── output/                syslog/CEF event emitters
├── metrics/               Prometheus exposition
├── intel/                 AbuseIPDB, VirusTotal, federated stubs
└── utils/
    ├── paths.py           LIDRA_ROOT resolution, secret resolution
    ├── runtime.py         IPC socket location + mode (runtime dir, not /tmp)
    ├── severity.py        the observation-vs-attack predicate
    ├── interface.py       interface detection + all_local_ipv4 + protected_ips
    ├── actor.py           who did it (SO_PEERCRED from the kernel)
    └── version.py         the single version string
```

Roughly **23,000 LOC** in `src/`, **5,900 LOC** in `tests/`.

---

## Storage

SQLite, at `data/lidra.db`. Chosen deliberately: single-file, no daemon, and the
audit trail is something an operator can copy off the box.

| Table | Contents |
|---|---|
| `attackers` | one row per source IP seen attacking, with counters |
| `attacks` | individual detections (type, severity, timestamp) |
| `alerts` | alerts actually raised |
| `blocks` | active blocks |
| `audit_log` | who blocked/unblocked/refused what, and when |
| `honeypot_sessions` | connections to the honeypot |
| `honeyfile_hits` | decoy files that were accessed |
| `schema_meta` | schema version bookkeeping |

**Migrations** are versioned via `PRAGMA user_version` and an ordered step list,
not by replaying a `.sql` file with errors swallowed. Two safety properties:

- a **backup is taken before migrating**, so a failed migration is recoverable;
- opening a database *newer* than the binary raises `SchemaTooNewError` rather
  than silently corrupting it by operating against an unknown schema.

`data/lidra.db` is an operator's evidence. Nothing in the test suite is allowed
to write it — `tests/conftest.py` points `LIDRA_ROOT` at a temporary directory,
so an attempt raises rather than succeeds.

---

## Time handling

Detectors use **capture timestamps**, never `time.time()`.

This is not a stylistic preference. Replaying the bundled 1200-packet benign
capture takes **0.095 s** of wall clock, so anything measuring with
`time.time()` concluded that every connection was a sub-500 ms scan and reported
ordinary browsing as a slow-loris attack. Under a live capture backlog the same
bug appears in reverse. `inline_engine._parse_packet` therefore passes the
observation time through as `capture_ts`, and the timing detectors read it.

---

## Response path

```
detection(s) ──▶ decide_verdict()  ──▶ 'drop' if ANY detection is high/critical
                     │
                     ▼
              severity gate ──▶ firewall.block_ip(ip, ttl)
                     │
                     ├─ protected?  (own IP / gateway / resolver) ──▶ REFUSE + audit
                     ├─ dry_run? ──▶ report only, no kernel rule
                     └─ otherwise ──▶ iptables/nftables rule, tagged lidra_nfqueue
```

Three guards matter:

1. **Protected addresses.** LIDRA refuses to block its own address, its gateway
   and its DNS resolvers. The set is built from `all_local_ipv4()`, which reads
   `/proc/net/fib_trie` — *all* addresses, not just the primary egress IP, since
   the primary-only version let a gateway sensor block its own secondary address.
2. **Dry-run.** `response.dry_run: true` (or `LIDRA_DRY_RUN=1`) makes the whole
   path report without touching the kernel.
3. **Rule ownership.** Every rule carries the comment `lidra_nfqueue`, so
   teardown removes exactly LIDRA's rules. Before this, teardown matched on queue
   number alone and would delete another tool's rule that happened to share it.

Every attempt — including refusals — is written to `audit_log` with the acting
user, which for IPC-initiated actions is resolved from the kernel
(`SO_PEERCRED`), not from anything the client claims.

---

## Failure containment

Design rules, each traceable to a failure:

| Rule | Why |
|---|---|
| An alerting failure must never block the verdict path | Alerts are sent on the detection worker. An unreachable SMTP host with no timeout blocked it for **133 seconds**; there is now a 10 s timeout and per-channel isolation. |
| One failing channel must not stop the others | `AlertNotifier` catches per channel and continues. |
| An inline queue rule with no consumer must never be left behind | It blackholes the network. `safe_link.py` enforces consumer liveness and a fail-open policy; the uninstaller fails loudly rather than warning. |
| A degraded firewall guard is better than a crash | `firewall._protected_ips()` swallows import failures and degrades to the pre-guard behaviour with a debug log. |
| The agent must survive an unwritable data directory | Verified in the live matrix (`s8_diskfull`). |

---

## What is not wired

Stated here so the diagram above is not read as complete:

- `ebpf/xdp_loader.py` (966 LOC) — no entry point imports it.
- `soar/engine.py` (316 LOC) — zero importers.
- `policy/enforcer.py`, `intel/federated.py`, `detection/countermeasures/evasion.py` —
  present, unreachable.
- `detection/ml/` — anomaly/feature/LM modules, not wired into the pipeline.
- `detection/anomaly/smuggling_detector.py` — not wired.

These are candidates for wiring or deletion, not features. A CI check that walks
the import graph from the entry point and fails on newly-orphaned modules would
keep this list from growing — the same check would have caught a documented alert
channel that no code ever instantiated.
