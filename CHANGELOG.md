# Changelog

All notable changes to LIDRA. Format based on
[Keep a Changelog](https://keepachangelog.com/); this project uses
[Semantic Versioning](https://semver.org/).

Entries record *what was wrong*, not only what changed — a fix without the
failure it prevents is a claim nobody can check.

---

## [Unreleased]

A correctness pass over the detection, response and alerting paths. The theme:
**most of these were silent**. Nothing crashed, nothing logged an error, and
several had been wrong since the first commit.

### Fixed — detection correctness

- **Observation-severity leak.** A detection at severity `info` is an
  *observation* (e.g. "this is a TLS ClientHello"), but the database row was
  written *above* the `high/critical` gate. Every ordinary HTTPS connection
  therefore created an attacker row, so `attackers` grew without bound under
  normal traffic and the attacker count in `lidra status` was meaningless.
  Observation severity is now defined in `src/utils/severity.py` and enforced at
  the choke point that feeds all three consumers — row, alert, block — plus the
  two mirrored write paths that shared the identical bug shape. The observation
  itself is preserved: it still reaches the TUI and the metrics.
  (`tests/test_observation_severity.py`)

- **Alert throttle was blind for the first 15 minutes after every reboot.**
  `AlertThrottle.allow()` used `self._last.get(key, 0)` as its "never seen before"
  sentinel and compared it to `time.monotonic()`, which counts from boot. For the
  first `cooldown` seconds of uptime, every key looked like a recent alert. With
  the shipped 900 s cooldown that meant **no alert of any kind for 15 minutes
  after each reboot**; with the 60 s record cooldown, no attack rows for the first
  minute. Sentinel is now `None` with an explicit first-seen branch.

- **Five false-positive root causes**, found by measuring rather than guessing.
  On the bundled benign capture (`web_traffic.pcap`) the engine flagged 46 of
  1200 packets (3.83%); it now flags 0.
  - `session_correlator`'s `_PARTIAL_SQL` pattern matched `/*` — SQL comment
    syntax — inside the ordinary request header `Accept: */*`, so every plain
    `GET / HTTP/1.1` became a high-severity SQL attack (18 hits).
  - `tcp_fingerprinter` treated identical or zero ISNs as spoofing. pcap writers
    commonly emit `seq=0`, so ordinary captures looked like replay attacks (24
    hits). Zero ISNs are no longer sampled, and an accusation now additionally
    requires failed handshakes.
  - Timing detectors read `time.time()` — when the pipeline ran — instead of the
    capture timestamp. A 1200-packet replay takes 0.095 s, so genuinely slow
    scans looked instantaneous and fast clients looked like slow-loris (4 hits).
  - The "low-volume host" heuristic inspected only the last 60 packets, so a DNS
    resolver sending 2477 packets was counted quiet and flagged.
  - `unusual_hours_activity` used a bare `hour < 6 or hour > 22` test with no
    floor on observations, so on a fresh sensor the hour it was installed in was
    an anomaly for every host.

  The unifying principle: **a pattern alone must never accuse a host.**

- **`session_correlated_*` is still direction-blind.** It no longer fires on the
  benign corpus, but only because the token no longer matches — not because it
  now distinguishes a request from a response. Recorded as open, not closed.

### Fixed — response and safety

- **Own-address guard saw only the primary egress IP.** `local_ips()` returns the
  address found by UDP-connecting to a public host; on a single-NIC laptop that is
  the only one, which is why the gap went unnoticed. On a box with a second NIC, a
  VLAN, a bridge or an alias — a gateway sensor — the secondary addresses were
  absent, so LIDRA could block its own secondary address and take that segment
  down. Added `all_local_ipv4()` reading `/proc/net/fib_trie`.

- **Firewall rules were not identifiably LIDRA's.** Rules carried no marker, so
  teardown matched on queue number alone and would delete another tool's rule that
  happened to share it; the uninstaller offered to delete *every* NFQUEUE rule in
  `INPUT` on that basis. Rules now carry the comment tag `lidra_nfqueue`.

- **A refused block was recorded as a success.** The TUI added a manual block to
  its list even when the firewall refused it (own address / gateway / resolver),
  so the block list showed a rule that did not exist.

- **Actions over the IPC socket were not attributable.** The socket accepts from
  any user in the `lidra` group, so a block could not be traced to a person. The
  server now resolves the peer uid from the kernel (`SO_PEERCRED`) and writes the
  audit row itself rather than trusting the client.

### Fixed — alerting

Alert delivery had never been exercised against a real endpoint. Doing so found
three defects:

- **The SMTP channel was never instantiated.** `config/config.yaml` documents a
  complete `alerts.email` block (`enabled`, `smtp_host`, `smtp_port`, `username`,
  `password`, `from_addr`, `to_addrs`), but `_init_alerting()` read only Slack and
  Discord — the documented email channel could not be enabled by any
  configuration. Now wired, with the password resolved through `resolve_secret` so
  `LIDRA_SMTP_PASSWORD` works instead of a plaintext config value.

- **No SMTP timeout — measured a 133-second block.** `smtplib.SMTP()`'s default
  is infinite, and `notify()` runs on the detection worker, the *same thread* that
  writes rows and pushes TUI events. An unreachable mail host did not merely lose
  an alert; it backpressured the verdict path for over two minutes. Explicit 10 s
  default.

- **`starttls()` was unconditional.** Only port 587 could ever work: port 25
  (plain relay) failed outright and port 465 (implicit TLS) failed the STARTTLS
  handshake. Transport is now derived from the port, with an override.

- **A failing channel no longer stops the others**, and webhook failure modes are
  tested: 500, hang, and no-route each return in bounded time without raising.
  (`tests/test_alert_delivery.py`)

### Fixed — architecture and hygiene

- **Four version strings, already drifted.** The CLI, the banner, the TUI status
  bar and emitted syslog events each hardcoded their own version, so the product
  could advertise different builds in different places. All read
  `src/utils/version.py` now.

- **The IPC socket lived in `/tmp` with mode 0666.** Under systemd
  `PrivateTmp=true` the path was invisible to a user-shell TUI, and a world-writable
  socket in a shared directory let any local user issue block/unblock commands.
  Moved to a runtime directory with a restrictive mode and a `lidra` operator group.

- **Database setup replayed a `.sql` file with errors swallowed.** Replaced with
  `PRAGMA user_version` plus ordered migration steps, a backup taken before
  migrating, and an explicit refusal (`SchemaTooNewError`) to open a database newer
  than the binary.

- **A hardcoded author path in the source** (`/home/<author>/Project/LIDRA/...`)
  leaked a username and pointed at a pre-rename checkout. Path resolution belongs
  to `utils/paths.py`.

- **Dead config implying a security control:** `dashboard.api_key` was read by
  nothing — there is no served dashboard to authenticate.

- **Deleted** `src/database/schema.sql` (statement-identical to migration v1,
  imported by nothing) and `install/lidra.service` (a stale duplicate unit naming
  the wrong user and path).

### Added

- **`install/uninstall.sh`** — an uninstaller that mirrors the installer in
  reverse: stops and verifies the service is dead, removes the unit, sleep hook
  and logrotate config, flushes LIDRA's firewall artifacts, and **fails loudly**
  if a rule cannot be removed, because an orphaned NFQUEUE rule with no consumer
  is a connectivity outage. It will not touch a rule it cannot attribute to LIDRA,
  and keeps the database (the operator's evidence) unless `--purge` is passed.
  `install.sh` gained `--uninstall` / `--purge` / `--yes` so it works even when
  the install itself cannot proceed. **Not yet run against a populated system.**

- **`tests/live/matrix.sh`** — 10 cases through the real `AF_PACKET` capture path
  in a network namespace, as an unprivileged user, no VM. Includes two negative
  controls (benign DNS is not flagged; 12 beacons produce exactly one row).

- **TLS captures** (`benign/https_traffic.pcap`, `tls/malicious_clienthello.pcap`)
  with provenance metadata and a generator. The repository previously contained no
  TLS capture at all, which is exactly how the observation-severity leak stayed
  invisible — the benign baseline had zero TCP/443 packets.

- **`docs/ARCHITECTURE.md`** and a rewritten `README.md` with measured results, a
  bug-hunt table, and an explicit Limitations section.

### Verified

- **377 tests passing, 1 skipped**, in both a deep and a shallow `TMPDIR` (two
  socket tests used to fail only in the deep one, because the `AF_UNIX` path
  exceeded 108 bytes).
- Alert delivery, end to end on live traffic: a real `nmap -sS` against the sensor
  produced two detected attack types, two database rows, and two webhook payloads,
  with the agent still alive afterwards.

### Known limitations

See the Limitations section of the README. The headline ones: inline mode,
suspend/resume and a genuinely full disk need real hardware or a VM; CI covers
Python 3.11–3.13 while `pyproject.toml` declares `>=3.10`; several modules ship
unreachable; dependency versions are floors, not a lockfile.

---

## [3.0.0] — earlier

Packet-level detection (AF_PACKET and NFQUEUE inline), DPI with JA4 TLS
fingerprinting, log and syslog detection, per-IP baselining, SQLite persistence,
iptables/nftables blocking with TTL, a terminal UI, a CLI, Prometheus metrics, and
Slack/Discord/SMTP alerting.

Developed as a Masters thesis project in Cybersecurity.
