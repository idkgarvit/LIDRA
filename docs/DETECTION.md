# Detection Coverage and Evidence

What LIDRA detects, what it misses, and how each number was obtained.

Every figure here comes from replaying a real capture through the real engine
(`tests/test_attack_pcap_replay.py`). Nothing in this document is an estimate.
Where a number was measured ad-hoc rather than produced by a committed test, it
says so.

Reproduce everything:

```bash
.venv/bin/python -m pytest tests/test_attack_pcap_replay.py -v -s
bash tests/live/matrix.sh all          # live packets, no root, no VM
```

---

## How to read the numbers

The harness reports **two** counts per capture, and confusing them is the easiest
way to make this project look better or worse than it is:

| Counter | Meaning |
|---|---|
| `packets w/det` | every packet where an analyzer fired — coverage, "did the pipeline see this at all" |
| `actionable` | packets where a **non-`info`** detection fired — what the benign budget is measured against |

The distinction exists because severity `info` is an **observation**, not an
accusation. A TLS ClientHello is reported at `info` so the TUI and metrics can see
it; it must never create an attacker row, alert, or block. Counting that as a
false positive would make the benign budget unsatisfiable on any TLS traffic and
would push the next person to silence the observation rather than tune a detector.

So: a benign capture showing `12 flagged` with `actionable: 0` is **not** 12 false
positives. It is 12 observations.

---

## Results

### Benign captures — the false-positive budget

| Capture | Packets | w/det | **Actionable** | Types | Budget |
|---|---:|---:|---:|---|---:|
| `web_traffic.pcap` (HTTP) | 1200 | 0 | **0** | — | 5 |
| `https_traffic.pcap` (TLS) | 60 | 12 | **0** | `tls_fingerprint` (observations) | 0 |
| `clean.pcap` (DNS resolver) | 4956 | 6 | **6** | `dns_tunnel`, `session_correlated_*` | 8 |

`web_traffic` is the headline: **0.00%**, down from 46 packets (3.83%), with all
five root causes attributed and fixed (see README). It is the "what normal looks
like" baseline.

`https_traffic` has a budget of **0** and reports **0 actionable** — the 12
detections are all `info` observations. This is the capture that would have
exposed the observation-severity leak: before the fix, each of those 12 created an
attacker row.

`clean.pcap` still flags 6 packets (0.12%). These are `dns_tunnel` and
`session_correlated_*` hits on a synthetic DNS corpus — the residual noisy
capture, and the honest current limit of the tuning. The budget is pinned at 8 so
it cannot silently grow.

### Attack captures

| Class | Capture | Packets | w/det | Types fired |
|---|---|---:|---:|---|
| **DoS** | `syn_flood.pcap` | 5000 | 2 | `syn_flood`, `syn_burst` |
| **Recon** | `nmap_syn_scan.pcap` | 2687 | 4 | `port_scan`, `port_hopping`, `syn_burst`, `syn_flood` |
| **Recon** | `nbtscan.pcap` | 100 | **0** | **none — gap** |
| **Bruteforce** | `fscan_mysql_bruteforce.pcap` | 3048 | 6 | `session_correlated_*`, `syn_burst`, `syn_flood` |
| **Bruteforce** | `fscan_redis_bruteforce.pcap` | 324 | 3 | `session_correlated_sql_attack`, `syn_burst`, `timing_evasion` |
| **Tunnelling** | `dnscat2.pcap` | 438 | 3 | `dns_tunnel`, `session_correlated_*` |
| **TLS C2** | `malicious_clienthello.pcap` | 4 | 1 | `tls_fingerprint` (see note) |
| **SQLi** | `dvwa-sqli-writeWebShell.pcap` | 11 | 2 | `sql_injection`, `command_injection` |
| **SQLi** | `zentao-sqli.pcap` | 11 | 2 | `sql_injection`, `xss_attempt` |
| **SQLi** | `test_with_sql.pcap` | 1 | 1 | `sql_injection` |
| **SQLi** | `edited_test_with_sql.pcap` | 1 | 1 | `sql_injection` |
| **RCE** | `shiro-cve-2016-4437.pcap` | 781 | 6 | `cookie_injection`, `session_correlated_*`, `syn_burst` |

**Note on `malicious_clienthello.pcap`.** In the replay harness this capture shows
as an `info` observation with 0 actionable, because the harness does not patch the
JA4 blocklist — a JA4 match requires the crafted hash to be *in* the blocklist,
which the test does deliberately in isolation. The malicious path is verified
elsewhere and does reach a block decision:

- `tests/manual/ja4_repro.py` — builds the engine, *then* patches the blocklist
  (the construction order matters: `TLSFingerprinter.__init__` calls
  `_load_ja4_db()`, which rebinds it, so patching first is silently wiped).
- `tests/live/matrix.sh t7_ja4` — a real ClientHello with a blocklisted JA4
  through the live capture path.

### Summary

| Metric | Value |
|---|---|
| Attack captures replayed | 12 |
| Classes detected | 9 of 12 cleanly, 3 partially, **1 missed** |
| Benign web false positives | **0.00%** (0/1200) |
| Benign DNS false positives | 0.12% (6/4956) |
| Benign TLS false positives | **0** actionable (12 observations) |

---

## Known gaps

Named deliberately. A coverage table without gaps is a coverage table nobody
checked.

| Gap | Detail |
|---|---|
| **NBTScan (UDP/NetBIOS)** | Not detected at all. `port_analyzer` handles TCP SYN scanning; UDP/NetBIOS name-service sweeps are not modelled. The one capture in the corpus that is missed entirely. |
| **No specific bruteforce signature** | The fscan MySQL/Redis captures are caught — but as `session_correlated_*` and `syn_burst`, not as a `bruteforce` attack type. The behaviour is flagged; the class is not named. |
| **No specific Shiro signature** | CVE-2016-4437 is caught via `cookie_injection`, not as `shiro_deserialization`. Same shape: detected, not named. |
| **`session_correlated_*` is direction-blind** | It no longer fires on the benign corpus — but only because the token no longer matches, **not** because it now distinguishes a request from a response. It will still correlate a response body as though it were a request. |
| **`clean.pcap` residual** | 6 hits on synthetic DNS traffic, borderline rather than clearly wrong. |

---

## Attack classes with no capture at all

The analyzers emit these classes; there is **no capture in the repository**
exercising them end-to-end. They are covered by unit tests on synthetic packets,
which is weaker evidence than a replay.

| Class | Detections |
|---|---|
| Fragmentation | `tiny_fragment`, `fragment_overlap`, `fragment_oversize`, `fragment_storm` |
| Covert channels | `ack_covert_channel`, `seq_covert_channel`, `ttl_covert_channel`, `header_covert_channel` |
| Layer 2 | `arp_spoofing`, `mac_spoofing`, `broadcast_storm`, `jumbo_frame` |
| Proxy / VPN | `proxy_traffic`, `tor_traffic`, `vpn_traffic` |
| TCP fingerprinting | `invalid_tcp_flags`, `low_entropy_isn`, `ttl_inconsistency`, `rare_port_pairing` |
| Timing | `slow_loris`, `timed_probe`, `timing_evasion`, `short_connection`, `slow_drip` |
| Tunnelling | `http_tunnel`, `icmp_tunnel` |
| IPv6 | `ipv6_*` |

Closing this gap is the single highest-value addition to the test corpus: it is
mechanical work (generate the traffic, add a capture and its metadata) and it
would convert a whole column of "unit-tested only" into "replayed end to end".

---

## Live traffic (no root, no VM)

Replay cannot catch a bug in the capture path itself, so `tests/live/matrix.sh`
sends real packets through the real `AF_PACKET` path in a network namespace.

| Case | Result |
|---|---|
| `t1_portscan` | `port_scan`, `port_hopping`, `syn_burst` |
| `t2_synflood` | `syn_flood`, `syn_burst` |
| `t3_web` | `sql_injection`, `xss_attempt`, `command_injection` — traversal is sent but not asserted |
| `t5_dns` | **not flagged** (negative control) |
| `t6_beacon` | detected; 12 beacons produce exactly **1** row |
| `t7_ja4` | `malicious_tls_fingerprint` reaches the block decision |
| `f1_block` | dry-run wrote no kernel rule |
| `f4_ownip` | blocking own address refused |
| `s7_restarts` | no orphaned firewall rule after restarts |
| `s8_diskfull` | unwritable data dir survived, DB integrity ok |

`t5` and `t6` are the important rows: they are negative controls, and they are
what demonstrate the false-positive work holds on **live** traffic rather than
only on a corpus.

The case names are exactly the ones the harness declares (`#CASE:` tags in
`tests/live/_in_ns.sh`); `t3_web` sends a path-traversal probe but its assertion
counts only the three classes above, so traversal is exercised without being
proven.

---

## What is *not* verified

- **Inline (NFQUEUE) mode** has not run on real gateway hardware. The live matrix
  covers detection on a real interface, not drop-before-forward.
- **Suspend/resume, kernel bypass, and a genuinely full disk** — the disk case
  simulates an unwritable directory; these need a VM or a second machine.
- **Cross-distribution behaviour** — tested on Kali only.
- **Alert delivery to live Slack/Discord/SMTP servers** — verified against local
  endpoints that reproduce each provider's contract (including Discord's
  204-not-200 quirk), not against the real services.
- **The 30 MB iodine capture** is opt-in (`RUN_SLOW_PCAPS=1`) and was not part of
  the default run reported here.

A number in this document is measured. A statement in this section is unproven.
That distinction is the point of the document.
