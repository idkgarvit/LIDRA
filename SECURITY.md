# Security Policy

## Reporting a vulnerability

Please report security issues **privately**, not in a public issue.

Use GitHub's [private vulnerability reporting][gh-report] on this repository
(Security → Report a vulnerability). If that is unavailable, open a minimal issue
asking for a private contact channel — without describing the vulnerability.

Please include:

- what the issue is and where (file, function, config);
- how to reproduce it, with the smallest example;
- what an attacker gains;
- whether it requires root, a group membership, or local access.

**Do not** include live credentials. Redact keys, tokens and passwords.

There is no bug-bounty programme and no guaranteed response time — this is a
personal project, maintained in spare time. A good-faith report will be
acknowledged and credited unless you prefer otherwise.

## Scope

LIDRA runs as **root** by design: it needs `AF_PACKET` for raw capture and
`NET_ADMIN` to manage the firewall. That makes privilege boundaries the most
interesting class of bug here, and the most welcome reports.

In scope:

- Privilege escalation through LIDRA's IPC socket, CLI, or config handling.
- Bypasses of the protected-address guard (blocking the host's own address,
  its gateway, or its resolvers).
- Injection through any parsed input: packet payloads, log lines, syslog frames,
  config values, or CLI arguments.
- Firewall/rule handling that removes rules LIDRA does not own, or leaves a rule
  behind on teardown (an orphaned NFQUEUE rule with no consumer blackholes the
  network — see `docs/SAFE_LINK.md`).
- Credential or secret disclosure in logs, error messages, or the database.
- Detection bypasses significant enough to hide a class of attack.

Out of scope:

- Anything requiring root already (root can do anything to LIDRA by definition).
- The absence of a feature — no TLS on the metrics endpoint by default, no
  authentication on the TUI socket beyond group membership. These are documented
  trade-offs, though a *bypass* of the intended boundary is in scope.
- Vulnerabilities in third-party dependencies. Report those upstream; still
  worth telling me if it affects LIDRA's default install.
- Denial of service by flooding a host that is itself running an IDS.

## Security properties LIDRA does have

Stated so you can check them rather than assume them:

| Property | Implementation |
|---|---|
| The IPC socket is not world-writable | Runtime dir, mode `0660 root:lidra`; operators join the `lidra` group (`src/utils/runtime.py`) |
| Firewall actions are attributable | The server resolves the peer uid from the kernel via `SO_PEERCRED` and writes the audit row itself, rather than trusting the client (`src/utils/actor.py`) |
| Own addresses are never blocked | Guard built from `all_local_ipv4()` reading `/proc/net/fib_trie` — every configured address, not only the primary egress IP (`src/utils/interface.py`) |
| LIDRA removes only its own firewall rules | Rules carry the comment tag `lidra_nfqueue` (`src/response/firewall.py`) |
| Secrets need not live in the config file | `LIDRA_SMTP_PASSWORD`, `LIDRA_ABUSEIPDB_KEY`, `LIDRA_VT_KEY` resolve through `utils/paths.resolve_secret` |
| Observations are never persisted or acted on | Severity `info` is gated at the choke point (`src/utils/severity.py`) |
| A failing alert channel cannot stall detection | Per-channel isolation plus a 10 s SMTP timeout; alerts run on the detection worker, so this matters |
| Dry-run writes no kernel rule | Verified in the live harness (`f1_block`) |

## Known weaknesses

Documented rather than hidden — a limitation you know about is not a
vulnerability you are exposed to.

- **The metrics endpoint binds `0.0.0.0` by default** and has no authentication.
  Set `LIDRA_METRICS_HOST=127.0.0.1`, or configure `LIDRA_METRICS_CERT` /
  `LIDRA_METRICS_KEY` for TLS, or front it with a reverse proxy. This is the
  default most likely to surprise someone.
- **The TUI socket's boundary is group membership.** Any process running as a
  member of the `lidra` group can issue block/unblock. Actions are audited with
  the uid, but not otherwise restricted.
- **No rate limiting on the IPC socket.**
- **Webhook alerts send to a URL from configuration** and do not add
  authentication beyond whatever the URL itself contains. Treat a webhook URL as
  a secret.
- **The project has had no independent security review, no fuzzing campaign, and
  no soak test beyond a few hours.** It is a working, tested detector — not a
  hardened product. Do not deploy it as your only line of defence.
- **Dependency versions are floors, not a lockfile** (`requirements.txt` uses
  `>=`), so builds are not bit-reproducible.

## Hardening checklist for a real deployment

1. `response.dry_run: true` first. Watch the TUI for at least a day before letting
   it block.
2. Set `LIDRA_METRICS_HOST=127.0.0.1` unless you specifically want remote scrapes.
3. Review the protected-address list against your own topology. The guard reflects
   what the host can see — a router or resolver reached over a link the host does
   not have an address on will not be in the set.
4. Keep secrets in the environment, not in `config/config.yaml`; that file is
   readable by root and typically committed by mistake.
5. Back up `data/lidra.db` — it is your audit evidence and the uninstaller keeps
   it by design.

[gh-report]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability
