# Safe Link — why LIDRA can't take your network down

LIDRA's local (laptop) mode has exactly one dangerous capability: it can put a
kernel-level queue rule on the host's own inbound path. Everything else it does
is observation or an iptables/nftables drop rule, both of which are recoverable
in one command. The queue rule is not — if it is wrong, the machine loses
connectivity and the operator cannot look up how to fix it.

This document records what was measured, what changed, and what the remaining
limits are.

## Measured failure modes

Reproduced on Kali GNU/Linux rolling, kernel `7.1.5+kali-amd64`, WiFi `wlan0`,
2026-09-12. Harness: `/tmp/lidra_outage_test.sh` (adds and removes rules with a
failsafe `trap`).

| Rule installed | Consumer bound? | `curl https://1.1.1.1` | `ping 192.168.1.1` |
|---|---|---|---|
| `queue num 0 bypass` | yes | 0.08 s | replies |
| `queue num 0 bypass` | no (agent SIGKILLed) | 0.08 s | replies |
| `queue num 0` (no bypass) | no | **3.0 s → timeout** | **no replies** |
| (rule deleted) | — | 0.07 s | replies |

Delete the rule and connectivity returns immediately. This confirms the
mechanism behind the reported "LIDRA disconnected the internet" / "internet
dropping" behaviour, which was originally observed while running inside a VM.

**The mechanism, precisely:** an NFQUEUE rule parks every matching packet in a
kernel queue until a userspace listener returns a verdict. With no listener and
no `bypass` flag, nothing ever answers, so the packets are never delivered or
rejected — they simply stop. This is a property of netfilter, not of LIDRA's
code, but LIDRA is the thing installing the rule.

Wireless makes it worse in a way that matters for a laptop: the queue rule sits
on `wlan0`, so the operator is cutting the physical link they would use to
download a fix. There is no "reconnect on Ethernet" escape hatch.

## What the fix does

### 1. Inline interception is opt-in, and the default is monitor-only

`local.inline` ships `false`. A plain `lidra` / `sudo python3
src/lidra_agent_v3.py` start captures with AF_PACKET, detects, and blocks
attacker IPs with persistent firewall rules — it never installs a queue rule.
Inline interception needs an explicit `--local-inline` or `local.inline: true`.

This costs something real and it should be stated plainly: AF_PACKET cannot
drop the packet that carried the attack, only subsequent packets from that
source. LIDRA blocks the attacker one packet late. That trade is deliberate —
first-packet interception is not worth a support burden where the fix
instructions are unreachable while the problem exists.

### 2. No LIDRA rule can be built without `bypass`

`bridge/safe_link.py:always_bypass()` appends the flag to any `queue` rule
LIDRA constructs, and `tests/test_bridge.py::TestQueueRuleAlwaysBypass`
inspects the actual command list passed to `subprocess.run` to prove it. A
crash, a SIGKILL, an OOM-kill or a traceback in the bind path therefore fails
**open**: the kernel lets packets through and the operator keeps working.

### 3. A guard that notices when protection silently stops

`bridge/safe_link.py:SafeLink` is armed only after the netlink consumer has
successfully bound (`InlineEngine._run_nfqueue_capture`). Every 5 seconds it
checks two things:

- **Is the queue rule still in the ruleset?** Another firewall manager, an
  `nft flush ruleset`, a `docker` restart or a manual `iptables -F` can remove
  it. If it is gone, LIDRA is no longer inspecting traffic. The guard logs
  CRITICAL and dispatches an alert rather than continuing to report "running".
- **Does the queue still have a consumer?** `/proc/net/netfilter/nfnetlink_queue`
  empty while our rule is present means the rule now depends entirely on
  `bypass`.

The guard does not re-add rules and does not drop anything. It reports and
fails open; re-arming is an operator decision. Silently degrading from "IPS" to
"a process that is up" is the failure mode that makes a security tool worse
than useless, because it is trusted.

### 4. Stale rules from a previous crash are cleared before install

`_setup_nfqueue_nft()` deletes any existing `lidra_nfqueue` table before
creating its own, so a killed agent's leftover rule is not stacked on top of a
new one.

## Residual risk (honest list)

- **Kernel crash window.** Between `nft add rule` and the netlink `BIND` there
  is a window of milliseconds where the rule exists and no consumer does. That
  is survivable only because the rule carries `bypass`. Making it airtight
  requires creating the rule from inside the same netlink transaction that
  binds the queue, which means replacing the `nft` CLI calls with direct
  `nfnetlink_queue`/`nf_tables` messages. Not done yet.
- **`bypass` availability.** `--queue-bypass` (iptables) and the `bypass` queue
  flag (nftables) are modern-kernel features. LIDRA checks the command's return
  code and will only claim setup succeeded if the flagged rule was accepted,
  but on an old kernel the failure of *both* forms is only a warning in the
  log, not a refusal to run. A kernel-version preflight check is still to do.
- **The guard is a reporter, not a circuit breaker.** It deliberately does not
  auto-remove rules or auto-restore. If the automatic response is wanted, the
  watchdog should own an explicit `rollback` path with its own tests.
- **No connectivity probe is wired in yet.** `SafeLink.probe_connectivity()`
  exists but is not called in the guard loop: a false "network is down"
  reading would itself trigger a rollback and mask real outages. Wiring it in
  needs a baseline check at arm time so "was already offline" is
  distinguishable from "went offline because of us".
- **Bridge (gateway) mode is untested on this hardware.** The same rule logic
  applies on the `bridge` family FORWARD hook, but the failure mode differs —
  a gateway that stops forwarding takes down other people's machines, not the
  operator's. It needs its own test before any claim is made about it, and it
  should stay behind `mode: inline`, which is already explicit.
