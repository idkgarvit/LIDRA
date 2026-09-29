# Contributing to LIDRA

Thanks for looking. This is a small project with a short set of ground rules, and
they exist because breaking them has cost real debugging time here.

## Getting set up

```bash
git clone https://github.com/idkgarvit/LIDRA.git && cd LIDRA
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-test.txt
.venv/bin/python -m pytest tests/ -q          # expect: 380 passed, 1 skipped
```

You do **not** need root for the test suite. The live-traffic harness uses
unprivileged user namespaces:

```bash
bash tests/live/matrix.sh all
```

## The rules

### 1. Verify, don't restate

If you change behaviour that a document asserts, correct the document **in the
same change**. The README, `docs/ARCHITECTURE.md`, `docs/DETECTION.md` and
`CHANGELOG.md` make specific factual claims; a stale one is worse than a missing
one, because it is actively misleading.

A doc claim is not evidence. Check it against the code before repeating it.

### 2. Say whether a number was measured or inferred

Both are fine. Confusing them is not — and it has happened in this repository.
If you measured it, say how to reproduce it. If you reasoned it out, say that it
is an inference.

### 3. A bug fix comes with a test that fails without it

Not "a test exists" — a test that **fails when you revert the fix**. Verify that
by actually reverting it:

```bash
# apply your fix, write the test, confirm green
git stash            # or comment the fix out
.venv/bin/python -m pytest tests/test_yourfile.py -q     # must FAIL
git stash pop
```

This is not ceremony. There is a test in this repository that asserted a guard
which did not bite, and it was only found by reverting the fix and watching the
suite stay green.

### 4. Never let a test write `data/lidra.db`

It is an operator's evidence history. `tests/conftest.py` points `LIDRA_ROOT` at
a temporary directory, so an attempt raises rather than succeeding. Keep it that
way: if you need a database, ask for the fixture.

### 5. Do not run `install.sh` / `install/uninstall.sh` on a working machine

The uninstaller flushes firewall state and stops the service. Test installer
changes in a VM or a container. If you do run it somewhere, say where in the pull
request.

### 6. Detector fixes go in the detector

If a detector produces false positives, fix the detector. Do **not** widen the
severity filter in `src/utils/severity.py` to suppress them — that hides real
findings along with the noise, and it is how the observation-severity leak
happened in the first place.

The same applies in the other direction: an `info`-severity detection is an
observation and must stay visible to the TUI and metrics even though it is not
persisted. Do not "fix" a noisy observation by deleting it.

### 7. Measure false positives before and after

Any change to a detector can regress the benign budget. The harness enforces an
upper bound per capture from its `.meta.yaml`:

```bash
.venv/bin/python -m pytest tests/test_attack_pcap_replay.py -v -s
```

If your change raises a benign count, either fix the detector or justify the new
budget in the pull request — do not quietly raise the number.

### 8. Commit messages explain the failure

This repository's changelog and history are part of its argument. A commit that
says what changed but not *what was wrong* cannot be reviewed or trusted later.
Include the measurement when you have one.

## What is most useful right now

The highest-value contributions, roughly in order:

1. **Captures for the untested classes.** `docs/DETECTION.md` lists attack
   classes with no capture at all — fragmentation, covert channels, layer 2,
   proxy/VPN, and several others. Generating real traffic for one of these and
   adding a `.pcap` plus its `.meta.yaml` converts a column of "unit-tested only"
   into "replayed end to end".
2. **NBTScan detection.** The one capture in the corpus missed entirely:
   `port_analyzer` models TCP SYN scanning, not UDP/NetBIOS sweeps.
3. **Inline (NFQUEUE) testing on real hardware.** Needs a VM or a second machine;
   it is the least-exercised path in the project.
4. **Named signatures** for the three partially-detected classes: bruteforce
   (currently caught as `session_correlated_*`), Shiro deserialization
   (currently `cookie_injection`), and direction-aware session correlation.

## Reporting a bug

Include:

- what you ran and what you expected;
- what actually happened, with the output;
- whether it is reproducible, and the smallest input that reproduces it;
- if it involves detection quality: the capture or a description of the traffic.

If it is a security issue, see [SECURITY.md](SECURITY.md) instead of opening a
public issue.

## Style

Match the surrounding code. Specifically:

- Type hints on function signatures.
- No new dependencies without a reason in the pull request.
- Handle the failure case rather than letting it propagate into the verdict path:
  a metrics or alerting bug must never cost a packet its verdict.
- Comments explain *why*, not *what*. Where a change fixes a bug, name the bug.

## License

By contributing you agree your work is licensed under the MIT License (see
[LICENSE](LICENSE)).
