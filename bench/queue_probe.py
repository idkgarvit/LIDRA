#!/usr/bin/env python3
"""Can an attack outrun LIDRA's detection worker?

`agent_base._on_detection_callback` does `put_nowait` on a `queue.Queue()` with
no maxsize. An unbounded queue never raises, so when the worker cannot keep up
with the detection rate the queue grows without limit — the sensor loses memory
during exactly the event it exists to handle. Each event also does an
add_attacker() SELECT+UPDATE against SQLite on the worker thread.

This measures both sides:
  * supply  — detection events/second a flood produces
  * drain   — events/second the worker + SQLite can consume
"""
import os
import queue
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from database.db import LIDRADatabase

DB = "/tmp/lidra_queue_probe.db"
for suffix in ("", "-wal", "-shm"):
    try:
        os.unlink(DB + suffix)
    except FileNotFoundError:
        pass

db = LIDRADatabase(DB)

# --- drain rate: what one worker can actually consume -----------------------
N = 3000
processed = 0
done = threading.Event()
q = queue.Queue()


def worker():
    global processed
    while True:
        item = q.get()
        try:
            if item is None:
                return
            src = item["src"]
            aid = db.add_attacker(src, country="", org="")
            # dedupe=False: the default dedupes (ip, type) pairs, which hides
            # the real write cost. Worst case is all-unique events.
            db.record_attack(aid, item["type"], source_log="bridge_inline",
                             raw_line="x" * 200, severity=item["sev"],
                             dedupe=False)
            processed += 1
        finally:
            q.task_done()


t = threading.Thread(target=worker, daemon=True)
t.start()

start = time.time()
for i in range(N):
    q.put({"src": f"203.0.113.{i % 250}", "type": "syn_flood",
           "sev": "high", "ts": time.time()})
enqueue_elapsed = time.time() - start

# wait for drain
while q.qsize() > 0:
    time.sleep(0.05)
drain_elapsed = time.time() - start
q.put(None)

print(f"events enqueued:        {N}")
print(f"enqueue time:           {enqueue_elapsed:.3f}s "
      f"({N/max(enqueue_elapsed,1e-9):.0f} events/s ingest capacity)")
print(f"worker drain time:      {drain_elapsed:.3f}s "
      f"({N/max(drain_elapsed,1e-9):.0f} events/s)")
print(f"processed:              {processed}")

# --- supply rate: events a flood produces -----------------------------------
# From the live run: the syn_flood detector fires on every SYN in the window,
# and the engine measured ~17,000 pps on this hardware for that pcap.
PPS = 17000
print()
print(f"a 17k pps SYN flood produces ~{PPS} detection events/s (1 per SYN)")
print(f"worker sustains              ~{N/max(drain_elapsed,1e-9):.0f} events/s")
backlog = PPS - (N / max(drain_elapsed, 1e-9))
if backlog > 0:
    print(f"net queue growth             ~{backlog:,.0f} events/s")
    print(f"per minute of attack         ~{backlog*60:,.0f} queued events")
    print("VERDICT: worker cannot keep up — unbounded queue grows without limit")
else:
    print(f"headroom                     ~{-backlog:,.0f} events/s")
    print("VERDICT: worker outruns this flood; unbounded queue is not the "
          "bottleneck at this rate")

# --- prove the queue is unbounded -------------------------------------------
u = queue.Queue()
added = 0
try:
    for _ in range(2_000_000):
        u.put_nowait({})
        added += 1
except queue.Full:
    pass
print()
print(f"unbounded put_nowait accepted: {added:,} items with no exception")
print(f"queue object maxsize:          {u.maxsize} (0 = unlimited)")

db.close()
