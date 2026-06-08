#!/usr/bin/env python3
"""
Scale benchmark for LIDRA — simulates high-throughput attack traffic.
Usage:
  python3 bench/scale.py [--packets 100000] [--rate 1000] [--duration 30]
"""

import time, sys, os, random, argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

THREAT_IPS = [
    "10.0.0.1", "10.0.0.2", "10.0.0.3", "192.168.1.100", "192.168.1.200",
    "172.16.0.50", "172.16.0.51", "203.0.113.1", "203.0.113.2", "198.51.100.1",
]
ATTACK_TYPES = [
    "port_scan", "ssh_bruteforce", "sql_injection", "xss", "path_traversal",
    "dns_tunnel", "command_injection", "http_flood", "syn_flood", "log4j_scan",
]
SEVERITIES = ["low", "medium", "high", "critical"]


def simulate_packets(count: int, rate: int):
    """Synthetic event generation at given packet/sec."""
    from lidra_agent_v3 import LIDRAv3
    from utils.config_loader import load_config

    config = load_config()
    config["mode"] = "local"
    config["response"]["dry_run"] = True
    agent = LIDRAv3(config)
    agent.running = True

    interval = 1.0 / rate if rate > 0 else 0
    processed = 0
    start = time.time()
    errors = 0

    print(f"Benchmark: {count} synthetic events @ {rate} pkts/sec")
    print(f"{'Progress':>10} | {'Elapsed':>10} | {'Rate':>10} | {'Errors':>8}")
    print("-" * 45)

    for i in range(count):
        t0 = time.perf_counter()
        try:
            fake_event = {
                "dst_ip": random.choice(THREAT_IPS),
                "ip_address": random.choice(THREAT_IPS),
                "raw_data": {
                    "attack": {
                        "attack_type": random.choice(ATTACK_TYPES),
                        "severity": random.choice(SEVERITIES),
                        "mitre": ["T1595"],
                        "details": {"msg": f"benchmark event {i}"},
                    }
                },
            }
            agent._on_security_event(type("obj", (object,), fake_event))
            processed += 1
        except Exception:
            errors += 1

        elapsed = time.time() - start
        if interval > 0:
            sleep = interval - (time.perf_counter() - t0)
            if sleep > 0:
                time.sleep(sleep)

        if (i + 1) % max(1, count // 20) == 0:
            current_rate = (i + 1) / elapsed if elapsed > 0 else 0
            print(f"{i+1:>8,} | {elapsed:>8.2f}s | {current_rate:>8.0f}/s | {errors:>8}")

    total_time = time.time() - start
    print("-" * 45)
    print(f"Done: {processed:,} events in {total_time:.2f}s ({processed/total_time:,.0f} pkts/sec)")
    print(f"Errors: {errors}")

    agent.stop()
    return processed, total_time


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LIDRA scale benchmark")
    parser.add_argument("--packets", type=int, default=50000, help="Number of synthetic events")
    parser.add_argument("--rate", type=int, default=0, help="Target packet rate (0 = max)")
    args = parser.parse_args()
    simulate_packets(args.packets, args.rate)
