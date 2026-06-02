# Recursive Sinkhole — Feature Design

## Goal
Extend LIDRA's deception layer with a **TCP tarpit** — when a scanner/fuzzer is detected from an IP, redirect their traffic into a slow-response sinkhole that wastes their resources and collects intel.

## Files to create
- `src/honeypot/tarpit.py` — asyncio TCP tarpit listener
- `src/honeypot/manager.py` — lifecycle (deploy/undeploy sinkhole + iptables REDIRECT rules)

## Files to modify
- `src/response/firewall.py` — add `redirect_to_tarpit(ip, port)` / `remove_redirect(ip)` methods alongside existing `block_ip`/`unblock_ip`
- `src/detection/attack_detector.py` — add `_check_fuzzer_pattern()` heuristic (same IP, ≥50 unique ports in 60s, or ≥1000 packets/min, or ≥3 sentinel-style alerts)
- `src/database/schema.sql` — add `sinkhole_sessions` table
- `src/database/db.py` — add CRUD methods for sinkhole sessions
- `src/dashboard/main.py` — add `/api/tarpit-stats` route + tarpit section in dashboard HTML
- `src/response/` pipeline in `lidra_agent_v3.py` — when fuzzer detected with confidence ≥0.85, auto-deploy tarpit instead of DROP

## Tarpit mechanics
1. Listen on port 9999 (or configurable)
2. On SYN → SYN-ACK with window=1
3. Send 1 byte every 2–3s
4. Log: src_ip, dst_port, bytes_received, duration
5. Timeout and close after 5–30 min
6. For UDP: read and log, send nothing back

## iptables rules
```bash
# Instead of: -A LIDRA_BLOCK -s <ip> -j DROP
iptables -t nat -A PREROUTING -s <ip> -p tcp -j REDIRECT --to-port 9999
```

## Auto-detection
New `fuzzer_detected` attack type in `attack_detector.py`:
- ≥50 unique dst ports from same IP in 60s ← port scan / fuzzer
- OR ≥1000 packets from same IP in 60s ← unthrottled fuzzer  
- OR IP triggers ≥3 distinct attack types in 300s ← multi-vector scanning

## Dashboard additions
- Right-panel or page section: "Active Sinkholes" with per-IP cards showing:
  - IP address
  - Bytes sunk
  - Packets captured
  - Sessions active
  - Duration
  - [RELEASE] button
- Chart: bytes sunk over time
