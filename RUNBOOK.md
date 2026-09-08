# LIDRA Operations Runbook

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Deployment](#deployment)
3. [Startup / Shutdown](#startup--shutdown)
4. [Config Hot-Reload](#config-hot-reload)
5. [Monitoring & Metrics](#monitoring--metrics)
6. [Alerting](#alerting)
7. [Common Procedures](#common-procedures)
8. [Troubleshooting](#troubleshooting)
9. [Disaster Recovery](#disaster-recovery)

---

## Architecture Overview

```
┌─────────────┐     ┌─────────────┐     ┌──────────────┐
│  eBPF / Log  │────▶│  Detection  │────▶│  Response     │
│  Collectors  │     │  Pipeline   │     │  (Firewall)   │
└─────────────┘     └──────┬──────┘     └──────────────┘
                           │
                    ┌──────▼──────┐
                    │   Database  │
                    │   (SQLite)  │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │  Metrics  │ │  TUI     │ │  CLI     │
        │ /metrics  │ │ Dashboard│ │ Dashboard│
        └──────────┘ └──────────┘ └──────────┘
```

## Deployment

### Docker Compose (recommended)
```bash
# Start full stack
docker compose up -d

# Check logs
docker compose logs -f lidra-agent

# Scale detection workers
docker compose up -d --scale lidra-agent=2
```

### Manual (bare metal)
```bash
sudo python3 src/lidra_agent_v3.py
# or
lidra
```

## Startup / Shutdown

| Action | Command |
|--------|---------|
| Start agent | `sudo python3 src/lidra_agent_v3.py` |
| Start with TUI | `PYTHONPATH=src python3 -m tui.app` |
| Graceful stop | `Ctrl+C` or `kill -TERM <pid>` |
| Force stop | `kill -9 <pid>` |
| Check status | `systemctl status lidra` (if installed) |

## Config Hot-Reload

LIDRA reloads config on `SIGHUP` without restarting the process:

```bash
kill -HUP $(cat /var/run/lidra/lidra.pid 2>/dev/null || cat state/lidra.pid)
```

This re-reads the central YAML config and re-initializes:
- Threat intelligence providers
- Alerting channels
- Firewall dry-run mode
- Blocklist rules

**Note:** Changing `mode` (inline ↔ local) still requires a full restart.

## Monitoring & Metrics

Prometheus metrics are available at `http://<host>:8080/metrics`.

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `lidra_packets_total` | Counter | Packets processed, by verdict (pass/drop) |
| `lidra_attacks_total` | Counter | Attacks detected, by type & severity |
| `lidra_blocks_total` | Counter | IPs blocked, by method |
| `lidra_active_connections` | Gauge | Currently tracked connections |
| `lidra_cpu_percent` | Gauge | Agent CPU usage |
| `lidra_memory_percent` | Gauge | Agent memory usage |
| `lidra_packet_rate` | Gauge | Packets processed per second |
| `lidra_throughput_mbps` | Gauge | Throughput in Mbps |
| `lidra_detection_latency_seconds` | Histogram | Detection latency distribution |

### Grafana Dashboard

1. Start stack: `docker compose up -d`
2. Open http://localhost:3000 (admin/admin)
3. Add Prometheus data source → `http://prometheus:9090`
4. Import dashboard or create panels from the metrics above

## Alerting

### Prometheus Alertmanager

Alerting rules are in `config/alerting_rules.yml`. Deploy with:

```yaml
# docker-compose override for Alertmanager
alertmanager:
  image: prom/alertmanager:latest
  ports: ["9093:9093"]
  volumes:
    - ./config/alertmanager.yml:/etc/alertmanager/alertmanager.yml
  depends_on: [prometheus]
```

### Notifications (Slack/Discord)

Configure in `config/config.yaml`:
```yaml
alerts:
  slack_webhook: "https://hooks.slack.com/..."
  discord_webhook: "https://discord.com/api/webhooks/..."
```

### Critical Alerts

| Severity | Response |
|----------|----------|
| **critical** | Attack rate >10 critical/min — page on-call, investigate immediately |
| **warning** | High CPU/memory — check for resource leaks or DoS |
| **info** | Routine detection — review in daily triage |

## Common Procedures

### View live attacks
```bash
PYTHONPATH=src python3 -m tui.app --standalone
```

### Inspect blocked IPs
```bash
sudo iptables -L LIDRA -n
# or for nftables:
sudo nft list set inet filter lidra_blocklist
```

### Manually unblock an IP
```bash
# iptables
sudo iptables -D LIDRA -s <IP> -j DROP

# nftables
sudo nft delete element inet filter lidra_blocklist { <IP> }
```

### Check database stats
```bash
PYTHONPATH=src python3 -c "
from database.db import LIDRADatabase
db = LIDRADatabase('data/lidra.db')
print('Attackers:', db.get_attacker_count())
print('Attacks:', db.get_attack_count())
print('Alerts:', db.get_alert_count())
"
```

### Enable verbose logging
```bash
export LIDRA_LOG_LEVEL=DEBUG
sudo -E python3 src/lidra_agent_v3.py
```

## Troubleshooting

### Agent won't start
```bash
# Check root
[ $(id -u) = 0 ] || echo "Must be root"

# Check config syntax
PYTHONPATH=src python3 -c "from utils.config_loader import load_config; print(load_config())"

# Check PID file (falls back to state/ for unprivileged runs)
cat /var/run/lidra/lidra.pid 2>/dev/null || cat state/lidra.pid 2>/dev/null || echo "No PID file"
```

### High CPU usage
1. Check `lidra_cpu_percent` in Prometheus
2. Reduce log verbosity: `export LIDRA_LOG_LEVEL=WARNING`
3. Increase main loop sleep: set `main_loop.cycle_seconds` to 120
4. Scale horizontally with Docker Compose

### Database corruption
```bash
# Backup current
cp data/lidra.db data/lidra.db.bak

# Reset
rm data/lidra.db
PYTHONPATH=src python3 -c "from database.db import LIDRADatabase; LIDRADatabase('data/lidra.db')"
```

### Metrics not showing
```bash
curl http://localhost:8080/metrics  # should return text
# If empty: check prometheus_client is installed
pip install prometheus-client
```

### No detections
1. Check config has `mode` set correctly
2. Monitor logs: `tail -f logs/lidra_v3.log`
3. Test with a manual attack: `nmap -sS <target>`
4. Check whitelist in config

## Disaster Recovery

### Full data loss
```bash
# Restore from backup
cp data/lidra.db.bak data/lidra.db

# Or re-deploy with persistent volumes
docker compose down -v  # WARNING: destroys volumes
docker compose up -d
```

### Agent crash loop
```bash
# Check recent logs
journalctl -u lidra --since "5 minutes ago"

# Run in foreground with debug
sudo env LIDRA_LOG_LEVEL=DEBUG python3 src/lidra_agent_v3.py

# Reset state
rm -rf state/* logs/*
```

### Network bridge broken
```bash
# Teardown and re-create bridge
sudo nft flush ruleset
sudo ip link delete br_lidra 2>/dev/null
sudo python3 src/lidra_agent_v3.py
```

---

**Maintainer:** Garvit Kanojia  
**Repository:** https://github.com/idkgarvit/LIDRA
