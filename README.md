# LIDRA - Production Intrusion Detection System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/idkgarvit/LIDRA/actions/workflows/ci.yml/badge.svg)](https://github.com/idkgarvit/LIDRA/actions/workflows/ci.yml)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker)](https://github.com/idkgarvit/LIDRA/pkgs/container/lidra)
[![Prometheus](https://img.shields.io/badge/metrics-prometheus-E6522C?logo=prometheus)](config/prometheus.yml)

**Lightweight Intrusion Detection and Response with Adaptive Deception**

LIDRA is a production-ready honeypot-based intrusion detection system designed for real-world deployment. It combines active deception with intelligent threat detection and automated response.

## Features

- **Real-time Detection** - Monitors auth.log, syslog, web servers, databases, email, FTP
- **Comprehensive Attack Coverage:**
  - SSH: Bruteforce, invalid users, connection floods
  - Web: SQL injection, XSS, path traversal, LFI/RFI, command injection, scanner probes
  - Database: MySQL, PostgreSQL, MongoDB, Redis unauthorized access
  - Email: SMTP, IMAP, POP3 brute force attacks
  - FTP: Login failures, anonymous access attempts
  - Network: Port scans, service probes
  - Exploit: Shellshock, Log4j, CVE signatures
  - Privilege: sudo/su failures
- **Threat Intelligence** - AbuseIPDB and VirusTotal integration for IP reputation
- **Instant Alerting** - Slack, Discord, and Email notifications
- **Automated Response** - iptables/nftables blocking with TTL
- **Live Dashboard** - Web UI with real-time attack monitoring
- **Docker Ready** - Full containerization support

## Quick Start

```bash
# One command — asks: laptop shield or company gateway? (non-interactive: --laptop | --gateway)
curl -fsSL https://github.com/idkgarvit/LIDRA/raw/main/install.sh | sudo bash

# Configure (edit with your API keys/webhooks)
sudo nano /opt/lidra/config/config.yaml

# Watch it live (no sudo needed)
cd /opt/lidra/src && LIDRA_TUI_SOCKET=$(ls -t /tmp/lidra_tui_*.sock | head -1) \
  PYTHONPATH=. python3 -m tui.app --standalone
```

Manual run instead of the service:

```bash
sudo -E python3 src/lidra_agent_v3.py --tui
```

Dashboard: TUI mode (run with `--tui`).

## Configuration & Secrets

Set these via environment variables or `config/config.yaml`:

| Variable | Config Path | Required | Purpose |
|----------|-------------|----------|---------|
| `LIDRA_ABUSEIPDB_KEY` | `threat_intel.abuseipdb_api_key` | No | IP reputation lookups |
| `LIDRA_VT_KEY` | `threat_intel.virustotal_api_key` | No | VirusTotal enrichment |
| `LIDRA_SMTP_PASSWORD` | `alerts.email.password` | No | SMTP password for email alerts |
| `SLACK_WEBHOOK` | `alerts.slack_webhook` | No | Slack alert notifications (in YAML config) |
| `DISCORD_WEBHOOK` | `alerts.discord_webhook` | No | Discord alert notifications (in YAML config) |
| `LIDRA_METRICS_PORT` | — | No | Prometheus metrics port (default: 8080) |
| `LIDRA_METRICS_HOST` | — | No | Metrics bind address (default: `0.0.0.0`; use `127.0.0.1` for localhost-only) |
| `LIDRA_METRICS_CERT` | — | No | TLS cert path for metrics endpoint |
| `LIDRA_METRICS_KEY` | — | No | TLS key path for metrics endpoint |
| `LIDRA_DRY_RUN` | `response.dry_run` | No | Dry-run mode (`1` = no actual blocking) |
| `LIDRA_LOG_LEVEL` | `general.verbose` | No | Set `DEBUG` for verbose logging |

> **Security:**
> - Never commit API keys or webhooks to version control. Use environment variables or `.env` in production.
> - The metrics endpoint (`:8080`) listens on all interfaces. In production, either:
>   - Set `LIDRA_METRICS_CERT` + `LIDRA_METRICS_KEY` for TLS, **or**
>   - Bind to localhost only (`LIDRA_METRICS_HOST=127.0.0.1`), **or**
>   - Use a reverse proxy (nginx) in front of the agent.
> - Agent ↔ TUI IPC uses a Unix socket (`/tmp/lidra_tui_<pid>.sock`) — local-only, no TLS needed.
> - Docker Compose inter-container traffic is on an isolated bridge network.

## Demo (60 seconds)

End-to-end demo of three real attacks (SQL injection, port scan,
DNS tunnel). See **[DEMO.md](DEMO.md)** for the walkthrough.

```bash
# Terminal 1: start the TUI
sudo -E python3 src/lidra_agent_v3.py --tui

# Terminal 2: run the demo (starts vuln_server, fires 3 attacks)
./demo/run_all.sh
```

## Architecture

```
+-------------------------------------------------------------+
|                      LIDRA Core                              |
+-------------+-------------+-------------+-------------------+
|  Detection  |  Deception  |   Response  |    Alerting       |
|  - Log parse|  - Cowrie   |  - iptables |  - Slack          |
|  - Multi-src|  - Honeyfile|  - fail2ban |  - Discord        |
|  - Enrich   |  - Canary   |  - Block TTL|  - Email          |
+-------------+-------------+-------------+-------------------+
                            |
                    +-------v-------+
                    |   SQLite DB   |
                    |  - Attackers  |
                    |  - Sessions   |
                    |  - Alerts     |
                    +---------------+
```

## Configuration

### Key Settings (config/config.yaml)

```yaml
mode: local  # 'local' (this machine) | 'inline' (gateway bridge) | 'monitor' (legacy)

database:
  path: ./data/lidra.db
  cleanup_days: 30

detection:
  log_sources:
    - /var/log/auth.log
    - /var/log/syslog
    - /var/log/apache2/access.log
    - /var/log/nginx/access.log
    - /var/log/mysql/error.log

threat_intel:
  abuseipdb_api_key: "your-key"  # Get at abuseipdb.com
  virustotal_api_key: "your-key"  # Get at virustotal.com
  check_on_detect: true
  auto_report: true

alerts:
  slack_webhook: "https://hooks.slack.com/..."
  discord_webhook: "https://discord.com/api/webhooks/..."

response:
  dry_run: true  # TRUE = demo, FALSE = real blocking
  firewall: iptables
  block_ttl_seconds: 3600
```

## Monitoring

LIDRA has no REST API — live state lives in the TUI (run with `--tui`)
and machine-readable metrics on the Prometheus endpoint:

| Surface | Address | Description |
|---------|---------|-------------|
| `GET /metrics` | `:8080` (or `LIDRA_METRICS_PORT`) | Prometheus counters/gauges (packets, attacks, blocks) |
| TUI dashboard | `--tui` | Attackers, recent attacks, honeypot sessions, manual block/unblock |
| `lidra-cli` | `python -m cli.main` (from `src/`) | Interactive shell (`block`, `unblock`, `status`) |

## Project Structure

```
LIDRA/
├── config/           # Configuration files
├── data/             # SQLite database
├── docs/             # Documentation
├── docker/           # Docker configuration
├── logs/             # Log files
├── src/
│   ├── alerts/       # Alerting system (Slack, Discord, Email)
│   ├── bridge/       # Inline gateway / NFQUEUE bridge mode
│   ├── cli/          # `lidra` command-line entry point
│   ├── core/         # Docker-internal honeypot orchestration
│   ├── dashboard/    # Text-based CLI dashboard (cli.py)
│   ├── database/     # SQLite database layer
│   ├── detection/    # Attack detection engine
│   ├── honeypot/     # Honeyfiles + deception assets
│   ├── intel/        # Threat intelligence
│   ├── response/     # Firewall/response mechanisms
│   ├── utils/        # Utility modules
│   └── lidra_agent_v3.py  # Main orchestrator
├── state/            # State files
└── tests/            # Test suite
```

## Installation Guide

### System Requirements

- Python 3.10+
- Linux (Ubuntu 22.04, Debian 12, Kali)
- 2GB RAM minimum
- Root/sudo access for firewall features

### Quick Install

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install system packages
sudo apt install -y iptables inotify-tools curl jq

# Create directories
mkdir -p data logs state

# Test installation
python src/lidra_agent_v3.py
```

### Docker Deployment

```bash
# Build and run
docker-compose up -d

# View logs
docker logs -f lidra-core

# Metrics endpoint (the visual dashboard is the TUI: sudo python src/lidra_agent_v3.py --tui)
open http://localhost:8080/metrics
```

## Testing

```bash
# Run test suite (test deps are separate from the production install)
pip install -r requirements-test.txt
pytest tests/ -v

# Simulate SSH attack (test detection)
for i in {1..6}; do
  echo "Failed password from 192.168.1.100" >> /var/log/auth.log
done

# Check metrics for the new attacker
curl -s http://localhost:8080/metrics | grep lidra_attacks_total
```

## Deployment

### Docker (single service)
```bash
docker build --target production -t lidra:latest .
docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=SYS_ADMIN \
  -p 8080:8080 lidra:latest
```

### Docker Compose (full stack with monitoring)
```bash
docker compose up -d
# Agent metrics:  http://localhost:8080/metrics
# Prometheus:     http://localhost:9090
# Grafana:        http://localhost:3000 (admin/admin)
# Vuln server:    http://localhost:8081
```

### Recommended: agent on host, monitoring in Docker
The agent sees real traffic, host logs, and the host firewall only when it
runs bare-metal — a container on the compose bridge network sees (and can
block) almost nothing. So run the sensor on the host and keep Prometheus +
Grafana as a sidecar that scrapes it (graphs lag ~15s; alerts and blocks
still fire instantly inside the agent):
```bash
sudo systemctl enable --now lidra   # or: sudo -E python3 src/lidra_agent_v3.py --tui
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d prometheus grafana
# Grafana: http://localhost:3000 (admin/admin), scraping the host agent
```

### Hot-Reload
Config is reloaded on `SIGHUP` without restart:
```bash
kill -HUP $(cat /var/run/lidra/lidra.pid 2>/dev/null || cat state/lidra.pid)
```

### CI/CD
Every push runs lint, tests across Python 3.11–3.13, config validation, and a Docker build check via GitHub Actions.

## Troubleshooting

### Database errors
```bash
rm data/lidra.db
python -c "from database.db import LIDRADatabase; LIDRADatabase('data/lidra.db')"
```

### Firewall permission denied
```bash
sudo python src/lidra_agent_v3.py
```

### Dashboard not starting
```bash
sudo -E python3 src/lidra_agent_v3.py --tui
# or read-only, without starting the agent:
./lidra dashboard
```

## License

MIT License - see LICENSE file

## Author

**Garvit Kanojia**

This project was developed as part of a Masters thesis in Cybersecurity.

## Acknowledgments

- Cowrie honeypot team
- AbuseIPDB for threat data
- VirusTotal API
