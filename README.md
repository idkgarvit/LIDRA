# LIDRA - Production Intrusion Detection System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

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
# Clone repository
git clone https://github.com/idkgarvit/LIDRA.git
cd LIDRA

# Install dependencies
pip install -r requirements.txt

# Configure (edit with your API keys/webhooks)
nano config/config.yaml

# Run LIDRA
python src/lidra_agent_v3.py
```

Dashboard available at `http://localhost:8080`

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
mode: production  # development (60s) or production (300s)

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

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/stats` | Attacker statistics |
| `GET /api/attackers` | List of attackers |
| `GET /api/recent-attacks` | Recent attack events |
| `GET /api/honeypot-sessions` | Honeypot session data |
| `POST /api/block` | Manually block an IP |

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

# Access dashboard
open http://localhost:8080
```

## Testing

```bash
# Run test suite
pytest tests/ -v

# Simulate SSH attack (test detection)
for i in {1..6}; do
  echo "Failed password from 192.168.1.100" >> /var/log/auth.log
done

# Check dashboard for new attacker
curl http://localhost:8080/api/stats
```

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
pip install fastapi uvicorn
python -m src.dashboard.main
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
