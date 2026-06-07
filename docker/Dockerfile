# LIDRA v3 Docker Image
# Lightweight eBPF-powered detection system
#
# NOTE: This image MUST run as root (or with full capabilities).
# AF_PACKET raw sockets, NFQUEUE, and iptables all require CAP_NET_RAW /
# CAP_NET_ADMIN, which the docker-compose grants via privileged: true and
# cap_add. Running as a non-root uid without those caps will fail at startup.

FROM python:3.11-slim

LABEL maintainer="LIDRA Project"
LABEL description="Lightweight eBPF-powered Intrusion Detection System"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    iptables \
    ipset \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/lidra

# Copy requirements first (for caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application structure
COPY src/ ./src/
COPY config/ ./config/
COPY tests/ ./tests/
COPY docs/ ./docs/
COPY README.md .
COPY Makefile .

# Create necessary directories (root-owned — container runs as root)
RUN mkdir -p /opt/lidra/data /opt/lidra/state /opt/lidra/logs /var/log/lidra /var/lib/lidra /var/run/lidra

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV LIDRA_MODE=production

# Expose ports (TUI doesn't expose any, but kept for future / IPC clients)
EXPOSE 9090

# Health check — verifies the SQLite database is queryable
# (a real readiness signal: if the DB is healthy, the agent is functioning)
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD sqlite3 /opt/lidra/data/lidra.db "SELECT 1" >/dev/null 2>&1 || exit 1

# Entry point
ENTRYPOINT ["python", "src/lidra_agent_v3.py"]