# LIDRA v3 Docker Image
# Lightweight eBPF-powered detection system

FROM python:3.11-slim

LABEL maintainer="LIDRA Project"
LABEL description="Lightweight eBPF-powered Intrusion Detection System"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    iptables \
    ipset \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -s /bin/bash lidra && \
    mkdir -p /opt/lidra && \
    chown -R lidra:lidra /opt/lidra

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

# Create necessary directories
RUN mkdir -p /opt/lidra/data /opt/lidra/state /opt/lidra/logs /var/log/lidra /var/lib/lidra && \
    chown -R lidra:lidra /opt/lidra /var/log/lidra /var/lib/lidra

# Switch to non-root user
USER lidra

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV LIDRA_MODE=production

# Expose dashboard port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/api/stats || exit 1

# Entry point
ENTRYPOINT ["python", "src/lidra_agent_v3.py"]