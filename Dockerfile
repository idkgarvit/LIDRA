FROM python:3.13-slim-bookworm AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iptables nftables tcpdump nmap curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/lidra
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY config/ config/
COPY lidra .

ENV LIDRA_ROOT=/opt/lidra
ENV PYTHONPATH=/opt/lidra/src

RUN python3 <<'PYEOF'
import sys, os
sys.path.insert(0, 'src')
mods = [
    'detection.dpi_engine', 'detection.ml.anomaly', 'detection.ml.features',
    'bridge.inline_engine', 'soar.engine', 'cli.main', 'tui.app',
    'ebpf.tracer', 'metrics.server',
]
for m in mods:
    __import__(m)
    print(f'  OK  {m}')
print('All imports OK')
PYEOF

FROM base AS production
RUN mkdir -p /opt/lidra/data
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import sqlite3; sqlite3.connect('/opt/lidra/data/lidra.db').execute('SELECT 1')" || exit 1
CMD ["python3", "-m", "src.lidra_agent_v3"]

FROM base AS demo
CMD ["python3", "-m", "src.tui.app", "--demo"]

FROM base AS test
COPY Dockerfile Dockerfile
COPY tests/ tests/
COPY demo/ demo/
RUN python3 -m pytest tests/ -q --tb=short
CMD ["python3", "-m", "pytest", "tests/", "-v", "--tb=short"]
