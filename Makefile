# LIDRA v3 Makefile
# Easy build and run commands

.PHONY: help build run stop clean test docker-build docker-run docker-stop

help:
	@echo "LIDRA v3 - eBPF-Powered Detection System"
	@echo ""
	@echo "Available targets:"
	@echo "  make build          - Build LIDRA from source"
	@echo "  make run            - Run LIDRA directly"
	@echo "  make test           - Run tests"
	@echo "  make docker-build   - Build Docker image"
	@echo "  make docker-run     - Run in Docker"
	@echo "  make docker-stop    - Stop Docker container"
	@echo "  make clean          - Clean data/logs"

build:
	@echo "Building LIDRA v3..."
	python3 -m py_compile src/lidra_agent_v3.py
	@echo "Build complete"

run:
	@echo "Starting LIDRA v3..."
	python3 src/lidra_agent_v3.py

test:
	@echo "Running tests..."
	pytest tests/ -v

docker-build:
	@echo "Building Docker image..."
	docker build -f docker/Dockerfile -t lidra-v3:latest .

docker-run:
	@echo "Starting LIDRA in Docker..."
	docker-compose -f docker/docker-compose.yaml up -d

docker-logs:
	docker-compose -f docker/docker-compose.yaml logs -f

docker-stop:
	@echo "Stopping LIDRA..."
	docker-compose -f docker/docker-compose.yaml down

clean:
	@echo "Cleaning data and logs..."
	rm -rf data/*.db
	rm -rf logs/*.log
	rm -rf state/*
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

install:
	@echo "Installing dependencies..."
	pip install -r requirements.txt

check-deps:
	@echo "Checking system dependencies..."
	@which python3 >/dev/null 2>&1 || echo "ERROR: Python3 not found"
	@which docker >/dev/null 2>&1 || echo "WARNING: Docker not found"
	@which iptables >/dev/null 2>&1 || echo "WARNING: iptables not found"

.DEFAULT_GOAL := help