# LIDRA Makefile - Cross-distro XDP build system
# Works on Debian, Ubuntu, Kali, Fedora, Arch, etc.

# ponytail: `pytest`/`lint` run the Python suite (CI parity) — `test` is the
# hardware XDP drop test and needs sudo + a NIC.
.PHONY: all build clean test pytest lint run stop unload status block unblock install-deps verify help install uninstall

pytest:
	@PYTHONPATH=src python3 -m pytest tests/ -q --tb=short

lint:
	@python3 -m flake8 src/ --max-line-length=120 --extend-ignore=E203,W503 --exclude=__pycache__ || true

# Two-door installer (asks laptop/gateway) and the escape route. Both need
# root: they touch systemd, /etc and the firewall.
install:
	@sudo ./install.sh

uninstall:
	@sudo ./install/uninstall.sh

# Configuration
SRC_DIR := $(shell pwd)
XDP_SRC := $(SRC_DIR)/src/ebpf/xdp_drop.c
XDP_OBJ := $(SRC_DIR)/src/ebpf/xdp_drop.o
LOADER := $(SRC_DIR)/src/ebpf/xdp_loader.py
TEST_SCRIPT := $(SRC_DIR)/test_xdp_drop.py
BUILD_SCRIPT := $(SRC_DIR)/build_xdp_universal.sh
IFACE ?= eth0

# Colors
GREEN := \033[0;32m
RED := \033[0;31m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m

all: build

build: $(XDP_OBJ)

$(XDP_OBJ): $(XDP_SRC) $(BUILD_SCRIPT)
	@echo "$(BLUE)[INFO]$(NC) Building XDP program..."
	@chmod +x $(BUILD_SCRIPT)
	@$(BUILD_SCRIPT)

# Auto-detect package manager and install dependencies
install-deps:
	@if command -v apt >/dev/null 2>&1; then \
		echo "$(BLUE)[INFO]$(NC) Installing for Debian/Ubuntu/Kali..."; \
		sudo apt update && sudo apt install -y \
			clang llvm \
			linux-headers-$(shell uname -r) \
			bpftool iproute2 python3 python3-pip; \
	elif command -v dnf >/dev/null 2>&1; then \
		echo "$(BLUE)[INFO]$(NC) Installing for Fedora/RHEL..."; \
		sudo dnf install -y \
			clang llvm \
			kernel-headers-$(shell uname -r) kernel-devel-$(shell uname -r) \
			bpftool iproute python3; \
	elif command -v pacman >/dev/null 2>&1; then \
		echo "$(BLUE)[INFO]$(NC) Installing for Arch..."; \
		sudo pacman -S --needed \
			clang llvm \
			linux-headers \
			bpftool iproute2 python3; \
	elif command -v zypper >/dev/null 2>&1; then \
		echo "$(BLUE)[INFO]$(NC) Installing for openSUSE..."; \
		sudo zypper --non-interactive install -y \
			clang llvm \
			kernel-devel \
			bpftool iproute2 python3; \
	elif command -v apk >/dev/null 2>&1; then \
		echo "$(BLUE)[INFO]$(NC) Installing for Alpine..."; \
		sudo apk add --no-cache \
			clang llvm \
			linux-lts-dev \
			iproute2 python3; \
	else \
		echo "$(RED)[ERR]$(NC) Unknown package manager. Install manually:"; \
		echo "  clang, llvm, kernel-headers, bpftool, iproute2, python3"; \
		exit 1; \
	fi

test: $(XDP_OBJ)
	@echo "$(BLUE)[INFO]$(NC) Running XDP drop test on $(IFACE)..."
	@sudo python3 $(TEST_SCRIPT) $(IFACE)

run: $(XDP_OBJ)
	@echo "$(BLUE)[INFO]$(NC) Starting XDP loader on $(IFACE)..."
	@sudo python3 $(LOADER) load $(IFACE)

stop:
	@echo "$(BLUE)[INFO]$(NC) Stopping XDP loader..."
	@sudo python3 $(LOADER) stop
	@sudo ip link set dev $(IFACE) xdp off 2>/dev/null || true

unload:
	@echo "$(BLUE)[INFO]$(NC) Detaching XDP from $(IFACE)..."
	@sudo ip link set dev $(IFACE) xdp off 2>/dev/null || true

status:
	@echo "$(BLUE)[INFO]$(NC) Checking XDP status..."
	@sudo python3 $(LOADER) status

block:
	@if [ -z "$(IP)" ]; then \
		echo "$(RED)[ERR]$(NC) Usage: make block IP=1.2.3.4"; \
		exit 1; \
	fi
	@echo "$(BLUE)[INFO]$(NC) Blocking $(IP)..."
	@sudo python3 $(LOADER) block $(IP)

unblock:
	@if [ -z "$(IP)" ]; then \
		echo "$(RED)[ERR]$(NC) Usage: make unblock IP=1.2.3.4"; \
		exit 1; \
	fi
	@echo "$(BLUE)[INFO]$(NC) Unblocking $(IP)..."
	@sudo python3 $(LOADER) unblock $(IP)

clean:
	@echo "$(BLUE)[INFO]$(NC) Cleaning..."
	@rm -f $(XDP_OBJ)
	@rm -f /tmp/lidra_xdp.sock
	@echo "$(GREEN)[OK]$(NC) Clean complete"

verify:
	@echo "============================================"
	@echo "LIDRA XDP Build Verification"
	@echo "============================================"
	@echo ""
	@echo "Checking tools:"
	@which clang && echo "  $(GREEN)clang: OK$(NC)" || echo "  $(RED)clang: MISSING$(NC)"
	@which llvm-objdump && echo "  $(GREEN)llvm-objdump: OK$(NC)" || echo "  $(RED)llvm-objdump: MISSING$(NC)"
	@which bpftool && echo "  $(GREEN)bpftool: OK$(NC)" || echo "  $(RED)bpftool: MISSING$(NC)"
	@which ip && echo "  $(GREEN)ip: OK$(NC)" || echo "  $(RED)ip: MISSING$(NC)"
	@python3 --version && echo "  $(GREEN)python3: OK$(NC)" || echo "  $(RED)python3: MISSING$(NC)"
	@echo ""
	@echo "Kernel: $$(uname -r)"
	@echo "Distro: $$(cat /etc/os-release 2>/dev/null | grep '^ID=' | cut -d= -f2 | tr -d '\"' || echo unknown)"
	@echo ""
	@if [ -f "$(XDP_OBJ)" ]; then \
		echo "$(GREEN)XDP object: $(XDP_OBJ) [EXISTS]$(NC)"; \
		file $(XDP_OBJ); \
	else \
		echo "$(YELLOW)XDP object: Not built yet$(NC)"; \
	fi

help:
	@echo "LIDRA XDP Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build         - Build XDP program (default)"
	@echo "  test          - Run XDP drop test on IFACE=<interface>"
	@echo "  run           - Start XDP loader daemon on IFACE=<interface>"
	@echo "  stop          - Stop XDP loader and detach"
	@echo "  unload        - Detach XDP from interface only"
	@echo "  status        - Show XDP attachment status"
	@echo "  block IP=x.x.x.x  - Block an IP address"
	@echo "  unblock IP=x.x.x.x - Unblock an IP address"
	@echo "  install-deps  - Auto-install system dependencies"
	@echo "  verify        - Check toolchain and installation"
	@echo "  clean         - Remove build artifacts"
	@echo "  help          - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  IFACE         - Network interface (default: eth0)"
	@echo "  IP            - IP address for block/unblock"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make test IFACE=eth0"
	@echo "  make run IFACE=eth0"
	@echo "  make block IP=192.168.1.100"
	@echo "  make status"
	@echo "  make stop"

.DEFAULT_GOAL := build