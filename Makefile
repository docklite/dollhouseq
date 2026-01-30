# Makefile for Dollhouse q

VERSION := 0.1.0
BINARY := dollhouse-q
GO := go
INSTALL_PATH := /usr/local/bin
CONFIG_PATH := /etc/dollhouse-q
SYSTEMD_PATH := /etc/systemd/system

# Default target
.PHONY: all
all: build

# Build for current platform
.PHONY: build
build:
	$(GO) build -ldflags="-s -w -X main.version=$(VERSION)" -o $(BINARY) .

# Cross-compile for common platforms
.PHONY: build-all
build-all: build-linux-amd64 build-linux-arm64 build-linux-arm

.PHONY: build-linux-amd64
build-linux-amd64:
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags="-s -w -X main.version=$(VERSION)" -o $(BINARY)-linux-amd64 .

.PHONY: build-linux-arm64
build-linux-arm64:
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags="-s -w -X main.version=$(VERSION)" -o $(BINARY)-linux-arm64 .

.PHONY: build-linux-arm
build-linux-arm:
	GOOS=linux GOARCH=arm GOARM=7 $(GO) build -ldflags="-s -w -X main.version=$(VERSION)" -o $(BINARY)-linux-arm .

# Install binary and config
.PHONY: install
install: build
	@echo "Installing binary to $(INSTALL_PATH)..."
	install -m 755 $(BINARY) $(INSTALL_PATH)/$(BINARY)
	@echo "Creating config directory..."
	install -d -m 755 $(CONFIG_PATH)
	@if [ ! -f $(CONFIG_PATH)/config.json ]; then \
		echo "Installing example config..."; \
		install -m 644 config.example.json $(CONFIG_PATH)/config.json; \
		echo "IMPORTANT: Edit $(CONFIG_PATH)/config.json with your settings"; \
	else \
		echo "Config already exists at $(CONFIG_PATH)/config.json"; \
	fi

# Install systemd service
.PHONY: install-service
install-service:
	@echo "Installing systemd service..."
	install -m 644 dollhouse-q.service $(SYSTEMD_PATH)/dollhouse-q.service
	systemctl daemon-reload
	@echo "Service installed. Enable with: systemctl enable dollhouse-q"
	@echo "Start with: systemctl start dollhouse-q"

# Uninstall
.PHONY: uninstall
uninstall:
	@echo "Stopping service (if running)..."
	-systemctl stop dollhouse-q
	-systemctl disable dollhouse-q
	@echo "Removing files..."
	rm -f $(INSTALL_PATH)/$(BINARY)
	rm -f $(SYSTEMD_PATH)/dollhouse-q.service
	systemctl daemon-reload
	@echo "Uninstalled. Config preserved in $(CONFIG_PATH)"

# Clean build artifacts
.PHONY: clean
clean:
	rm -f $(BINARY) $(BINARY)-*

# Development: run locally
.PHONY: run
run: build
	./$(BINARY) config.example.json

# Check dependencies
.PHONY: deps
deps:
	$(GO) mod download
	$(GO) mod verify

# Format code
.PHONY: fmt
fmt:
	$(GO) fmt .

# Run tests (when added)
.PHONY: test
test:
	$(GO) test -v ./...

.PHONY: help
help:
	@echo "Dollhouse q - Makefile targets:"
	@echo "  make build              - Build for current platform"
	@echo "  make build-all          - Cross-compile for linux/amd64, arm64, arm"
	@echo "  make install            - Install binary and config to system paths"
	@echo "  make install-service    - Install systemd service"
	@echo "  make uninstall          - Remove binary and service"
	@echo "  make clean              - Remove build artifacts"
	@echo "  make run                - Build and run locally"
	@echo "  make deps               - Download dependencies"
	@echo "  make fmt                - Format code"
	@echo "  make test               - Run tests"
