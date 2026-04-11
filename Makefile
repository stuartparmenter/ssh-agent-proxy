# ssh-agent-proxy — Makefile
#
# Most of the value here is the systemd user-service install lifecycle
# (install-systemd, uninstall-systemd, status, logs). The build / test /
# clippy targets are thin aliases for muscle memory — call `cargo` directly
# if you prefer.
#
# Run `make` or `make help` to see all targets.

SHELL := /bin/bash

# --- Paths --------------------------------------------------------------
# Override on the command line, e.g. `make install BINDIR=/usr/local/bin`.
BINDIR           ?= $(HOME)/.local/bin
CONFIG_DIR       ?= $(HOME)/.config/ssh-agent-proxy
SYSTEMD_USER_DIR ?= $(HOME)/.config/systemd/user
PROXY_URL        ?= http://127.0.0.1:7221

UNIT_SRC  := contrib/systemd/ssh-agent-proxy.service
UNIT_DEST := $(SYSTEMD_USER_DIR)/ssh-agent-proxy.service
ENV_SRC   := contrib/systemd/env.example
ENV_DEST  := $(CONFIG_DIR)/env

# --- Cargo targets ------------------------------------------------------

.PHONY: build
build: ## Build the ssh-agent-proxy binary for the host platform (release)
	cargo build --release

.PHONY: build-windows
build-windows: ## Cross-compile the Windows binary (x86_64-pc-windows-gnu)
	cargo build --release --target x86_64-pc-windows-gnu

.PHONY: build-darwin
build-darwin: ## Cross-compile the macOS (aarch64-apple-darwin) binary
	cargo build --release --target aarch64-apple-darwin

.PHONY: build-all
build-all: build build-windows build-darwin ## Build for Linux, Windows, and macOS

.PHONY: test
test: ## Run the full test suite
	cargo test

.PHONY: vet
vet: ## Run clippy (Rust equivalent of go vet)
	cargo clippy -- -D warnings

.PHONY: check
check: vet test ## Run clippy and tests

.PHONY: clean
clean: ## Remove built artifacts
	cargo clean
	rm -rf bin

# --- Install / systemd lifecycle ---------------------------------------

.PHONY: install
install: build ## Install the binary into $(BINDIR) (default ~/.local/bin)
	install -d -m 0755 $(BINDIR)
	install -m 0755 target/release/ssh-agent-proxy $(BINDIR)/ssh-agent-proxy
	@echo "Installed $(BINDIR)/ssh-agent-proxy"

.PHONY: install-systemd
install-systemd: install ## Install binary + systemd user unit + env template, then reload
	install -d -m 0700 $(CONFIG_DIR)
	@if [ -e $(ENV_DEST) ]; then \
		echo "Keeping existing $(ENV_DEST) (edit manually to change)"; \
	else \
		install -m 0600 $(ENV_SRC) $(ENV_DEST); \
		echo "Wrote $(ENV_DEST) from template"; \
	fi
	install -d -m 0755 $(SYSTEMD_USER_DIR)
	install -m 0644 $(UNIT_SRC) $(UNIT_DEST)
	systemctl --user daemon-reload
	@echo
	@echo "Next steps:"
	@echo "  1. Edit $(ENV_DEST) to set SSH_AUTH_SOCK (or SSH_AGENT_PROXY_UPSTREAM)"
	@echo "     pointing at your local ssh-agent (e.g. 1Password Desktop)."
	@echo "  2. systemctl --user enable --now ssh-agent-proxy.service"
	@echo "  3. Under WSL2 (first time only): sudo loginctl enable-linger \$$USER"

.PHONY: uninstall-systemd
uninstall-systemd: ## Stop, disable, and remove the systemd user unit (env file preserved)
	-systemctl --user disable --now ssh-agent-proxy.service
	rm -f $(UNIT_DEST)
	systemctl --user daemon-reload
	@echo "Removed $(UNIT_DEST)"
	@echo "$(ENV_DEST) preserved. Delete manually if desired."

.PHONY: status
status: ## systemctl --user status ssh-agent-proxy
	systemctl --user status ssh-agent-proxy.service

.PHONY: logs
logs: ## journalctl --user -u ssh-agent-proxy -f
	journalctl --user -u ssh-agent-proxy.service -f

.PHONY: pubkey
pubkey: ## Fetch the public key from a running proxy
	@curl --silent --show-error --fail $(PROXY_URL)/publickey

# --- Help ---------------------------------------------------------------

.PHONY: help
help: ## Show this help
	@awk 'BEGIN { FS = ":.*##"; printf "ssh-agent-proxy targets:\n\n" } \
	      /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' \
	      $(MAKEFILE_LIST)
	@echo
	@echo "Paths (override on the command line):"
	@echo "  BINDIR           = $(BINDIR)"
	@echo "  CONFIG_DIR       = $(CONFIG_DIR)"
	@echo "  SYSTEMD_USER_DIR = $(SYSTEMD_USER_DIR)"

.DEFAULT_GOAL := help
