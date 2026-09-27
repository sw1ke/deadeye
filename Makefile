# Deadeye — build and checks.
#
# make            — build bin/deadeye (debug build)
# make release    — static build without debug information
# make test       — unit tests
# make check      — gofmt + vet + test + build (everything that must be green)
# make test-all   — integration tests: TUI in a pty, heuristics, daemon
# make install      — install deadeye into $(PREFIX)/bin (needs sudo)
# make install-user — the same, but into ~/.local/bin, no root

BINARY  := deadeye
PREFIX  ?= /usr/local
BINDIR  := $(PREFIX)/bin
DATADIR := $(PREFIX)/share
SYSCONF := /etc/deadeye
FISHDIR := $(DATADIR)/fish/vendor_completions.d
GO      ?= go
LDFLAGS := -s -w

# sudo is needed only when installing not as root.
SUDO    :=
ifneq ($(shell id -u),0)
SUDO    := sudo
endif

# Interpreter for the integration tests. The terminal test (scripts/ptytest.py)
# needs pyte: make venv-test && make test-pty PYTHON=.venv-test/bin/python
PYTHON  ?= python3
SCRIPTS := scripts

.PHONY: all build release vet fmt fmt-check test test-pty test-func test-daemon test-all \
        venv-test tidy install install-user uninstall uninstall-user run once config \
        sources clean help

all: build

## build: regular build into bin/
build:
	$(GO) build -o bin/$(BINARY) .

## release: static build with stripped symbols
release:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) .

## vet: static analysis
vet:
	$(GO) vet ./...

## sources: gather all source code into one file ../Deadeye-sources.txt
sources:
	"$(PYTHON)" $(SCRIPTS)/mksources.py

## fmt: format the sources
fmt:
	gofmt -l -w .

## fmt-check: check the formatting without changing anything
fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "not formatted:"; echo "$$out"; exit 1; \
	else echo "gofmt: clean"; fi

## test: unit tests
test:
	$(GO) test ./...

## check: everything together — format, vet, tests, build
check: fmt-check vet test build
	@echo "checks passed"

## venv-test: create .venv-test and install pyte (needed for test-pty)
venv-test:
	"$(PYTHON)" -m venv .venv-test
	.venv-test/bin/pip install --quiet pyte
	@echo "done: make test-pty PYTHON=.venv-test/bin/python"

## test-pty: integration test of the TUI in a real pseudo-terminal (16 scenarios)
test-pty: build
	"$(PYTHON)" $(SCRIPTS)/ptytest.py ./bin/$(BINARY)

## test-func: heuristics and auto-actions on disposable victim processes
test-func: build
	"$(PYTHON)" $(SCRIPTS)/functest.py ./bin/$(BINARY)

## test-daemon: the --daemon life cycle (background, pid file, log, SIGTERM)
test-daemon: build
	"$(PYTHON)" $(SCRIPTS)/daemontest.py ./bin/$(BINARY)

## test-all: all integration tests in a row
test-all: test-pty test-func test-daemon

## tidy: tidy up go.mod/go.sum
tidy:
	$(GO) mod tidy

## install: install deadeye into $(PREFIX)/bin, the example config and the fish completion
install: release
	$(SUDO) install -Dm755 bin/$(BINARY) $(DESTDIR)$(BINDIR)/$(BINARY)
	$(SUDO) install -Dm644 completions/deadeye.fish $(DESTDIR)$(FISHDIR)/deadeye.fish
	$(SUDO) install -Dm644 deadeye.example.toml $(DESTDIR)$(SYSCONF)/config.example.toml
	@echo "installed: $(BINDIR)/$(BINARY)"
	@echo "example config: $(SYSCONF)/config.example.toml"

## uninstall: remove the installed files
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BINARY)
	rm -f $(DESTDIR)$(FISHDIR)/deadeye.fish
	rm -f $(DESTDIR)$(SYSCONF)/config.example.toml

## install-user: install into ~/.local/bin without root
install-user: release
	install -Dm755 bin/$(BINARY) $(HOME)/.local/bin/$(BINARY)
	mkdir -p $(HOME)/.config/fish/completions
	install -m644 completions/deadeye.fish $(HOME)/.config/fish/completions/deadeye.fish
	mkdir -p $(HOME)/.config/deadeye
	@test -f $(HOME)/.config/deadeye/config.toml || \
		./bin/$(BINARY) --init-config $(HOME)/.config/deadeye/config.toml
	@echo "installed: $(HOME)/.local/bin/$(BINARY)"
	@echo "config: $(HOME)/.config/deadeye/config.toml"
	@echo "if the command is not found, run once: fish_add_path -U ~/.local/bin"

## uninstall-user: remove the user installation
uninstall-user:
	rm -f $(HOME)/.local/bin/$(BINARY)
	rm -f $(HOME)/.config/fish/completions/deadeye.fish

## run: build and start the TUI
run: build
	./bin/$(BINARY)

## once: build and print one system snapshot
once: build
	./bin/$(BINARY) --once --top 15

## config: create an example config next to the project
config: build
	./bin/$(BINARY) --init-config ./deadeye.toml

## clean: remove build results and the test environment
clean:
	rm -rf bin .venv-test

## sources-check: rebuild the source archive and show its size
sources-check: sources
	@ls -l ../Deadeye-sources.txt

## help: list of targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
