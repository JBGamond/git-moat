BINARY    := git-moat
CARGO     := cargo
DESTDIR   ?=
PREFIX    ?= $(HOME)/.local
BINDIR    := $(DESTDIR)$(PREFIX)/bin

.PHONY: all build release install uninstall test lint clean

all: build

build:
	$(CARGO) build

release:
	$(CARGO) build --release

install: release
	@mkdir -p $(BINDIR)
	install -m 755 target/release/$(BINARY) $(BINDIR)/$(BINARY)
	@echo ""
	@echo "✓ $(BINARY) installed to $(BINDIR)/$(BINARY)"
	@echo ""
	@echo "  Usage: git-moat clone <url> [git-options...]"
	@echo ""

uninstall:
	rm -f $(BINDIR)/$(BINARY)
	@echo "✓ $(BINARY) removed from $(BINDIR)"

test:
	$(CARGO) test

lint:
	$(CARGO) clippy -- -D warnings
	$(CARGO) fmt --check

clean:
	$(CARGO) clean
