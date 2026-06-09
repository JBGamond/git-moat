BINARY    := git-moat
CARGO     := cargo
DESTDIR   ?=
PREFIX    ?= $(HOME)/.local
BINDIR    := $(DESTDIR)$(PREFIX)/bin
ZSH_COMPDIR  := $(DESTDIR)$(PREFIX)/share/zsh/site-functions
BASH_COMPDIR := $(DESTDIR)$(PREFIX)/share/bash-completion/completions

.PHONY: all build release install uninstall test lint clean

all: build

build:
	$(CARGO) build

release:
	$(CARGO) build --release

install: release
	@mkdir -p $(BINDIR) $(ZSH_COMPDIR) $(BASH_COMPDIR)
	install -m 755 target/release/$(BINARY) $(BINDIR)/$(BINARY)
	install -m 644 completions/_git-moat      $(ZSH_COMPDIR)/_git-moat
	install -m 644 completions/git-moat.bash  $(BASH_COMPDIR)/git-moat
	@echo ""
	@echo "✓ $(BINARY) installed to $(BINDIR)/$(BINARY)"
	@echo "✓ zsh  completion → $(ZSH_COMPDIR)/_git-moat"
	@echo "✓ bash completion → $(BASH_COMPDIR)/git-moat"
	@echo ""
	@echo "  Reload completions:"
	@echo "    zsh:  autoload -Uz compinit && compinit"
	@echo "    bash: source $(BASH_COMPDIR)/git-moat"
	@echo ""

uninstall:
	rm -f $(BINDIR)/$(BINARY)
	rm -f $(ZSH_COMPDIR)/_git-moat
	rm -f $(BASH_COMPDIR)/git-moat
	@echo "✓ $(BINARY) and completions removed"

test:
	$(CARGO) test

lint:
	$(CARGO) clippy -- -D warnings
	$(CARGO) fmt --check

clean:
	$(CARGO) clean
