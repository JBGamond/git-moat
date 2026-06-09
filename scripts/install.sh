#!/usr/bin/env bash
# git-moat installer — no Rust toolchain required.
#
# Downloads the appropriate pre-built binary from GitHub Releases.
# Falls back to `cargo install` if no pre-built binary is available for
# the current platform.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/JBGamond/git-moat/main/scripts/install.sh | bash
#   bash scripts/install.sh                        # defaults to ~/.local/bin
#   INSTALL_DIR=/usr/local/bin bash scripts/install.sh
#   VERSION=v0.2.0 bash scripts/install.sh         # pin a specific release

set -euo pipefail

BINARY="git-moat"
REPO="JBGamond/git-moat"          # ← replace with your GitHub org/repo
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${VERSION:-latest}"

# ── helpers ───────────────────────────────────────────────────────────────────
info()  { printf '\033[1;32m  =>\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m  !\033[0m  %s\n' "$*" >&2; }
error() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" &>/dev/null || error "$1 is required but not installed."
}

# ── detect platform ───────────────────────────────────────────────────────────
detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Linux)
      case "$arch" in
        x86_64)        echo "git-moat-linux-x86_64" ;;
        aarch64|arm64) echo "git-moat-linux-aarch64" ;;
        *)             echo "" ;;
      esac ;;
    *)
      echo "" ;;
  esac
}

# ── resolve latest version tag ────────────────────────────────────────────────
resolve_version() {
  if [[ "$VERSION" == "latest" ]]; then
    need_cmd curl
    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\(.*\)".*/\1/')"
    [[ -n "$VERSION" ]] || error "Could not determine latest release version."
  fi
  echo "$VERSION"
}

# ── download and install pre-built binary ─────────────────────────────────────
install_prebuilt() {
  local artifact="$1"
  local tag="$2"
  local url="https://github.com/${REPO}/releases/download/${tag}/${artifact}"
  local tmp
  tmp="$(mktemp)"

  info "Downloading $artifact @ $tag"
  if command -v curl &>/dev/null; then
    curl -fsSL --retry 3 --output "$tmp" "$url"
  elif command -v wget &>/dev/null; then
    wget -q --tries=3 -O "$tmp" "$url"
  else
    error "Neither curl nor wget found. Install one and retry."
  fi

  mkdir -p "$INSTALL_DIR"
  install -m 755 "$tmp" "$INSTALL_DIR/$BINARY"
  rm -f "$tmp"
}

# ── fallback: build from source ───────────────────────────────────────────────
install_from_source() {
  warn "No pre-built binary for this platform — falling back to cargo install."
  need_cmd cargo
  cargo install --git "https://github.com/${REPO}" --branch main --locked --quiet
  info "$BINARY installed via cargo"
}

# ── main ──────────────────────────────────────────────────────────────────────
main() {
  need_cmd git

  local artifact
  artifact="$(detect_target)"

  local tag
  tag="$(resolve_version)"

  if [[ -z "$artifact" ]]; then
    warn "Unrecognised platform ($(uname -s)/$(uname -m))."
    install_from_source
  else
    install_prebuilt "$artifact" "$tag"
    info "$BINARY $tag installed to $INSTALL_DIR/$BINARY"
  fi

  # ── install completions ─────────────────────────────────────────────────────
  # Only attempt when running from a cloned repo (completions/ dir exists).
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
  if [[ -d "$REPO_ROOT/completions" ]]; then
    ZSH_COMPDIR="${ZSH_COMPDIR:-$HOME/.local/share/zsh/site-functions}"
    BASH_COMPDIR="${BASH_COMPDIR:-$HOME/.local/share/bash-completion/completions}"
    mkdir -p "$ZSH_COMPDIR" "$BASH_COMPDIR"
    install -m 644 "$REPO_ROOT/completions/_git-moat"     "$ZSH_COMPDIR/_git-moat"
    install -m 644 "$REPO_ROOT/completions/git-moat.bash" "$BASH_COMPDIR/git-moat"
    info "Shell completions installed"
    info "  zsh:  autoload -Uz compinit && compinit"
    info "  bash: source $BASH_COMPDIR/git-moat"
  fi

  # ── PATH hint ───────────────────────────────────────────────────────────────
  if ! command -v "$BINARY" &>/dev/null; then
    warn "$INSTALL_DIR is not in your PATH."
    warn "Add this to your ~/.bashrc or ~/.zshrc:"
    warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
  fi

  echo ""
  info "Done!  Run: git-moat --help"
  echo ""
}

main "$@"
