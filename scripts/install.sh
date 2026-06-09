#!/usr/bin/env bash
# git-moat installer
# Builds from source and copies the binary to /usr/local/bin (or $INSTALL_DIR).
#
# Usage:
#   bash scripts/install.sh              # installs to /usr/local/bin/git-moat
#   INSTALL_DIR=~/.local/bin bash scripts/install.sh  # user-local install

set -euo pipefail

BINARY="git-moat"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── dependency check ──────────────────────────────────────────────────────────
if ! command -v cargo &>/dev/null; then
  echo "error: cargo not found. Install Rust from https://rustup.rs and re-run."
  exit 1
fi

if ! command -v git &>/dev/null; then
  echo "error: git not found. Install git and re-run."
  exit 1
fi

# ── build ─────────────────────────────────────────────────────────────────────
echo "Building $BINARY (release)..."
cd "$REPO_ROOT"
cargo build --release --quiet

BINARY_PATH="$REPO_ROOT/target/release/$BINARY"
if [[ ! -f "$BINARY_PATH" ]]; then
  echo "error: build succeeded but binary not found at $BINARY_PATH"
  exit 1
fi

# ── install ───────────────────────────────────────────────────────────────────
DEST="$INSTALL_DIR/$BINARY"

# Create install dir if needed (common for ~/.local/bin)
mkdir -p "$INSTALL_DIR"

if [[ -w "$INSTALL_DIR" ]]; then
  install -m 755 "$BINARY_PATH" "$DEST"
else
  echo "Install directory $INSTALL_DIR requires elevated permissions."
  sudo install -m 755 "$BINARY_PATH" "$DEST"
fi

echo ""
echo "✓ $BINARY installed to $DEST"
echo ""
echo "  Usage:  git-moat clone <url> [git-options...]"
echo ""

# ── PATH check ────────────────────────────────────────────────────────────────
if ! command -v "$BINARY" &>/dev/null; then
  echo "  Note: $INSTALL_DIR is not in your PATH."
  echo "  Add the following to your shell profile (~/.bashrc / ~/.zshrc):"
  echo ""
  echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
  echo ""
fi
