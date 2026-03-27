#!/bin/bash
set -e

echo "Installing jig-server..."

# Check for Rust
if ! command -v cargo &>/dev/null; then
  echo "Rust is required. Install from https://rustup.rs"
  exit 1
fi

# Installation directory
INSTALL_DIR="${JIG_INSTALL_DIR:-$HOME/.jig}"
mkdir -p "$INSTALL_DIR"

# If running from local dev (Cargo.toml present in CWD), just build
if [ -f "./Cargo.toml" ]; then
  echo "Building jig-server from source..."
  cargo build --release -p jig-server
  cp target/release/jig-server "$INSTALL_DIR/jig-server"
  echo "Installed to $INSTALL_DIR/jig-server"
else
  echo "For OSS release: git clone https://github.com/TBD/jig-protocol && cd jig-protocol/repos"
  exit 1
fi

# Require JIG_NS_SECRET to be set before starting
if [ -z "${JIG_NS_SECRET}" ]; then
  echo ""
  echo "⚠️  JIG_NS_SECRET is not set."
  echo "   Set it to a strong random secret before running jig-server:"
  echo "   export JIG_NS_SECRET=\$(openssl rand -hex 32)"
  echo "   See repos/.env.example for all configuration options."
  exit 1
fi

echo ""
echo "Starting jig-server..."
echo "Database: ${JIG_DB_PATH:-$INSTALL_DIR/jig.db}"
echo ""
JIG_DB_PATH="${JIG_DB_PATH:-$INSTALL_DIR/jig.db}" "$INSTALL_DIR/jig-server"
