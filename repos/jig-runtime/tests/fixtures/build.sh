#!/usr/bin/env bash
# Build test WASM fixtures for jig-runtime tests
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building test WASM fixtures..."

# Check for rust toolchain and wasm32-wasip1 target
if ! rustc --version &>/dev/null; then
    echo "Error: Rust toolchain not found"
    exit 1
fi

if ! rustup target list --installed | grep -q wasm32-wasip1; then
    echo "Installing wasm32-wasip1 target..."
    rustup target add wasm32-wasip1
fi

if ! rustup target list --installed | grep -q wasm32-unknown-unknown; then
    echo "Installing wasm32-unknown-unknown target..."
    rustup target add wasm32-unknown-unknown
fi

# Check for wasm-tools (needed to add memory maximum bounds)
if ! command -v wasm-tools &> /dev/null; then
    echo "Installing wasm-tools..."
    cargo install wasm-tools
fi

# Build deterministic fixture (no WASI, no_std)
echo "Building deterministic.wasm..."
rustc --target wasm32-unknown-unknown \
    --crate-type=cdylib \
    -C opt-level=z \
    -C panic=abort \
    -C lto=yes \
    -C link-arg=--max-memory=1048576 \
    deterministic.rs \
    -o deterministic.tmp.wasm

# Add memory maximum bound for determinism (16 pages = 1MB)
wasm-tools print deterministic.tmp.wasm | \
    sed 's/(memory (;0;) 1)/(memory (;0;) 1 16)/' | \
    wasm-tools parse -o deterministic.wasm
rm deterministic.tmp.wasm

# Build fuel-heavy fixture (no WASI, no_std)
echo "Building fuel_heavy.wasm..."
rustc --target wasm32-unknown-unknown \
    --crate-type=cdylib \
    -C opt-level=z \
    -C panic=abort \
    -C lto=yes \
    -C link-arg=--max-memory=1048576 \
    fuel_heavy.rs \
    -o fuel_heavy.tmp.wasm

# Add memory maximum bound
wasm-tools print fuel_heavy.tmp.wasm | \
    sed 's/(memory (;0;) 1)/(memory (;0;) 1 16)/' | \
    wasm-tools parse -o fuel_heavy.wasm
rm fuel_heavy.tmp.wasm

# Build WASI hello world fixture
echo "Building hello_wasi.wasm..."
rustc --target wasm32-wasip1 \
    --crate-type=bin \
    -C opt-level=z \
    -C panic=abort \
    -C lto=yes \
    -C link-arg=-zstack-size=16384 \
    -C link-arg=--max-memory=1048576 \
    hello_wasi.rs \
    -o hello_wasi.tmp.wasm

# Add memory maximum bound (will vary based on rustc output, adjust pattern as needed)
wasm-tools print hello_wasi.tmp.wasm | \
    sed 's/(memory (;0;) [0-9]\+)/(memory (;0;) 17 32)/' | \
    wasm-tools parse -o hello_wasi.wasm
rm hello_wasi.tmp.wasm

echo ""
echo "✓ All fixtures built successfully:"
ls -lh *.wasm

echo ""
echo "Verifying memory bounds..."
for wasm in deterministic.wasm fuel_heavy.wasm hello_wasi.wasm; do
    echo "  $wasm:"
    wasm-tools print "$wasm" | grep -A 1 "memory" | head -3 || true
done
