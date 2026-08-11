#!/usr/bin/env bash
# Rebuild the canonical text-render Wasm artifact.
#
# Run this after ANY change to text-block's source or dependencies, then commit
# the regenerated artifacts/text_block.wasm alongside the source change. CI
# rebuilds and compares byte-for-byte, so a stale artifact is a red build rather
# than a silent mismatch between the code you read and the module that runs.
#
# The two build settings below are not defaults and not optional:
#
#   --target wasm32-unknown-unknown
#       NOT wasm32-wasip1. This block is a pure function and needs nothing from
#       the host; the unknown-unknown target emits a module with no imports at
#       all, which is what lets jig-runtime instantiate it under a no-imports
#       policy. A wasip1 build imports wasi_snapshot_preview1 and is rejected.
#
#   -C link-arg=--max-memory=16777216
#       jig-core's determinism validator rejects a memory with no declared
#       maximum (MemoryMissingMaximum). 16 MiB = 256 pages, comfortably inside
#       the 512-page ceiling.
#
# Verify with:  cargo test -p jig-runtime --test text_block_payload
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$CRATE_DIR/.." && pwd)"
TARGET="wasm32-unknown-unknown"
OUT="$CRATE_DIR/artifacts/text_block.wasm"

if ! rustup target list --installed | grep -qx "$TARGET"; then
	echo "error: $TARGET is not installed. Run: rustup target add $TARGET" >&2
	exit 1
fi

mkdir -p "$CRATE_DIR/artifacts"

echo "building text-block for $TARGET ..."
(
	cd "$WORKSPACE_DIR"
	RUSTFLAGS="-C link-arg=--max-memory=16777216" \
		cargo build --release --target "$TARGET" -p text-block
)

BUILT="$WORKSPACE_DIR/target/$TARGET/release/text_block.wasm"
if [ ! -f "$BUILT" ]; then
	echo "error: expected artifact not found at $BUILT" >&2
	exit 1
fi

# A float instruction anywhere in the module fails jig-core's determinism check,
# even on an unreachable path — which is how a well-meaning switch back to
# serde_json would break this. Catch it here rather than in a runtime rejection.
if command -v wasm-tools >/dev/null 2>&1; then
	if wasm-tools print "$BUILT" | grep -qE '\b(f32|f64)\.[a-z0-9_]+'; then
		echo "error: built module contains float instructions, which jig-core's" >&2
		echo "       determinism validator rejects. A dependency pulling in" >&2
		echo "       serde_json (or any float-formatting crate) is the usual cause." >&2
		exit 1
	fi
	echo "checked: no float instructions"
else
	echo "note: wasm-tools not installed; skipping the float-instruction check"
fi

cp "$BUILT" "$OUT"
echo "wrote $OUT"
ls -l "$OUT"
