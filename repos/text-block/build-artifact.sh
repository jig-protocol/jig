#!/usr/bin/env bash
# Rebuild the canonical text-render Wasm artifact.
#
# Run this after ANY change to text-block's source or dependencies, then commit
# the regenerated artifacts/text_block.wasm alongside the source change.
#
# CI does NOT compare the artifact byte-for-byte, deliberately. Wasm output here
# is not bit-identical across hosts: an identical source tree built on
# aarch64-apple-darwin and on CI's x86_64 Linux differs by ~1.4 KB under the same
# rustc, and `--remap-path-prefix` does not close the gap. Instead CI rebuilds
# and runs jig-runtime's payload suite against BOTH the committed artifact and
# the fresh build; both must agree with text-block's native `execute_pure`. That
# proves functional equivalence, which is the property that actually matters,
# without demanding reproducibility the toolchain does not provide.
#
# The invariant checks below are the other half of that gate.
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

# Structural invariants. Each of these is a way the module can become unloadable
# or unusable while still compiling perfectly well, so check them at build time
# rather than discovering them as a runtime rejection.
if command -v wasm-tools >/dev/null 2>&1; then
	# Disassemble to a temp file rather than a variable piped into grep. With
	# `set -o pipefail`, `grep -q` exits on its first match, the writer gets
	# EPIPE, and the pipeline reports failure even though the match SUCCEEDED —
	# so a passing check reads as a failing one. Grepping a file has no writer to
	# kill.
	WAT="$(mktemp -t text_block_wat)"
	trap 'rm -f "$WAT"' EXIT
	wasm-tools print "$BUILT" >"$WAT"

	# 1. No float instructions. jig-core's determinism validator rejects them even
	#    on unreachable paths, which is how a well-meaning switch back to
	#    serde_json (whose number parser links f64 code) would break this.
	if grep -qE '\b(f32|f64)\.[a-z0-9_]+' "$WAT"; then
		echo "error: built module contains float instructions, which jig-core's" >&2
		echo "       determinism validator rejects. A dependency pulling in" >&2
		echo "       serde_json (or any float-formatting crate) is the usual cause." >&2
		exit 1
	fi
	echo "checked: no float instructions"

	# 2. No imports at all. jig-runtime instantiates with an empty import list, so
	#    any import makes the module unloadable. This is what a rebuild for
	#    wasm32-wasip1 would reintroduce.
	if grep -qE '^[[:space:]]*\(import ' "$WAT"; then
		echo "error: built module declares imports; jig-runtime instantiates with" >&2
		echo "       none. Check that --target is wasm32-unknown-unknown." >&2
		grep -E '^[[:space:]]*\(import ' "$WAT" | head -5 >&2
		exit 1
	fi
	echo "checked: no imports"

	# 3. The exports the byte-payload convention requires.
	for sym in execute jig_alloc jig_dealloc memory; do
		if ! grep -qE "\(export \"$sym\"" "$WAT"; then
			echo "error: built module is missing the \`$sym\` export." >&2
			exit 1
		fi
	done
	echo "checked: exports present (execute, jig_alloc, jig_dealloc, memory)"

	# 4. A declared memory maximum, or jig-core rejects with MemoryMissingMaximum.
	#    wasm-tools renders this as `(memory (;0;) 18 256)` — min then max. The
	#    inline `(;0;)` index comment is why this cannot use a `[^)]*` span.
	if ! grep -qE '\(memory .*[0-9]+ [0-9]+\)' "$WAT"; then
		echo "error: built module's memory declares no maximum. The" >&2
		echo "       -C link-arg=--max-memory flag above should set it." >&2
		grep -E '\(memory ' "$WAT" | head -3 >&2
		exit 1
	fi
	echo "checked: memory maximum declared"
else
	echo "note: wasm-tools not installed; skipping structural checks"
	echo "      install with: cargo install wasm-tools --locked"
fi

# `install -m 0644` rather than `cp`: cargo marks the linker output executable,
# and copying that mode through means git tracks the artifact as 100755. A Wasm
# module is data, not a program to exec, and the stray +x bit shows up as a
# permanent mode diff once the tracked mode is corrected.
install -m 0644 "$BUILT" "$OUT"
echo "wrote $OUT"
ls -l "$OUT"
