#!/usr/bin/env bash
# Rebuild the canonical text-render component.
#
# Run this after ANY change to text-block's source or dependencies, then commit
# the regenerated artifacts/text_block.component.wasm alongside the source change.
#
# CI does NOT compare the artifact byte-for-byte, deliberately. Wasm output here
# is not bit-identical across hosts: an identical source tree built on
# aarch64-apple-darwin and on CI's x86_64 Linux differs by ~1.4 KB under the same
# rustc, and `--remap-path-prefix` does not close the gap. Instead CI rebuilds
# and runs jig-runtime's text_block_component suite against BOTH the committed
# artifact and the fresh build (JIG_TEXT_BLOCK_COMPONENT); both must agree with
# text-block's native `execute_pure`, keep the pinned render_hash values, and
# pass jig-core's component validator. That proves functional equivalence, which
# is the property that actually matters, without demanding reproducibility the
# toolchain does not provide.
#
# The invariant checks below are the other half of that gate.
#
# The two build settings below are not defaults and not optional:
#
#   --target wasm32-unknown-unknown
#       NOT wasm32-wasip1. This block is a pure function and needs nothing from
#       the host. A wasip1 build imports wasi_snapshot_preview1, which the
#       renderer world does not grant.
#
#   -C link-arg=--max-memory=16777216
#       jig-core's determinism validator rejects a memory with no declared
#       maximum (MemoryMissingMaximum). 16 MiB = 256 pages, comfortably inside
#       the 512-page ceiling.
#
# The core module comes from this crate with `--features component`, which
# brings in the wit-bindgen exports; `wasm-tools component new` then wraps it.
#
# Verify with:  cargo test -p jig-runtime --test text_block_component
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$CRATE_DIR/.." && pwd)"
TARGET="wasm32-unknown-unknown"

# Capture first, then match. Piping into `grep -q` under `set -o pipefail` is a
# trap: grep exits on its first match, the writer gets EPIPE, and the pipeline
# reports failure even though the match succeeded — so "target is installed" can
# read as "target is missing". It happens to work here because the output is
# small enough to be written before grep exits, which makes it a latent flake
# rather than a visible bug.
INSTALLED_TARGETS="$(rustup target list --installed)"
if ! printf '%s\n' "$INSTALLED_TARGETS" | grep -qx "$TARGET"; then
	echo "error: $TARGET is not installed. Run: rustup target add $TARGET" >&2
	exit 1
fi

mkdir -p "$CRATE_DIR/artifacts"

if ! command -v wasm-tools >/dev/null 2>&1; then
	echo "error: the component build needs wasm-tools." >&2
	echo "       install with: cargo install wasm-tools --locked" >&2
	exit 1
fi

OUT="$CRATE_DIR/artifacts/text_block.component.wasm"
CORE="$WORKSPACE_DIR/target/$TARGET/release/text_block.wasm"
FRESH="$WORKSPACE_DIR/target/$TARGET/release/text_block.component.wasm"

echo "building the text-block component for $TARGET ..."
(
	cd "$WORKSPACE_DIR"
	RUSTFLAGS="-C link-arg=--max-memory=16777216" \
		cargo build --release --target "$TARGET" -p text-block --features component
)
if [ ! -f "$CORE" ]; then
	echo "error: expected core module not found at $CORE" >&2
	exit 1
fi

# Structural invariants on the core module. Each is a way the component can
# become unloadable while still compiling perfectly well, so check them at build
# time rather than discovering them as a validator rejection. jig-core's
# component validator checks the same properties on the wrapped component; this
# catches them earlier, with a message that names the cause.
#
# Disassemble to a temp file rather than a variable piped into grep. With
# `set -o pipefail`, `grep -q` exits on its first match, the writer gets EPIPE,
# and the pipeline reports failure even though the match SUCCEEDED — so a
# passing check reads as a failing one. Grepping a file has no writer to kill.
#
# Explicit template, not `mktemp -t <prefix>`. BSD/macOS mktemp accepts a bare
# prefix and appends its own suffix; GNU coreutils rejects it with "too few X's
# in template", so the `-t` form builds locally on macOS and fails on Linux CI.
# A full template with six X's is accepted by both.
WAT="$(mktemp "${TMPDIR:-/tmp}/text_block_wat.XXXXXX")"
trap 'rm -f "$WAT"' EXIT
wasm-tools print "$CORE" >"$WAT"

# 1. No float instructions. jig-core's determinism validator rejects them even
#    on unreachable paths, which is how a well-meaning switch back to serde_json
#    (whose number parser links f64 code) would break this.
if grep -qE '\b(f32|f64)\.[a-z0-9_]+' "$WAT"; then
	echo "error: built module contains float instructions, which jig-core's" >&2
	echo "       determinism validator rejects. A dependency pulling in" >&2
	echo "       serde_json (or any float-formatting crate) is the usual cause." >&2
	exit 1
fi
echo "checked: no float instructions"

# 2. No WASI imports. This is what a rebuild for wasm32-wasip1 would introduce.
if grep -qE '\(import "wasi_snapshot_preview1"' "$WAT"; then
	echo "error: built module imports wasi_snapshot_preview1. Check that" >&2
	echo "       --target is wasm32-unknown-unknown." >&2
	exit 1
fi
echo "checked: no WASI imports"

# 3. A declared memory maximum, or jig-core rejects with MemoryMissingMaximum.
#    wasm-tools renders this as `(memory (;0;) 18 256)` — min then max. The
#    inline `(;0;)` index comment is why this cannot use a `[^)]*` span.
if ! grep -qE '\(memory .*[0-9]+ [0-9]+\)' "$WAT"; then
	echo "error: built module's memory declares no maximum. The" >&2
	echo "       -C link-arg=--max-memory flag above should set it." >&2
	grep -E '\(memory ' "$WAT" | head -3 >&2
	exit 1
fi
echo "checked: memory maximum declared"

wasm-tools component new "$CORE" -o "$FRESH"

# `install -m 0644` rather than `cp`: cargo marks the linker output executable,
# and copying that mode through means git tracks the artifact as 100755. A Wasm
# component is data, not a program to exec, and the stray +x bit shows up as a
# permanent mode diff once the tracked mode is corrected.
install -m 0644 "$FRESH" "$OUT"
echo "wrote $OUT"
ls -l "$OUT"
