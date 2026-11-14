#!/usr/bin/env bash
# dev-setup.sh — check, and with --install set up, what CI uses to build and
# test this repository.
#
# Usage: scripts/dev-setup.sh [--install] [--spec]
#
#   (default)  report what is present and what is missing; change nothing
#   --install  install what is missing: the pinned Rust toolchain (through
#              rustup, from rust-toolchain.toml) and the cargo tools CI runs
#              (cargo-nextest, cargo-deny, wasm-tools)
#   --spec     also check (and with --install, install) the spec book's tools
#              at the versions repos/jig-spec/Makefile.toml pins
#
# It never installs rustup or a C compiler itself: those come from your OS or
# from https://rustup.rs, and the script says so when they are missing. Every
# cargo tool is installed with --locked, as CI does. Nothing outside ~/.cargo
# and ~/.rustup is touched.
#
# Portable to macOS's bash 3.2.
set -euo pipefail

install=0
spec=0
for arg in "$@"; do
	case "$arg" in
	--install) install=1 ;;
	--spec) spec=1 ;;
	-h | --help)
		awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
		exit 0
		;;
	*)
		echo "unknown argument: $arg (see --help)" >&2
		exit 2
		;;
	esac
done

root="$(cd "$(dirname "$0")/.." && pwd -P)"
missing=0

ok() { printf '  ok       %s\n' "$1"; }
miss() {
	printf '  MISSING  %s\n' "$1"
	missing=$((missing + 1))
}
have() { command -v "$1" >/dev/null 2>&1; }

echo "System:"
for tool in git curl; do
	if have "$tool"; then ok "$tool"; else miss "$tool (install it with your package manager)"; fi
done
# rusqlite builds SQLite from source and ring has C and assembly, so a C
# toolchain is needed; nothing links OpenSSL.
if have cc; then
	ok "C compiler (cc)"
else
	case "$(uname -s)" in
	Darwin) miss "C compiler (run: xcode-select --install)" ;;
	*) miss "C compiler (install build-essential, gcc or clang)" ;;
	esac
fi

echo "Rust:"
if ! have rustup; then
	miss "rustup (install from https://rustup.rs, then re-run this script)"
	echo
	echo "$missing missing. Install rustup first; the rest depends on it."
	exit 1
fi
ok "rustup"

# rust-toolchain.toml pins the channel, components and the
# wasm32-unknown-unknown target. Inside the repository, rustup reads it.
channel="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$root/rust-toolchain.toml")"
if (cd "$root" && rustup run "$channel" rustc --version >/dev/null 2>&1) &&
	(cd "$root" && rustup target list --installed --toolchain "$channel" | grep -qx wasm32-unknown-unknown); then
	ok "toolchain $channel with wasm32-unknown-unknown"
elif [ "$install" = 1 ]; then
	(cd "$root" && rustup toolchain install)
	ok "toolchain $channel (installed)"
else
	miss "toolchain $channel from rust-toolchain.toml (--install runs: rustup toolchain install)"
fi

# name:binary pairs, matching what .github/workflows/ci.yml installs.
tools="cargo-nextest:cargo-nextest cargo-deny:cargo-deny wasm-tools:wasm-tools"
if [ "$spec" = 1 ]; then
	makefile="$root/repos/jig-spec/Makefile.toml"
	mdbook_v="$(sed -n 's/^MDBOOK_VERSION = "\(.*\)"/\1/p' "$makefile")"
	linkcheck_v="$(sed -n 's/^LINKCHECK_VERSION = "\(.*\)"/\1/p' "$makefile")"
	tools="$tools mdbook@$mdbook_v:mdbook mdbook-linkcheck@$linkcheck_v:mdbook-linkcheck"
fi

echo "Cargo tools:"
for pair in $tools; do
	crate="${pair%%:*}"
	bin="${pair##*:}"
	if have "$bin"; then
		ok "$bin"
	elif [ "$install" = 1 ]; then
		(cd "$root" && cargo install --locked "$crate")
		ok "$bin (installed)"
	else
		miss "$bin (--install runs: cargo install --locked $crate)"
	fi
done

echo
if [ "$missing" -gt 0 ]; then
	echo "$missing missing. Re-run with --install, or install them by hand."
	exit 1
fi
cat <<EOF
Ready. The workspace is repos/, not the repository root:

  cd repos
  CARGO_INCREMENTAL=0 cargo build --workspace
  CARGO_INCREMENTAL=0 cargo nextest run --workspace

CONTRIBUTING.md lists the exact checks CI runs; docs/ARCHITECTURE.md is the
tour of the code.
EOF
