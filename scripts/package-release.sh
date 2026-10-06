#!/usr/bin/env bash
# package-release.sh <rust-target> <tarball-name> <out-dir> [target-dir]
#
# Stages the release layout install.sh expects and writes <out-dir>/<name>.tar.gz:
#
#   <name>/bin/{jig,jig-server,jig-nameserver}
#   <name>/blocks/text_block.wasm
#   <name>/{install.sh,README.md,LICENSE*}
#
# Binaries are read from <target-dir>/<rust-target>/release (default target dir:
# repos/target). Used by .github/workflows/release.yml and install-smoke.yml.
set -euo pipefail

target="$1"
name="$2"
out="$3"
target_dir="${4:-repos/target}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

bin_dir="$target_dir/$target/release"
# A host build without --target lands in <target-dir>/release.
[ -d "$bin_dir" ] || bin_dir="$target_dir/release"
wasm="$target_dir/wasm32-wasip1/release/text_block.wasm"
stage="$(mktemp -d)/$name"
mkdir -p "$stage/bin" "$stage/blocks" "$out"

for b in jig jig-server jig-nameserver; do
  install -m 0755 "$bin_dir/$b" "$stage/bin/$b"
done
install -m 0644 "$wasm" "$stage/blocks/text_block.wasm"
cp install.sh README.md "$stage/"
cp LICENSE* "$stage/" 2>/dev/null || true

case "$target" in
  *-apple-darwin)
    cat > "$stage/QUARANTINE-README.txt" <<'EOF'
macOS Gatekeeper
================

These binaries are ad-hoc signed, not notarized. `curl | bash` installs are
not quarantined, but a tarball downloaded in a browser or AirDropped carries
com.apple.quarantine and macOS refuses to launch it. Clear the flag with:

    xattr -dr com.apple.quarantine ./bin
EOF
    ;;
esac

tar -C "$(dirname "$stage")" -czf "$out/$name.tar.gz" "$name"
rm -rf "$(dirname "$stage")"
echo "$out/$name.tar.gz"
