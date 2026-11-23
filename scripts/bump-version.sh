#!/usr/bin/env bash
# Set the workspace version before tagging a release.
#
# Usage: scripts/bump-version.sh VERSION      (e.g. 0.2.0 or 0.2.0-alpha.8, no "v")
#
# release.yml refuses a tag that is not v<workspace version>, so the version
# moves in a commit of its own ("chore(release): VERSION") before the tag.
# This script:
#   1. rewrites `version` under [workspace.package] in repos/Cargo.toml;
#   2. lets cargo move the workspace crates in repos/Cargo.lock
#      (`cargo update --workspace`; the lockfile is never edited by hand and
#      no dependency is upgraded);
#   3. checks with `cargo metadata --locked` that every workspace crate now
#      carries VERSION and that the lockfile needs no further change;
#   4. prints the diff stat. It does not commit or tag.
set -euo pipefail

version="${1:?usage: $0 VERSION (e.g. 0.2.0 or 0.2.0-alpha.8)}"
root="$(cd "$(dirname "$0")/.." && pwd)"
"$root/scripts/release-kind.sh" "v$version" >/dev/null \
  || { echo "bump-version: '$version' is not a semver version" >&2; exit 2; }

cd "$root/repos"
manifest=Cargo.toml
current="$(awk '/^\[workspace\.package\]/{s=1;next} /^\[/{s=0} s&&/^version *=/{gsub(/.*= *"|".*/,"");print;exit}' "$manifest")"
[ -n "$current" ] || { echo "bump-version: no version under [workspace.package] in repos/$manifest" >&2; exit 1; }
if [ "$current" = "$version" ]; then
  echo "bump-version: the workspace is already at $version" >&2
  exit 1
fi

# Only the first `version =` line inside [workspace.package] changes.
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
awk -v v="$version" '
  /^\[workspace\.package\]/ { s = 1; print; next }
  /^\[/ { s = 0 }
  s && !done && /^version *=/ { print "version = \"" v "\""; done = 1; next }
  { print }
' "$manifest" > "$tmp"
cat "$tmp" > "$manifest"

cargo update --workspace --quiet

versions="$(cargo metadata --no-deps --format-version 1 --locked \
  | jq -r '[.packages[].version] | unique | .[]')"
if [ "$versions" != "$version" ]; then
  echo "bump-version: workspace crates carry ${versions//$'\n'/ }, not only $version" >&2
  echo "  (a crate that sets its own version instead of version.workspace = true?)" >&2
  exit 1
fi

echo "workspace version $current -> $version"
git -C "$root" diff --stat -- repos/Cargo.toml repos/Cargo.lock
echo "next: commit as \"chore(release): $version\", with .github/release/notes/v$version.md"
