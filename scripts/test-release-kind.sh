#!/usr/bin/env bash
# Tests for scripts/release-kind.sh: which tags publish as a prerelease, which
# as a final (latest) release, and which are refused. Needs only bash.
set -euo pipefail
kind="$(dirname "$0")/release-kind.sh"
fails=0

expect() {
  local tag="$1" want="$2" got rc=0
  got="$("$kind" "$tag" 2>/dev/null)" || rc=$?
  [ "$rc" -eq 0 ] || got="refused"
  if [ "$got" = "$want" ]; then
    echo "ok: $tag -> $got"
  else
    echo "FAIL: $tag -> $got, want $want" >&2
    fails=$((fails + 1))
  fi
}

expect v0.2.0-alpha.8 prerelease
expect v0.2.0-alpha.1 prerelease
expect v0.2.0-rc.1 prerelease
expect v0.0.0-relpipe.1 prerelease
expect v1.0.0-rc.1+build.5 prerelease
expect v0.2.0 final
expect v1.10.0 final
expect v0.2.0+build.1 final
expect 0.2.0 refused
expect v0.2 refused
expect v01.2.0 refused
expect v0.2.0- refused
expect v0.2.0-alpha..1 refused
expect "v0.2.0 " refused
expect refs/tags/v0.2.0 refused
expect "" refused

[ "$fails" -eq 0 ] || { echo "$fails case(s) failed" >&2; exit 1; }
echo "all release-kind cases pass"
