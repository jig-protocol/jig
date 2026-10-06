#!/usr/bin/env bash
# install-smoke.sh [budget-seconds]
#
# Times `curl <install.sh> | bash` from nothing to "hello, world" accepted in
# #hello, in a throwaway $HOME, then proves the message round-trips by reading
# it back over `jig tail`. Exits non-zero if anything fails or the install
# takes longer than the budget (default 60s).
#
# Where install.sh comes from:
#   JIG_INSTALL_SH_URL   explicit URL (file:// works).
#   otherwise            install.sh at $JIG_VERSION in $JIG_REPO via the GitHub
#                        contents API (works for private repos with JIG_GITHUB_TOKEN).
# Every other JIG_* knob is passed straight through to install.sh.
#
# Writes the measured seconds to $JIG_SMOKE_RESULT (if set) and, on GitHub
# Actions, to the job summary.
set -euo pipefail

budget="${1:-60}"
JIG_REPO="${JIG_REPO:-jig-protocol/jig}"
JIG_VERSION="${JIG_VERSION:-latest}"
export JIG_GITHUB_TOKEN="${JIG_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"

now() { perl -MTime::HiRes=time -e 'printf "%.2f\n", time'; }

if [ -z "${JIG_INSTALL_SH_URL:-}" ]; then
  ref="main"
  [ "$JIG_VERSION" != "latest" ] && ref="$JIG_VERSION"
  JIG_INSTALL_SH_URL="https://api.github.com/repos/$JIG_REPO/contents/install.sh?ref=$ref"
fi
curl_args=(-fsSL)
case "$JIG_INSTALL_SH_URL" in
  https://api.github.com/*)
    curl_args+=(-H "Accept: application/vnd.github.raw")
    [ -n "$JIG_GITHUB_TOKEN" ] && curl_args+=(-H "Authorization: Bearer $JIG_GITHUB_TOKEN")
    ;;
esac

sandbox="$(mktemp -d "${TMPDIR:-/tmp}/jig-smoke.XXXXXX")"
port=$(( 20000 + RANDOM % 20000 ))
export HOME="$sandbox/home"
export JIG_HOME="$HOME/.jig"
export JIG_SERVER_LISTEN="127.0.0.1:$port"
export JIG_NONINTERACTIVE=1
export USER="${USER:-smoke}"
mkdir -p "$HOME"

cleanup() {
  [ -f "$JIG_HOME/jig-server.pid" ] && kill "$(cat "$JIG_HOME/jig-server.pid")" 2>/dev/null || true
  [ -n "${tail_pid:-}" ] && kill "$tail_pid" 2>/dev/null || true
  rm -rf "$sandbox"
}
trap cleanup EXIT

echo "== curl $JIG_INSTALL_SH_URL | bash   (budget ${budget}s, HOME=$HOME, port $port)"
start=$(now)
curl "${curl_args[@]}" "$JIG_INSTALL_SH_URL" | bash
end=$(now)
elapsed=$(awk -v a="$start" -v b="$end" 'BEGIN { printf "%.1f", b - a }')

# Round trip: a fresh subscriber's backfill must contain the installer's post.
jig="$JIG_HOME/bin/jig"
"$jig" tail '#hello' > "$sandbox/tail.out" 2>&1 &
tail_pid=$!
for _ in $(seq 1 50); do
  grep -q "hello, world" "$sandbox/tail.out" && break
  sleep 0.2
done
if ! grep -q "hello, world" "$sandbox/tail.out"; then
  echo "FAIL: 'hello, world' not readable back from #hello. jig tail said:" >&2
  cat "$sandbox/tail.out" >&2
  tail -30 "$JIG_HOME/logs/jig-server.log" >&2 || true
  exit 1
fi

# Idempotency: a second run over the same HOME, with the server still up and
# #hello already there, must succeed too (untimed).
echo "== re-running install.sh over the existing install"
curl "${curl_args[@]}" "$JIG_INSTALL_SH_URL" | bash

[ -n "${JIG_SMOKE_RESULT:-}" ] && echo "$elapsed" > "$JIG_SMOKE_RESULT"
verdict=$(awk -v e="$elapsed" -v b="$budget" 'BEGIN { print (e <= b) ? "PASS" : "FAIL" }')
line="install → hello-world: ${elapsed}s (budget ${budget}s) on $(uname -s)/$(uname -m): $verdict"
echo "== $line"
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "- $line" >> "$GITHUB_STEP_SUMMARY"
[ "$verdict" = "PASS" ]
