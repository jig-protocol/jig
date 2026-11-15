#!/usr/bin/env bash
# One burst of text-render posts against a fresh local jig-server, to see how
# often a render misses the server's deadline under load and what clients do
# with the `retry_after_ms` a missed deadline returns.
#
# Usage: scripts/bench/render-flood.sh TIMEOUT_MS WRITERS POSTS_EACH MODE [OUT.tsv]
#
# TIMEOUT_MS is the server's [execution] timeout_ms; MODE is once, fixed or
# jitter (see integration-tests/examples/render_flood.rs). Rate limits are off,
# so only the render deadline refuses a post. Needs release builds of
# jig-server and the example:
#   (cd repos && cargo build --release -p jig-server -p integration-tests --example render_flood)
# Env: BENCH_BIN (default repos/target/release), BENCH_PORT (default 47701).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${BENCH_BIN:-$ROOT/repos/target/release}"
PORT="${BENCH_PORT:-47701}"
T="${1:?TIMEOUT_MS}" W="${2:?WRITERS}" P="${3:?POSTS_EACH}" M="${4:?MODE}" OUT="${5:-}"
[ -x "$BIN/jig-server" ] && [ -x "$BIN/examples/render_flood" ] || { echo "build jig-server and the render_flood example first" >&2; exit 1; }
D="$(mktemp -d "${TMPDIR:-/tmp}/render-flood.XXXXXX")"
PID=
# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() { [ -n "$PID" ] && kill "$PID" 2>/dev/null; rm -rf "$D"; }
trap cleanup EXIT
# A throwaway key, sealed with a throwaway secret that lives only here.
KEY="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
"$BIN/jig-server" --init-config "$D/config.toml" >/dev/null
sed -i -e "s#^database_path = .*#database_path = \"$D/jig.db\"#" -e "s#^port = .*#port = $PORT#" \
  -e "s#^server_did_keyfile = .*#server_did_keyfile = \"$D/server.key\"#" \
  -e 's#^storage = "sealed"#storage = "sealed"\nunlock = "env:BENCH_KEY"#' \
  -e "s#^timeout_ms = .*#timeout_ms = $T#" \
  -e 's#^per_did_burst = .*#per_did_burst = 0#' -e 's#^per_did_per_second = .*#per_did_per_second = 0#' \
  -e 's#^per_ip_burst = .*#per_ip_burst = 0#' -e 's#^per_ip_per_second = .*#per_ip_per_second = 0#' \
  "$D/config.toml"
grep -q "^timeout_ms = $T\$" "$D/config.toml" || { echo "the config template changed: no timeout_ms line" >&2; exit 1; }
grep -q '^unlock = "env:BENCH_KEY"' "$D/config.toml" || { echo "the config template changed: no [keys] storage line" >&2; exit 1; }
BENCH_KEY="$KEY" "$BIN/jig-server" --config "$D/config.toml" keys generate --slot env:BENCH_KEY >/dev/null 2>&1
(cd "$D" && exec env BENCH_KEY="$KEY" "$BIN/jig-server" --config "$D/config.toml" >"$D/server.log" 2>&1) &
PID=$!
for _ in $(seq 100); do curl -fsk -o /dev/null "https://127.0.0.1:$PORT/healthz" && break; sleep 0.1; done
"$BIN/examples/render_flood" "https://127.0.0.1:$PORT" "$W" "$P" "$M" ${OUT:+"$OUT"}
