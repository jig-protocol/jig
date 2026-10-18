#!/usr/bin/env bash
# demo-e2ee.sh — end-to-end encrypted channels and DMs, with real binaries.
#
# Usage: scripts/demo-e2ee.sh [path/to/bin]
#
# Starts a throwaway jig-server and three users (alice, bob, carol), each with
# their own HOME, then walks through what v0.2 adds:
#
#   1. alice creates an encrypted, restricted channel and adds bob
#   2. alice and bob talk; carol, not a member, cannot read
#   3. the server's files on disk are searched for what was said — nothing
#   4. alice removes bob; what she says next, bob cannot read
#   5. alice DMs carol: a locked, encrypted channel for two
#
# Everything lives under one temp directory, deleted on exit, along with the
# server process. Nothing touches your real ~/.jig.
#
# Binaries default to repos/target/debug; pass a directory holding `jig` and
# `jig-server` to use others (e.g. repos/target/release).
set -euo pipefail
export RUST_BACKTRACE=0

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$ROOT/repos/target/debug}"
JIG="$BIN/jig"
SERVER="$BIN/jig-server"
for b in "$JIG" "$SERVER"; do
	[ -x "$b" ] || {
		echo "missing $b — build with: (cd repos && cargo build -p jig-cli -p jig-server)" >&2
		exit 1
	}
done

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
URL="https://127.0.0.1:$PORT"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
as() { # as <user> <jig args...>
	local who="$1"
	shift
	HOME="$WORK/$who" "$JIG" "$@"
}

say "starting jig-server on $URL"
mkdir -p "$WORK/server/.jig"
HOME="$WORK/server" "$SERVER" --init-config "$WORK/server/config.toml" >/dev/null
sed -i.bak -e "s/^port = 7117/port = $PORT/" -e "s/127.0.0.1:7117/127.0.0.1:$PORT/" "$WORK/server/config.toml"
HOME="$WORK/server" RUST_LOG=warn "$SERVER" --config "$WORK/server/config.toml" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 100); do
	curl -kfsS "$URL/healthz" >/dev/null 2>&1 && break
	sleep 0.1
done
# -k: the server's own certificate, which jig trusts through the server DID.
curl -kfsS "$URL/healthz" >/dev/null || { cat "$WORK/server.log"; exit 1; }

for who in alice bob carol; do
	mkdir -p "$WORK/$who"
	as "$who" init "$who" >/dev/null
	as "$who" server set "$URL"
done
did_of() { grep '^did' "$WORK/$1/.jig/cli.toml" | cut -d'"' -f2; }
BOB="$(did_of bob)"
CAROL="$(did_of carol)"

say "alice creates #ops: restricted, end-to-end encrypted"
as alice channel create '#ops' --visibility restricted
as alice channel add '#ops' "$BOB"
as alice channel list

SECRET="the launch code is 0451"
say "alice and bob talk"
as alice send --channel '#ops' "$SECRET" >/dev/null
as bob send --channel '#ops' "copy that" >/dev/null
echo "-- bob reads #ops:"
as bob read '#ops'

say "carol is not a member"
as carol read '#ops' 2>&1 | sed 's/^/   /' || true

say "what does the server have on disk?"
if grep -rqa "$SECRET" "$WORK/server"; then
	echo "FAIL: plaintext found in the server's files" >&2
	exit 1
fi
echo "searched every file under the server's HOME for \"$SECRET\": not found"

say "alice removes bob, then speaks"
as alice channel kick '#ops' "$BOB"
as alice send --channel '#ops' "bob cannot read this" >/dev/null
as alice channel members '#ops'
echo "-- bob tries to read #ops:"
as bob read '#ops' 2>&1 | sed 's/^/   /' || true
echo "-- alice reads #ops:"
as alice read '#ops'

say "alice DMs carol"
as alice dm "$CAROL" "hi carol — just us"
DM="$(as carol channel list | awk '/^#dm\// {print $1}')"
echo "-- carol reads $DM:"
as carol read "$DM"
echo "-- bob tries to read $DM:"
as bob read "$DM" 2>&1 | sed 's/^/   /' || true

say "done"
