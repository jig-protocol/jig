#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
SERVER_DIR="$ROOT_DIR/repos/jig-server"
CLI_DIR="$ROOT_DIR/repos/jig-cli"
TMP_DIR=$(mktemp -d -t jig-cli-flow-XXXX)
CONFIG="$TMP_DIR/config.toml"
DB_PATH="$TMP_DIR/server.db"
LOG="$TMP_DIR/server.log"
SERVER_URL="http://127.0.0.1:7117"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat > "$CONFIG" <<CONFIG
[server]
base_url = "$SERVER_URL"

[user]
did = "did:jig:cli"
display_name = "cli"
default_channel = "#integration"
CONFIG

pushd "$SERVER_DIR" >/dev/null
cargo run -p jig-server -- --init-config "$TMP_DIR/server-config.toml" >/dev/null
cat >> "$TMP_DIR/server-config.toml" <<TOML
database_path = "${DB_PATH}"
bind_address = "127.0.0.1"
port = 7117
host_id = "did:jig:test-server"
TOML
cargo run -p jig-server -- --config "$TMP_DIR/server-config.toml" >"$LOG" 2>&1 &
SERVER_PID=$!

for _ in {1..40}; do
  if curl -sf "$SERVER_URL/.well-known/jig" >/dev/null; then
    break
  fi
  sleep 0.25
done

if ! curl -sf "$SERVER_URL/.well-known/jig" >/dev/null; then
  echo "server failed to start" >&2
  cat "$LOG" >&2
  exit 1
fi
popd >/dev/null

pushd "$CLI_DIR" >/dev/null
cargo run -p jig-cli -- --config "$CONFIG" --server "$SERVER_URL" send "hello from cli"
OUTPUT=$(cargo run -p jig-cli -- --config "$CONFIG" --server "$SERVER_URL" read --channel '#integration' --limit 1)
if ! grep -q "hello from cli" <<<"$OUTPUT"; then
  echo "CLI read did not include sent message" >&2
  echo "$OUTPUT" >&2
  exit 1
fi
popd >/dev/null
