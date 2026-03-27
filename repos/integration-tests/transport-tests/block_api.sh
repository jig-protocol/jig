#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../" && pwd)"
SERVER_DIR="$ROOT_DIR/jig-server"
TMP_DIR=$(mktemp -d -t jig-server-test-XXXX)
CONFIG="$TMP_DIR/jig-server.toml"
DB_PATH="$TMP_DIR/jig.db"
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

pushd "$SERVER_DIR" >/dev/null

cargo run -p jig-server -- --init-config "$CONFIG" >/dev/null
cat >> "$CONFIG" <<TOML
database_path = "${DB_PATH}"
bind_address = "127.0.0.1"
port = 7117
host_id = "did:jig:test-server"
TOML

cargo run -p jig-server -- --config "$CONFIG" >"$LOG" 2>&1 &
SERVER_PID=$!

for _ in {1..40}; do
  if curl -sf "$SERVER_URL/.well-known/jig" >/dev/null; then
    break
  fi
  sleep 0.25
done

if ! curl -sf "$SERVER_URL/.well-known/jig" >/dev/null; then
  echo "Server failed to start" >&2
  cat "$LOG" >&2
  exit 1
fi

MANIFEST='{
  "schema": "https://jig.dev/schema/block-manifest/v0.1",
  "version": "0.1.0",
  "authors": [{ "did": "did:jig:alice" }],
  "constraints": { "fuel_max": 5000000, "memory_max_mb": 32, "execution_timeout_ms": 250, "deterministic": true }
}'

CID=$(curl -sf -X POST "$SERVER_URL/blocks" \
  -H 'content-type: application/json' \
  -d "{\"manifest\": $MANIFEST}" | jq -r '.block_id')

if [[ -z "$CID" || "$CID" == "null" ]]; then
  echo "Failed to ingest block" >&2
  cat "$LOG" >&2
  exit 1
fi

echo "Created block: $CID"

curl -sf "$SERVER_URL/blocks/$CID" | jq '.'
curl -sf "$SERVER_URL/receipts/$CID" | jq '.'

popd >/dev/null
