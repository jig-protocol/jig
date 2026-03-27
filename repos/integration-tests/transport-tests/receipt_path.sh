#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../" && pwd)"
SERVER_DIR="$ROOT_DIR/jig-server"
TMP_DIR=$(mktemp -d -t jig-server-receipt-XXXX)
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

retry() {
  local attempts=$1; shift
  local sleep_s=$1; shift
  local n=0
  until "$@"; do
    n=$((n+1))
    if (( n >= attempts )); then return 1; fi
    sleep "$sleep_s"
    sleep_s=$((sleep_s + 1))
  done
}

cat > "$CONFIG" <<TOML
database_path = "${DB_PATH}"
bind_address = "127.0.0.1"
port = 7117
host_id = "did:jig:test-server"

[execution]
fuel_max = 5000000
memory_max_mb = 64
timeout_ms = 250
pricing_enabled = true
cost_per_fuel = 0.0001
TOML

pushd "$SERVER_DIR" >/dev/null

cargo run -p jig-server -- --config "$CONFIG" >"$LOG" 2>&1 &
SERVER_PID=$!

for _ in {1..50}; do
  if curl -sf "$SERVER_URL/.well-known/jig" >/dev/null; then
    break
  fi
  sleep 0.2
done

if ! curl -sf "$SERVER_URL/.well-known/jig" >/dev/null; then
  echo "Server failed to start" >&2
  cat "$LOG" >&2
  exit 1
fi

echo "0061736d0100000001040160000003020100070801046d61696e00000a040102000b" | xxd -r -p > "$TMP_DIR/simple.wasm"
CODE_B64=$(base64 -i "$TMP_DIR/simple.wasm" | tr -d '\n')

MANIFEST=$(cat <<'JSON'
{
  "schema": "https://jig.dev/schema/block-manifest/v0.1",
  "version": "1.0.0",
  "authors": [{ "did": "did:jig:alice" }],
  "capabilities": []
}
JSON
)

RESP=$(retry 3 1 curl -sf -X POST "$SERVER_URL/blocks" \
  -H 'content-type: application/json' \
  -d "{\"manifest\": $MANIFEST, \"code_b64\": \"$CODE_B64\"}") || {
  echo "POST /blocks failed" >&2
  cat "$LOG" >&2
  exit 1
}

CID=$(echo "$RESP" | jq -r '.block_id')
if [[ -z "$CID" || "$CID" == "null" ]]; then
  echo "Failed to ingest block" >&2
  cat "$LOG" >&2
  exit 1
fi

echo "$RESP" | jq -e '.receipt.timings_ms.total' >/dev/null || { echo "timings_ms missing in ingest response" >&2; cat "$LOG" >&2; exit 1; }
echo "$RESP" | jq -e '.receipt | has("renders_match")' >/dev/null || { echo "renders_match missing in ingest response" >&2; cat "$LOG" >&2; exit 1; }
echo "$RESP" | jq -e '.receipt.metadata["pricing.cost_per_fuel_unit"]' >/dev/null || { echo "pricing metadata missing in ingest response" >&2; cat "$LOG" >&2; exit 1; }

R2=$(retry 3 1 curl -sf "$SERVER_URL/receipts/$CID") || { echo "GET /receipts failed" >&2; cat "$LOG" >&2; exit 1; }

echo "$R2" | jq -e '.receipt.timings_ms.exec' >/dev/null || { echo "timings_ms missing in stored receipt" >&2; cat "$LOG" >&2; exit 1; }
echo "$R2" | jq -e '.receipt | has("renders_match")' >/dev/null || { echo "renders_match missing in stored receipt" >&2; cat "$LOG" >&2; exit 1; }
echo "$R2" | jq -e '.receipt.metadata["pricing.cost_per_fuel_unit"]' >/dev/null || { echo "pricing metadata missing in stored receipt" >&2; cat "$LOG" >&2; exit 1; }

echo "Receipt path test OK: $CID"

popd >/dev/null
