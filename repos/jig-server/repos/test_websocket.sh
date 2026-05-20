#!/bin/bash
# Basic WebSocket integration test
set -euo pipefail

# Start server with WebSocket enabled
./target/release/jig-server --websocket --ws-port 8080 &
SERVER_PID=$!
trap 'kill $SERVER_PID' EXIT

sleep 1

# Simple anonymous auth using websocat if installed
if command -v websocat >/dev/null 2>&1; then
  echo '{"id":1,"method":"auth.anonymous","params":{"nickname":"test"}}' | \
    websocat ws://localhost:8080/ws || true
else
  echo "websocat not installed; skipping manual test"
fi
