#!/bin/bash
# Basic federation discovery test

set -euo pipefail

# Start two servers
./target/release/jig-server --port 7117 --db-path /tmp/server1.db &
PID1=$!
./target/release/jig-server --port 7118 --db-path /tmp/server2.db &
PID2=$!

sleep 1

echo "Server 1 info:"
curl -s http://localhost:7117/.well-known/jig | jq .

echo "Discover example.com (requires DNS):"
curl -s -X POST http://localhost:7117/federation/discover \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}' | jq .

kill $PID1 $PID2
