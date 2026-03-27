#!/bin/bash
# Debug IRC storage issue

set -e

TEST_DIR="/tmp/jig-debug-$$"
mkdir -p "$TEST_DIR"
export JIG_DB="$TEST_DIR/test.db"

echo "=== IRC Storage Debug ==="

# Start server
echo "Starting server..."
cd jig-server
./target/release/jig-server --db-path "$JIG_DB" --irc --irc-port 6668 > "$TEST_DIR/server.log" 2>&1 &
SERVER_PID=$!
cd ..
sleep 2

# Send IRC message
echo "Sending IRC message..."
(
    echo "NICK debuguser"
    echo "USER debuguser 0 * :Debug User"
    sleep 0.5
    echo "JOIN #debug"
    sleep 0.5
    echo "PRIVMSG #debug :Test message from IRC"
    sleep 0.5
    echo "QUIT :Done"
) | nc -w 2 127.0.0.1 6668

sleep 1

# Check database directly
echo -e "\nDatabase contents:"
sqlite3 "$JIG_DB" "SELECT channel, sender, json_extract(content, '$.content') as msg FROM messages;" | column -t -s '|'

# Try CLI read
echo -e "\nCLI read attempt:"
export JIG_DB_PATH="$JIG_DB"
./jig-cli/target/release/jig --anon read --channel "#debug" --limit 10 || echo "CLI read failed"

# Debug: Check what the CLI is actually querying
echo -e "\nDirect CLI database path check:"
echo "JIG_DB_PATH=$JIG_DB_PATH"
echo "File exists: $(ls -la $JIG_DB_PATH 2>/dev/null || echo 'NO')"

# Try without quotes
echo -e "\nTrying channel without quotes:"
./jig-cli/target/release/jig --anon read --channel \#debug --limit 10 || echo "Also failed"

# Check server logs
echo -e "\nServer logs:"
grep -E "(Storing|ERROR|WARN)" "$TEST_DIR/server.log" | tail -5

# Cleanup
kill $SERVER_PID 2>/dev/null || true
rm -rf "$TEST_DIR"