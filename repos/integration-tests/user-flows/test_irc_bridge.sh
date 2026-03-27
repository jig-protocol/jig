#!/bin/bash
# Test IRC bridge functionality

set -e

echo "=== Testing Jig IRC Bridge ==="
echo

# Test directory setup
TEST_DIR="/tmp/jig-irc-test-$$"
mkdir -p "$TEST_DIR"
export JIG_DB="$TEST_DIR/jig.db"
export JIG_DB_PATH="$JIG_DB"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Kill any existing jig-server
pkill -f "jig-server.*--irc" || true
sleep 1

# Start the IRC server
echo -e "${BLUE}Starting Jig server with IRC bridge on port 6667...${NC}"
cd jig-server
RUST_LOG=info cargo run --release -- --db-path "$JIG_DB" --irc --irc-port 6667 &
SERVER_PID=$!
cd ..

# Give server time to start
echo "Waiting for server to start..."
sleep 3

# Function to send IRC command
send_irc() {
    echo -e "$1\r" | nc -w 1 127.0.0.1 6667
}

# Function to test IRC interaction
test_irc_session() {
    echo -e "${BLUE}Testing IRC session...${NC}"
    
    # Create a simple IRC client interaction
    (
        echo "NICK testuser"
        sleep 0.5
        echo "USER testuser 0 * :Test User"
        sleep 0.5
        echo "JOIN #test"
        sleep 0.5
        echo "PRIVMSG #test :Hello from IRC!"
        sleep 0.5
        echo "QUIT :Test complete"
    ) | nc -w 2 127.0.0.1 6667 | while IFS= read -r line; do
        echo "IRC: $line"
        if echo "$line" | grep -q "001.*Welcome"; then
            echo -e "${GREEN}✓ Registration successful${NC}"
        fi
        if echo "$line" | grep -q "JOIN.*#test"; then
            echo -e "${GREEN}✓ Channel join successful${NC}"
        fi
    done
}

# Run the test
test_irc_session

# Test with CLI to verify messages are stored
echo
echo -e "${BLUE}Checking messages via CLI...${NC}"
sleep 1
cd jig-cli
export JIG_DB_PATH="$JIG_DB"
if cargo run --release -- --anon --name bob read --channel "#test" --limit 10 | grep -q "Hello from IRC"; then
    echo -e "${GREEN}✓ IRC messages visible via CLI${NC}"
else
    echo -e "${RED}✗ IRC messages not found${NC}"
    echo "Debug: Checking all messages in database..."
    ./target/release/jig --anon --name bob read --channel "#test" --limit 10
fi

# Cleanup
echo
echo -e "${BLUE}Cleaning up...${NC}"
kill $SERVER_PID 2>/dev/null || true
rm -rf "$TEST_DIR"

echo
echo -e "${GREEN}=== IRC Bridge Test Complete ===${NC}"