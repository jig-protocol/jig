#!/bin/bash
# Test IRC fixes - registration, QUIT, message storage

set -e

echo "=== Testing IRC Bridge Fixes ==="
echo

# Test directory setup
TEST_DIR="/tmp/jig-irc-fix-$$"
mkdir -p "$TEST_DIR"
export JIG_DB="$TEST_DIR/jig.db"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Kill any existing jig-server
pkill -f "jig-server.*--irc" || true
sleep 1

# Start the IRC server
echo -e "${BLUE}Starting Jig server with IRC bridge...${NC}"
cd jig-server
RUST_LOG=info cargo run --release -- --db-path "$JIG_DB" --irc --irc-port 6667 > "$TEST_DIR/server.log" 2>&1 &
SERVER_PID=$!
cd ..
sleep 3

echo -e "${BLUE}Test 1: Registration and Welcome${NC}"
RESPONSE=$(
    (
        echo "NICK testuser1"
        echo "USER testuser1 0 * :Test User One"
        sleep 1
        echo "QUIT :Registration test"
    ) | nc -w 2 127.0.0.1 6667 2>/dev/null
)

if echo "$RESPONSE" | grep -q "001.*Welcome"; then
    echo -e "${GREEN}✓ Registration sends welcome (001)${NC}"
else
    echo -e "${RED}✗ No welcome message received${NC}"
    echo "Response: $RESPONSE"
fi

echo
echo -e "${BLUE}Test 2: PRIVMSG Storage${NC}"
(
    echo "NICK alice"
    echo "USER alice 0 * :Alice User"
    sleep 0.5
    echo "JOIN #test"
    sleep 0.5
    echo "PRIVMSG #test :Hello from Alice!"
    sleep 0.5
    echo "QUIT :Done"
) | nc -w 2 127.0.0.1 6667 > /dev/null 2>&1

sleep 1

# Check if message was stored
export JIG_DB_PATH="$JIG_DB"
cd jig-cli
if cargo run --release -- --anon read --channel "#test" --limit 10 2>/dev/null | grep -q "Hello from Alice"; then
    echo -e "${GREEN}✓ PRIVMSG stored correctly${NC}"
else
    echo -e "${RED}✗ PRIVMSG not found in database${NC}"
    echo "Database contents:"
    sqlite3 "$JIG_DB" "SELECT channel, sender, json_extract(content, '$.content') FROM messages;" || true
fi
cd ..

echo
echo -e "${BLUE}Test 3: QUIT Termination${NC}"
# Test that QUIT actually closes the connection
QUIT_TEST=$(
    (
        echo "NICK quituser"
        echo "USER quituser 0 * :Quit Test"
        sleep 0.5
        echo "QUIT :Testing quit"
        sleep 0.5
        echo "PRIVMSG #test :This should not work"
    ) | nc -w 2 127.0.0.1 6667 2>&1
)

if echo "$QUIT_TEST" | grep -q "ERROR.*Closing Link"; then
    echo -e "${GREEN}✓ QUIT sends ERROR and closes${NC}"
else
    echo -e "${RED}✗ QUIT doesn't close properly${NC}"
fi

echo
echo -e "${BLUE}Test 4: Multiple Clients${NC}"
# Connect two clients and exchange messages
(
    echo "NICK bob"
    echo "USER bob 0 * :Bob User"
    sleep 0.5
    echo "JOIN #multi"
    sleep 2
    echo "QUIT"
) | nc 127.0.0.1 6667 > "$TEST_DIR/bob.out" 2>&1 &
BOB_PID=$!

sleep 0.5

(
    echo "NICK charlie"
    echo "USER charlie 0 * :Charlie User"
    sleep 0.5
    echo "JOIN #multi"
    sleep 0.5
    echo "PRIVMSG #multi :Hello from Charlie!"
    sleep 1
    echo "QUIT"
) | nc 127.0.0.1 6667 > "$TEST_DIR/charlie.out" 2>&1

wait $BOB_PID 2>/dev/null || true

if grep -q "Hello from Charlie" "$TEST_DIR/bob.out"; then
    echo -e "${GREEN}✓ Multi-client messaging works${NC}"
else
    echo -e "${RED}✗ Bob didn't receive Charlie's message${NC}"
fi

echo
echo -e "${BLUE}Test 5: Channel Isolation${NC}"
(
    echo "NICK dave"
    echo "USER dave 0 * :Dave User"
    sleep 0.5
    echo "JOIN #chan1"
    echo "JOIN #chan2"
    sleep 0.5
    echo "PRIVMSG #chan1 :Message to chan1"
    echo "PRIVMSG #chan2 :Message to chan2"
    sleep 0.5
    echo "QUIT"
) | nc -w 2 127.0.0.1 6667 > /dev/null 2>&1

sleep 1

pushd jig-cli >/dev/null
CHAN1_COUNT=$(JIG_DB_PATH="$JIG_DB" cargo run --release -- --anon read --channel "#chan1" 2>/dev/null | grep -c "Message to chan1" || true)
CHAN2_COUNT=$(JIG_DB_PATH="$JIG_DB" cargo run --release -- --anon read --channel "#chan2" 2>/dev/null | grep -c "Message to chan2" || true)
popd >/dev/null

if [ "$CHAN1_COUNT" -eq "1" ] && [ "$CHAN2_COUNT" -eq "1" ]; then
    echo -e "${GREEN}✓ Channel isolation works${NC}"
else
    echo -e "${RED}✗ Channel isolation failed (chan1: $CHAN1_COUNT, chan2: $CHAN2_COUNT)${NC}"
fi

# Check server logs for errors
echo
echo -e "${BLUE}Server Log Summary:${NC}"
grep -E "(ERROR|WARN)" "$TEST_DIR/server.log" | tail -5 || echo "No errors/warnings"

# Cleanup
echo
echo -e "${BLUE}Cleaning up...${NC}"
kill $SERVER_PID 2>/dev/null || true
rm -rf "$TEST_DIR"

echo
echo -e "${GREEN}=== IRC Fix Tests Complete ===${NC}"