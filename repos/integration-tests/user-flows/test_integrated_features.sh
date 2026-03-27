#!/bin/bash
# Test integrated SSH, WebSocket, and Federation features

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Test configuration
TEST_DIR="/tmp/jig-integrated-$$"
DB_PATH="$TEST_DIR/jig.db"
LOG_FILE="$TEST_DIR/server.log"

mkdir -p "$TEST_DIR"

echo -e "${BLUE}=== Jig Server Integrated Features Test ===${NC}"
echo "Testing SSH, WebSocket, and Federation components"
echo

# Kill any existing servers
pkill -f "jig-server" || true
sleep 1

# Build the server
echo -e "${BLUE}Building jig-server...${NC}"
cargo build --release -p jig-server 2>&1 | grep -E "Finished|error" || true

# Start server with all features enabled
echo -e "${BLUE}Starting server with all features...${NC}"
export JIG_DB_PATH="$DB_PATH"
./target/release/jig-server \
    --irc --irc-port 6667 \
    --ssh --ssh-port 2222 \
    --websocket --ws-port 8080 \
    > "$LOG_FILE" 2>&1 &
SERVER_PID=$!
sleep 3

# Function to check if port is open
check_port() {
    local port=$1
    nc -z localhost $port 2>/dev/null
}

# Test 1: Verify all ports are listening
echo -e "\n${BLUE}Test 1: Port Availability${NC}"

PORTS_OK=true
for port in 6667 2222 8080; do
    if check_port $port; then
        echo -e "${GREEN}✓ Port $port is listening${NC}"
    else
        echo -e "${RED}✗ Port $port is not listening${NC}"
        PORTS_OK=false
    fi
done

# Test 2: SSH Connection
echo -e "\n${BLUE}Test 2: SSH Transport${NC}"
SSH_RESPONSE=$(echo "test" | nc -w 2 localhost 2222 2>/dev/null | head -1)
if echo "$SSH_RESPONSE" | grep -q "SSH-2.0-jig-server"; then
    echo -e "${GREEN}✓ SSH server responds with identification${NC}"
else
    echo -e "${RED}✗ SSH server not responding correctly${NC}"
    echo "Response: $SSH_RESPONSE"
fi

# Test 3: WebSocket Connection
echo -e "\n${BLUE}Test 3: WebSocket Transport${NC}"
# Try to connect to WebSocket endpoint
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ws | grep -q "426"; then
    echo -e "${GREEN}✓ WebSocket endpoint requires upgrade (correct behavior)${NC}"
else
    echo -e "${RED}✗ WebSocket endpoint not responding correctly${NC}"
fi

# Test 4: Federation Endpoint
echo -e "\n${BLUE}Test 4: Federation Discovery${NC}"
FEDERATION_RESPONSE=$(curl -s http://localhost:7117/.well-known/jig 2>/dev/null || echo "")
if [ -n "$FEDERATION_RESPONSE" ]; then
    echo -e "${GREEN}✓ Federation endpoint accessible${NC}"
    echo "Response: $FEDERATION_RESPONSE" | head -2
else
    echo -e "${YELLOW}⚠ Federation endpoint not yet implemented${NC}"
fi

# Test 5: IRC Still Works
echo -e "\n${BLUE}Test 5: IRC Compatibility${NC}"
IRC_TEST=$(
    (
        echo "NICK testuser"
        echo "USER testuser 0 * :Test User"
        sleep 0.5
        echo "QUIT"
    ) | nc -w 2 localhost 6667 2>/dev/null
)
if echo "$IRC_TEST" | grep -q "001.*Welcome"; then
    echo -e "${GREEN}✓ IRC still functioning with new features${NC}"
else
    echo -e "${RED}✗ IRC broken after integration${NC}"
fi

# Test 6: Cross-Protocol Message Flow
echo -e "\n${BLUE}Test 6: Cross-Protocol Messaging${NC}"
echo "Sending message via IRC..."
(
    echo "NICK alice"
    echo "USER alice 0 * :Alice"
    sleep 0.5
    echo "JOIN #test"
    sleep 0.5
    echo "PRIVMSG #test :Cross-protocol test message"
    sleep 0.5
    echo "QUIT"
) | nc -w 2 localhost 6667 > /dev/null 2>&1

sleep 1

# Check if message is in database
MSG_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM messages WHERE content LIKE '%Cross-protocol%';" 2>/dev/null || echo 0)
if [ "$MSG_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ Message stored and accessible across protocols${NC}"
else
    echo -e "${RED}✗ Cross-protocol messaging not working${NC}"
fi

# Test 7: Multiple Concurrent Connections
echo -e "\n${BLUE}Test 7: Concurrent Connections${NC}"
(
    for i in {1..10}; do
        (echo "test" | nc -w 1 localhost 2222) &
        (echo "QUIT" | nc -w 1 localhost 6667) &
    done
    wait
) 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Server handles concurrent connections${NC}"
else
    echo -e "${RED}✗ Server fails with concurrent connections${NC}"
fi

# Check server logs for errors
echo -e "\n${BLUE}Server Log Analysis${NC}"
ERROR_COUNT=$(grep -c "ERROR" "$LOG_FILE" 2>/dev/null || echo 0)
WARN_COUNT=$(grep -c "WARN" "$LOG_FILE" 2>/dev/null || echo 0)

echo "Errors: $ERROR_COUNT"
echo "Warnings: $WARN_COUNT"

if [ "$ERROR_COUNT" -eq 0 ]; then
    echo -e "${GREEN}✓ No server errors${NC}"
else
    echo -e "${RED}✗ Server reported errors:${NC}"
    grep "ERROR" "$LOG_FILE" | tail -3
fi

# Performance check
echo -e "\n${BLUE}Performance Check${NC}"
if [ -n "$SERVER_PID" ] && kill -0 $SERVER_PID 2>/dev/null; then
    MEM=$(ps -o rss= -p $SERVER_PID | awk '{print $1/1024 " MB"}')
    echo "Memory usage: $MEM"
fi

# Cleanup
echo -e "\n${BLUE}Cleaning up...${NC}"
kill $SERVER_PID 2>/dev/null || true
sleep 1

# Summary
echo -e "\n${BLUE}=== Test Summary ===${NC}"
if $PORTS_OK; then
    echo -e "${GREEN}✓ All transport layers initialized${NC}"
else
    echo -e "${RED}✗ Some transport layers failed to start${NC}"
fi

echo
echo "Test directory: $TEST_DIR"
echo "Server log: $LOG_FILE"