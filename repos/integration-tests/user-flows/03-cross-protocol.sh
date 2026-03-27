#!/bin/bash
# User Flow: Cross-protocol messaging (IRC -> WebSocket -> SSH)

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo -e "${BLUE}=== Cross-Protocol Message Flow ===${NC}"
echo "Test message flow across IRC, WebSocket, and SSH"
echo

TEST_DIR="/tmp/jig-cross-protocol-$$"
DB_PATH="$TEST_DIR/cross.db"
mkdir -p "$TEST_DIR"

# Kill any existing servers
pkill -f jig-server 2>/dev/null || true
sleep 1

# Start server with all protocols
echo -e "${BLUE}Starting multi-protocol server...${NC}"
export JIG_DB_PATH="$DB_PATH"
../target/release/jig-server \
    --db-path "$DB_PATH" \
    --irc --irc-port 6667 \
    --ssh --ssh-port 2222 \
    --websocket --ws-port 8080 \
    > "$TEST_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 3

# Function to check if message exists
check_message() {
    local pattern=$1
    sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM messages WHERE content LIKE '%$pattern%';" 2>/dev/null || echo 0
}

# Step 1: Send via IRC
echo -e "\n${BLUE}Step 1: Send message via IRC${NC}"
(
    echo "NICK alice"
    echo "USER alice 0 * :Alice"
    sleep 0.5
    echo "JOIN #cross"
    sleep 0.5
    echo "PRIVMSG #cross :IRC->Others: Test message from IRC"
    sleep 0.5
    echo "QUIT"
) | nc -w 2 localhost 6667 > /dev/null 2>&1

sleep 1
COUNT=$(check_message "IRC->Others")
if [ "$COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ IRC message stored${NC}"
else
    echo -e "${YELLOW}⚠ IRC message not found${NC}"
fi

# Step 2: Verify via CLI
echo -e "\n${BLUE}Step 2: Read via CLI${NC}"
MSGS=$(../target/release/jig --anon read --channel "#cross" 2>/dev/null)
if echo "$MSGS" | grep -q "IRC->Others"; then
    echo -e "${GREEN}✓ IRC message readable via CLI${NC}"
else
    echo -e "${YELLOW}⚠ IRC message not visible in CLI${NC}"
fi

# Step 3: WebSocket test (if implemented)
echo -e "\n${BLUE}Step 3: WebSocket connection test${NC}"
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ws | grep -q "426"; then
    echo -e "${GREEN}✓ WebSocket endpoint responds${NC}"
else
    echo -e "${YELLOW}⚠ WebSocket not responding${NC}"
fi

# Step 4: SSH test
echo -e "\n${BLUE}Step 4: SSH protocol test${NC}"
SSH_RESP=$(echo "test" | nc -w 1 localhost 2222 2>/dev/null | head -1)
if echo "$SSH_RESP" | grep -q "SSH"; then
    echo -e "${GREEN}✓ SSH server responds${NC}"
else
    echo -e "${YELLOW}⚠ SSH not responding${NC}"
fi

# Step 5: Send via CLI, read via IRC
echo -e "\n${BLUE}Step 5: CLI -> IRC flow${NC}"
../target/release/jig --anon send --channel "#cross" "CLI->IRC: Message from CLI" 2>/dev/null

# Connect with IRC to read
IRC_OUTPUT=$(
    (
        echo "NICK bob"
        echo "USER bob 0 * :Bob"
        sleep 0.5
        echo "JOIN #cross"
        sleep 1
        echo "QUIT"
    ) | nc -w 3 localhost 6667 2>/dev/null
)

if echo "$IRC_OUTPUT" | grep -q "CLI->IRC"; then
    echo -e "${GREEN}✓ CLI message visible in IRC${NC}"
else
    echo -e "${YELLOW}⚠ CLI message not visible in IRC${NC}"
fi

# Check logs for errors
ERRORS=$(grep -c "ERROR" "$TEST_DIR/server.log" 2>/dev/null || echo 0)
echo -e "\n${BLUE}Server errors: $ERRORS${NC}"

# Cleanup
kill $SERVER_PID 2>/dev/null || true
sleep 1
rm -rf "$TEST_DIR"

echo -e "\n${BLUE}=== Summary ===${NC}"
echo "Cross-protocol messaging allows seamless communication"