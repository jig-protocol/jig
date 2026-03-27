#!/bin/bash
# User Flow: Cold send - sending message without server running

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Cold Send User Flow ===${NC}"
echo "Scenario: User sends message without server running"
echo

TEST_DIR="/tmp/jig-cold-send-$$"
mkdir -p "$TEST_DIR"
export JIG_DB_PATH="$TEST_DIR/cold.db"

# Kill any running servers
pkill -f jig-server 2>/dev/null || true

# Step 1: Send message with no server
echo -e "${BLUE}Step 1: Send message (no server running)${NC}"
../target/release/jig --anon send --channel "#test" "Message sent cold" 2>/dev/null

if [ -f "$TEST_DIR/cold.db" ]; then
    echo -e "${GREEN}✓ Message stored locally${NC}"
else
    echo -e "${RED}✗ Local storage failed${NC}"
fi

# Step 2: Start server
echo -e "\n${BLUE}Step 2: Start server${NC}"
../target/release/jig-server --db-path "$TEST_DIR/cold.db" > /dev/null 2>&1 &
SERVER_PID=$!
sleep 2

# Step 3: Verify message is available
echo -e "\n${BLUE}Step 3: Read message after server start${NC}"
MSG=$(../target/release/jig --anon read --channel "#test" 2>/dev/null)

if echo "$MSG" | grep -q "Message sent cold"; then
    echo -e "${GREEN}✓ Cold-sent message retrieved${NC}"
else
    echo -e "${RED}✗ Message not found${NC}"
fi

# Step 4: Send another message with server running
echo -e "\n${BLUE}Step 4: Send with server running${NC}"
../target/release/jig --anon send --channel "#test" "Server is up now" 2>/dev/null

# Step 5: Stop server and check persistence
echo -e "\n${BLUE}Step 5: Stop server and check persistence${NC}"
kill $SERVER_PID 2>/dev/null || true
sleep 1

MSGS=$(../target/release/jig --anon read --channel "#test" --limit 10 2>/dev/null | wc -l)
echo "Messages persisted: $MSGS"

if [ "$MSGS" -gt 0 ]; then
    echo -e "${GREEN}✓ Messages persist after server stop${NC}"
else
    echo -e "${RED}✗ Messages lost${NC}"
fi

# Cleanup
rm -rf "$TEST_DIR"

echo -e "\n${BLUE}=== Summary ===${NC}"
echo "Cold send allows offline message queueing"