#!/bin/bash
# Alice & Bob test script for Jig protocol
# Tests basic message exchange using the CLI

set -e

echo "=== Jig Protocol - Alice & Bob Test ==="
echo

# Set up test environment
TEST_DIR="/tmp/jig-test-$$"
mkdir -p "$TEST_DIR"
export JIG_DB_PATH="$TEST_DIR/test.db"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Build the CLI
echo "Building jig-cli..."
cd jig-cli
cargo build --release 2>/dev/null || cargo build
cd ..

# Path to jig binary (use workspace target)
JIG="./target/debug/jig"
if [ -f "./target/release/jig" ]; then
    JIG="./target/release/jig"
fi

echo "Using database: $JIG_DB_PATH"
echo

# Test 1: Alice sends a message
echo -e "${BLUE}Test 1: Alice sends a message${NC}"
$JIG --anon --name alice send "Hello, this is Alice!" --channel "#test"
echo -e "${GREEN}✓ Alice sent message${NC}"
echo

# Test 2: Bob reads the message
echo -e "${BLUE}Test 2: Bob reads messages${NC}"
OUTPUT=$($JIG --anon --name bob read --channel "#test" --limit 1)
if echo "$OUTPUT" | grep -q "Hello, this is Alice!"; then
    echo -e "${GREEN}✓ Bob received Alice's message${NC}"
    echo "$OUTPUT"
else
    echo -e "${RED}✗ Bob did not receive Alice's message${NC}"
    echo "$OUTPUT"
    exit 1
fi
echo

# Test 3: Bob replies
echo -e "${BLUE}Test 3: Bob sends a reply${NC}"
$JIG --anon --name bob send "Hi Alice, this is Bob!" --channel "#test"
echo -e "${GREEN}✓ Bob sent reply${NC}"
echo

# Test 4: Alice reads both messages
echo -e "${BLUE}Test 4: Alice reads the conversation${NC}"
OUTPUT=$($JIG --anon --name alice read --channel "#test" --limit 10)
if echo "$OUTPUT" | grep -q "Hello, this is Alice!" && echo "$OUTPUT" | grep -q "Hi Alice, this is Bob!"; then
    echo -e "${GREEN}✓ Alice sees the full conversation${NC}"
    echo "$OUTPUT"
else
    echo -e "${RED}✗ Alice cannot see the full conversation${NC}"
    echo "$OUTPUT"
    exit 1
fi
echo

# Test 5: Pipe mode test
echo -e "${BLUE}Test 5: Pipe mode test${NC}"
echo "This is a piped message from Alice" | $JIG --anon --name alice --channel "#test"
OUTPUT=$($JIG --anon --name bob read --channel "#test" --limit 1)
if echo "$OUTPUT" | grep -q "This is a piped message"; then
    echo -e "${GREEN}✓ Pipe mode works${NC}"
else
    echo -e "${RED}✗ Pipe mode failed${NC}"
    exit 1
fi
echo

# Test 6: Multiple messages
echo -e "${BLUE}Test 6: Multiple messages${NC}"
$JIG --anon --name alice send "Message 1" --channel "#test"
$JIG --anon --name alice send "Message 2" --channel "#test"
$JIG --anon --name bob send "Message 3" --channel "#test"
OUTPUT=$($JIG --anon --name alice read --channel "#test" --limit 3)
COUNT=$(echo "$OUTPUT" | grep -c "Message")
if [ "$COUNT" -eq "3" ]; then
    echo -e "${GREEN}✓ All 3 messages visible${NC}"
else
    echo -e "${RED}✗ Expected 3 messages, got $COUNT${NC}"
    exit 1
fi
echo

# Cleanup
echo -e "${GREEN}=== All tests passed! ===${NC}"
echo "Cleaning up test database..."
rm -rf "$TEST_DIR"

echo
echo "Summary:"
echo "✓ Alice can send messages"
echo "✓ Bob can read Alice's messages"
echo "✓ Bob can reply to Alice"
echo "✓ Both users see the full conversation"
echo "✓ Pipe mode works"
echo "✓ Multiple messages handled correctly"
echo
echo -e "${GREEN}Alice & Bob test completed successfully!${NC}"