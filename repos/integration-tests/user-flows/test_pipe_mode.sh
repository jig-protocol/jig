#!/bin/bash
# Test pipe mode functionality

set -e

echo "=== Testing Jig Pipe Mode ==="
echo

# Test directory setup
TEST_DIR="/tmp/jig-pipe-test-$$"
mkdir -p "$TEST_DIR"
export JIG_DB_PATH="$TEST_DIR/test.db"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Path to jig binary (use workspace target)
JIG="./target/release/jig"

echo -e "${BLUE}Test 1: Pipe input mode${NC}"
echo "Hello from pipe" | $JIG --anon --name alice --channel "#test"
if $JIG --anon read --channel "#test" --limit 1 | grep -q "Hello from pipe"; then
    echo -e "${GREEN}✓ Pipe input works${NC}"
else
    echo -e "${RED}✗ Pipe input failed${NC}"
    exit 1
fi
echo

echo -e "${BLUE}Test 2: Pipe output mode${NC}"
echo "Test message 2" | $JIG --anon --name bob --channel "#test"
OUTPUT=$($JIG --anon read --channel "#test" --limit 1 | tail -1)
if echo "$OUTPUT" | grep -q "Test message 2"; then
    echo -e "${GREEN}✓ Pipe output works${NC}"
else
    echo -e "${RED}✗ Pipe output failed${NC}"
    exit 1
fi
echo

echo -e "${BLUE}Test 3: Multi-line pipe input${NC}"
(echo "Line 1"; echo "Line 2"; echo "Line 3") | $JIG --anon --name alice --channel "#test"
COUNT=$($JIG --anon read --channel "#test" --limit 10 | grep -c "Line")
if [ "$COUNT" -eq "3" ]; then
    echo -e "${GREEN}✓ Multi-line pipe input works (3 lines)${NC}"
else
    echo -e "${RED}✗ Expected 3 lines, got $COUNT${NC}"
    exit 1
fi
echo

echo -e "${BLUE}Test 4: Grep integration${NC}"
$JIG --anon read --channel "#test" --limit 10 | grep "Line 2" > "$TEST_DIR/grep_out.txt"
if grep -q "Line 2" "$TEST_DIR/grep_out.txt"; then
    echo -e "${GREEN}✓ Grep integration works${NC}"
else
    echo -e "${RED}✗ Grep integration failed${NC}"
    exit 1
fi
echo

echo -e "${BLUE}Test 5: Log tailing simulation${NC}"
(for i in {1..3}; do echo "Log entry $i"; sleep 0.1; done) | $JIG --anon --name logger --channel "#logs"
LOG_COUNT=$($JIG --anon read --channel "#logs" --limit 5 | grep -c "Log entry")
if [ "$LOG_COUNT" -eq "3" ]; then
    echo -e "${GREEN}✓ Log tailing works (3 entries)${NC}"
else
    echo -e "${RED}✗ Expected 3 log entries, got $LOG_COUNT${NC}"
    exit 1
fi
echo

# Cleanup
echo -e "${BLUE}Cleaning up...${NC}"
rm -rf "$TEST_DIR"

echo
echo -e "${GREEN}=== All Pipe Mode Tests Passed ===${NC}"
echo
echo "Summary:"
echo "✓ Pipe input mode"
echo "✓ Pipe output mode"
echo "✓ Multi-line input"
echo "✓ Grep integration"
echo "✓ Log tailing"