#!/bin/bash
# Load test using daemon mode for maximum throughput

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Test configuration
TEST_DIR="/tmp/jig-daemon-load-$$"
DB_PATH="$TEST_DIR/load.db"
LOG_FILE="$TEST_DIR/server.log"
DAEMON_OUT="$TEST_DIR/daemon.out"
TEST_MSGS=10000
TARGET_TIME=1.0  # seconds

mkdir -p "$TEST_DIR"

echo -e "${BLUE}=== Jig Daemon Load Testing ===${NC}"
echo "Target: $TEST_MSGS messages in $TARGET_TIME second"
echo

# Kill any existing servers
pkill -f "jig-server" || true
pkill -f "jig.*daemon" || true
sleep 1

# Start server
echo -e "${BLUE}Starting Jig server...${NC}"
export JIG_DB_PATH="$DB_PATH"
./target/release/jig-server --db-path "$DB_PATH" > "$LOG_FILE" 2>&1 &
SERVER_PID=$!
sleep 2

# Test daemon mode throughput
echo -e "\n${BLUE}Test: Daemon Mode Throughput${NC}"
echo "Generating test messages..."

# Generate messages in daemon format
for i in $(seq 1 $TEST_MSGS); do
    echo "#loadtest:Daemon message $i"
done > "$TEST_DIR/messages.txt"

echo "Starting daemon and sending messages..."

START=$(date +%s.%N)

# Run daemon with the messages
./target/release/jig --anon --name daemontest daemon < "$TEST_DIR/messages.txt" > "$DAEMON_OUT" 2>&1

END=$(date +%s.%N)
DURATION=$(echo "$END - $START" | bc -l)
RATE=$(echo "scale=2; $TEST_MSGS / $DURATION" | bc -l)

echo -e "Duration: ${YELLOW}${DURATION}s${NC}"
echo -e "Rate: ${YELLOW}${RATE} msg/sec${NC}"

# Check success rate
SUCCESS_COUNT=$(grep -c "^OK:" "$DAEMON_OUT" 2>/dev/null || echo 0)
ERROR_COUNT=$(grep -c "^ERR:" "$DAEMON_OUT" 2>/dev/null || echo 0)

echo "Successful: $SUCCESS_COUNT"
echo "Errors: $ERROR_COUNT"

if (( $(echo "$RATE >= 10000" | bc -l) )); then
    echo -e "${GREEN}✓ Daemon mode meets target!${NC}"
else
    echo -e "${RED}✗ Daemon mode below target (need 10,000 msg/sec)${NC}"
fi

# Verify storage
echo -e "\n${BLUE}Verifying Storage${NC}"
COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM messages WHERE channel = '#loadtest';" 2>/dev/null || echo 0)
echo "Messages in database: $COUNT"

if [ "$COUNT" -eq "$TEST_MSGS" ]; then
    echo -e "${GREEN}✓ All messages stored correctly${NC}"
else
    echo -e "${RED}✗ Message count mismatch (expected $TEST_MSGS, got $COUNT)${NC}"
fi

# Check server performance
echo -e "\n${BLUE}Server Performance${NC}"
ERROR_LOG=$(grep -c "ERROR" "$LOG_FILE" 2>/dev/null || echo 0)
if [ "$ERROR_LOG" -eq 0 ]; then
    echo -e "${GREEN}✓ No server errors${NC}"
else
    echo -e "${RED}✗ Server reported $ERROR_LOG errors${NC}"
fi

# Memory usage
if [ -n "$SERVER_PID" ] && kill -0 $SERVER_PID 2>/dev/null; then
    MEM=$(ps -o rss= -p $SERVER_PID | awk '{print $1/1024 " MB"}')
    echo "Server memory: $MEM"
fi

# Cleanup
echo -e "\n${BLUE}Cleaning up...${NC}"
kill $SERVER_PID 2>/dev/null || true

echo
echo -e "${BLUE}=== Summary ===${NC}"
if (( $(echo "$RATE >= 10000" | bc -l) )); then
    echo -e "${GREEN}✓ PERFORMANCE TARGET MET: ${RATE} msg/sec${NC}"
else
    IMPROVEMENT=$(echo "scale=0; 10000 / $RATE" | bc -l)
    echo -e "${YELLOW}Need ${IMPROVEMENT}x improvement to reach target${NC}"
fi

echo
echo "Results saved in: $TEST_DIR"