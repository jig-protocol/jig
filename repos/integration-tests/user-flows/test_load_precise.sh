#!/bin/bash
# Precise load testing for Jig protocol
# Target: 10,000 messages/second

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Test configuration
TEST_DIR="/tmp/jig-load-$$"
DB_PATH="$TEST_DIR/load.db"
LOG_FILE="$TEST_DIR/server.log"
WARMUP_MSGS=100
TEST_MSGS=10000
TARGET_TIME=1.0  # seconds

mkdir -p "$TEST_DIR"

echo -e "${BLUE}=== Jig Protocol Load Testing ===${NC}"
echo "Target: $TEST_MSGS messages in $TARGET_TIME second"
echo

# Kill any existing servers
pkill -f "jig-server" || true
sleep 1

# Start server
echo -e "${BLUE}Starting Jig server...${NC}"
export JIG_DB_PATH="$DB_PATH"
./target/release/jig-server --db-path "$DB_PATH" > "$LOG_FILE" 2>&1 &
SERVER_PID=$!
sleep 2

# Function to send messages via CLI
test_cli_throughput() {
    echo -e "\n${BLUE}Test 1: CLI Direct Throughput${NC}"
    echo "Warming up with $WARMUP_MSGS messages..."
    
    # Warmup
    for i in $(seq 1 $WARMUP_MSGS); do
        echo "Warmup $i" | ./target/release/jig --anon --name loadtest --channel "#perf" 2>/dev/null
    done
    
    echo "Starting load test: $TEST_MSGS messages..."
    START=$(date +%s.%N)
    
    for i in $(seq 1 $TEST_MSGS); do
        echo "Message $i" | ./target/release/jig --anon --name loadtest --channel "#perf" 2>/dev/null
    done
    
    END=$(date +%s.%N)
    DURATION=$(echo "$END - $START" | bc -l)
    RATE=$(echo "scale=2; $TEST_MSGS / $DURATION" | bc -l)
    
    echo -e "Duration: ${YELLOW}${DURATION}s${NC}"
    echo -e "Rate: ${YELLOW}${RATE} msg/sec${NC}"
    
    if (( $(echo "$RATE >= 10000" | bc -l) )); then
        echo -e "${GREEN}✓ CLI throughput meets target!${NC}"
    else
        echo -e "${RED}✗ CLI throughput below target (need 10,000 msg/sec)${NC}"
    fi
    
    return 0
}

# Function to send messages in batches
test_cli_batch() {
    echo -e "\n${BLUE}Test 2: CLI Batch Mode${NC}"
    echo "Testing with batched input..."
    
    # Generate batch file
    for i in $(seq 1 $TEST_MSGS); do
        echo "Batch message $i"
    done > "$TEST_DIR/batch.txt"
    
    START=$(date +%s.%N)
    
    cat "$TEST_DIR/batch.txt" | ./target/release/jig --anon --name batchtest --channel "#batch" 2>/dev/null
    
    END=$(date +%s.%N)
    DURATION=$(echo "$END - $START" | bc -l)
    RATE=$(echo "scale=2; $TEST_MSGS / $DURATION" | bc -l)
    
    echo -e "Duration: ${YELLOW}${DURATION}s${NC}"
    echo -e "Rate: ${YELLOW}${RATE} msg/sec${NC}"
    
    if (( $(echo "$RATE >= 10000" | bc -l) )); then
        echo -e "${GREEN}✓ Batch mode meets target!${NC}"
    else
        echo -e "${RED}✗ Batch mode below target${NC}"
    fi
}

# Function to test IRC throughput
test_irc_throughput() {
    echo -e "\n${BLUE}Test 3: IRC Bridge Throughput${NC}"
    
    # Kill server and restart with IRC
    kill $SERVER_PID 2>/dev/null || true
    sleep 2
    
    ./target/release/jig-server --db-path "$DB_PATH" --irc --irc-port 6667 > "$LOG_FILE" 2>&1 &
    SERVER_PID=$!
    sleep 2
    
    echo "Testing IRC single connection..."
    
    START=$(date +%s.%N)
    
    (
        echo "NICK loadbot"
        echo "USER loadbot 0 * :Load Test Bot"
        sleep 0.5
        echo "JOIN #ircperf"
        for i in $(seq 1 $TEST_MSGS); do
            echo "PRIVMSG #ircperf :IRC message $i"
        done
        echo "QUIT"
    ) | nc -w 30 127.0.0.1 6667 > /dev/null 2>&1
    
    END=$(date +%s.%N)
    DURATION=$(echo "$END - $START" | bc -l)
    RATE=$(echo "scale=2; $TEST_MSGS / $DURATION" | bc -l)
    
    echo -e "Duration: ${YELLOW}${DURATION}s${NC}"
    echo -e "Rate: ${YELLOW}${RATE} msg/sec${NC}"
    
    if (( $(echo "$RATE >= 10000" | bc -l) )); then
        echo -e "${GREEN}✓ IRC throughput meets target!${NC}"
    else
        echo -e "${RED}✗ IRC throughput below target${NC}"
    fi
}

# Function for concurrent IRC clients
test_irc_concurrent() {
    echo -e "\n${BLUE}Test 4: Concurrent IRC Clients${NC}"
    echo "Testing 100 clients, 100 messages each (10,000 total)..."
    
    START=$(date +%s.%N)
    
    for client in $(seq 1 100); do
        (
            (
                echo "NICK user$client"
                echo "USER user$client 0 * :User $client"
                echo "JOIN #concurrent"
                for msg in $(seq 1 100); do
                    echo "PRIVMSG #concurrent :Message $msg from user$client"
                done
                echo "QUIT"
            ) | nc 127.0.0.1 6667 > /dev/null 2>&1
        ) &
    done
    
    wait
    
    END=$(date +%s.%N)
    DURATION=$(echo "$END - $START" | bc -l)
    RATE=$(echo "scale=2; 10000 / $DURATION" | bc -l)
    
    echo -e "Duration: ${YELLOW}${DURATION}s${NC}"
    echo -e "Rate: ${YELLOW}${RATE} msg/sec${NC}"
    
    if (( $(echo "$RATE >= 10000" | bc -l) )); then
        echo -e "${GREEN}✓ Concurrent clients meet target!${NC}"
    else
        echo -e "${RED}✗ Concurrent clients below target${NC}"
    fi
}

# Function to verify messages in database
verify_storage() {
    echo -e "\n${BLUE}Verifying Storage${NC}"
    
    COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM messages;" 2>/dev/null || echo 0)
    echo "Total messages stored: $COUNT"
    
    if [ "$COUNT" -gt 0 ]; then
        echo -e "${GREEN}✓ Messages successfully stored${NC}"
        
        # Check read performance
        echo "Testing read performance..."
        START=$(date +%s.%N)
        ./target/release/jig --anon read --channel "#perf" --limit 1000 > /dev/null 2>&1
        END=$(date +%s.%N)
        READ_TIME=$(echo "$END - $START" | bc -l)
        echo "Read 1000 messages in ${READ_TIME}s"
    else
        echo -e "${RED}✗ No messages in database${NC}"
    fi
}

# Function to analyze server performance
analyze_server() {
    echo -e "\n${BLUE}Server Performance Analysis${NC}"
    
    # Check for errors
    ERROR_COUNT=$(grep -c "ERROR" "$LOG_FILE" 2>/dev/null || echo 0)
    WARN_COUNT=$(grep -c "WARN" "$LOG_FILE" 2>/dev/null || echo 0)
    
    echo "Errors: $ERROR_COUNT"
    echo "Warnings: $WARN_COUNT"
    
    if [ "$ERROR_COUNT" -eq 0 ]; then
        echo -e "${GREEN}✓ No server errors${NC}"
    else
        echo -e "${RED}✗ Server reported errors${NC}"
        echo "Last 5 errors:"
        grep "ERROR" "$LOG_FILE" | tail -5
    fi
    
    # Check memory usage
    if [ -n "$SERVER_PID" ] && kill -0 $SERVER_PID 2>/dev/null; then
        MEM=$(ps -o rss= -p $SERVER_PID | awk '{print $1/1024 " MB"}')
        echo "Server memory usage: $MEM"
    fi
}

# Run tests
test_cli_throughput
test_cli_batch
test_irc_throughput
test_irc_concurrent
verify_storage
analyze_server

# Cleanup
echo -e "\n${BLUE}Cleaning up...${NC}"
kill $SERVER_PID 2>/dev/null || true
sleep 1

# Final summary
echo -e "\n${BLUE}=== Load Test Summary ===${NC}"
echo "Database size: $(du -h "$DB_PATH" 2>/dev/null | cut -f1)"
echo "Log file: $LOG_FILE"
echo "Test directory: $TEST_DIR"
echo
echo -e "${YELLOW}Note: Keep test directory for analysis, or remove with:${NC}"
echo "rm -rf $TEST_DIR"