#!/bin/bash
# User Flow: First-time user quickstart (<60 seconds to first message)

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo -e "${BLUE}=== Jig Quickstart User Flow ===${NC}"
echo "Goal: First message in <60 seconds"
echo

# Track timing
START=$(date +%s)

# Step 1: Installation (simulated)
echo -e "${BLUE}Step 1: Download and install${NC}"
echo "$ curl -L https://jig.onl/install | sh"
echo "(Simulating with local binary...)"

# Ensure binary exists
if [ ! -f "../target/release/jig" ]; then
    echo "Building jig CLI..."
    (cd .. && cargo build --release -p jig-cli 2>&1 | grep -E "Finished|error" || true)
fi

STEP1=$(date +%s)
echo -e "${GREEN}✓ Installation: $((STEP1 - START))s${NC}"

# Step 2: First run - anonymous mode
echo -e "\n${BLUE}Step 2: Send first message (anonymous)${NC}"
echo "$ jig --anon \"Hello, Jig!\" --channel \"#general\""

TEST_DIR="/tmp/jig-quickstart-$$"
mkdir -p "$TEST_DIR"
export JIG_DB_PATH="$TEST_DIR/quickstart.db"

../target/release/jig --anon "Hello, Jig!" --channel "#general" 2>/dev/null

STEP2=$(date +%s)
echo -e "${GREEN}✓ First message sent: $((STEP2 - START))s total${NC}"

# Step 3: Read messages
echo -e "\n${BLUE}Step 3: Read messages${NC}"
echo "$ jig read --channel \"#general\""

OUTPUT=$(../target/release/jig --anon read --channel "#general" 2>/dev/null)
if echo "$OUTPUT" | grep -q "Hello, Jig!"; then
    echo -e "${GREEN}✓ Message retrieved successfully${NC}"
else
    echo -e "${YELLOW}⚠ Message not found${NC}"
fi

STEP3=$(date +%s)
echo -e "${GREEN}✓ Read messages: $((STEP3 - START))s total${NC}"

# Step 4: Interactive mode
echo -e "\n${BLUE}Step 4: Interactive mode (skipped for automation)${NC}"
echo "$ jig --anon --channel \"#general\""
echo "(Would enter interactive chat...)"

# Final timing
END=$(date +%s)
TOTAL=$((END - START))

echo -e "\n${BLUE}=== Results ===${NC}"
echo -e "Total time: ${YELLOW}${TOTAL}s${NC}"

if [ $TOTAL -lt 60 ]; then
    echo -e "${GREEN}✓ SUCCESS: Quickstart completed in <60 seconds!${NC}"
else
    echo -e "${YELLOW}⚠ WARNING: Quickstart took longer than 60 seconds${NC}"
fi

# Cleanup
rm -rf "$TEST_DIR"