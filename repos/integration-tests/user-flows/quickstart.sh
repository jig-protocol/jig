#!/bin/bash
# Jig Protocol - 60 Second Quickstart
# Goal: From zero to first message in under 60 seconds

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}"
echo "     ╦╦╔═╗  ╔═╗╦═╗╔═╗╔╦╗╔═╗╔═╗╔═╗╦  "
echo "     ║║║ ╦  ╠═╝╠╦╝║ ║ ║ ║ ║║  ║ ║║  "
echo "    ╚╝╩╚═╝  ╩  ╩╚═╚═╝ ╩ ╚═╝╚═╝╚═╝╩═╝"
echo -e "${NC}"
echo "    Quickstart - First message in 60 seconds"
echo

# Track timing
START=$(date +%s)

# Step 1: Check/Install
echo -e "${BLUE}[1/4] Checking installation...${NC}"
if command -v jig &> /dev/null; then
    echo -e "${GREEN}✓ Jig already installed${NC}"
else
    echo "Installing Jig..."
    # In production: curl -L https://jig.onl/install | sh
    # For testing: use local build
    if [ -f "./target/release/jig" ]; then
        echo -e "${GREEN}✓ Using local build${NC}"
        JIG="./target/release/jig"
    else
        echo "Building from source..."
        cargo build --release -p jig-cli 2>&1 | grep -E "Finished" || true
        JIG="./target/release/jig"
    fi
fi

JIG=${JIG:-jig}

# Step 2: Initialize (anonymous mode, no config needed)
echo -e "\n${BLUE}[2/4] Initializing (anonymous mode)...${NC}"
NICK="user$$"
echo -e "${GREEN}✓ Anonymous identity: $NICK${NC}"

# Step 3: Send first message
echo -e "\n${BLUE}[3/4] Sending your first message...${NC}"
echo -e "${YELLOW}$ $JIG --anon --name $NICK \"Hello from quickstart!\" --channel \"#general\"${NC}"
$JIG --anon --name "$NICK" "Hello from quickstart!" --channel "#general" 2>/dev/null
echo -e "${GREEN}✓ Message sent!${NC}"

# Step 4: Read messages
echo -e "\n${BLUE}[4/4] Reading messages...${NC}"
echo -e "${YELLOW}$ $JIG --anon read --channel \"#general\"${NC}"
echo "---"
$JIG --anon read --channel "#general" --limit 5 2>/dev/null
echo "---"

# Calculate time
END=$(date +%s)
ELAPSED=$((END - START))

echo
if [ $ELAPSED -lt 60 ]; then
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✓ SUCCESS! First message in ${ELAPSED} seconds!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
else
    echo -e "${YELLOW}⚠ Took ${ELAPSED} seconds (target: <60s)${NC}"
fi

echo
echo -e "${BLUE}Next steps:${NC}"
echo "  • Join more channels: $JIG --anon --channel \"#random\""
echo "  • Interactive mode: $JIG --anon"
echo "  • Start server: jig-server --irc"
echo "  • Connect via IRC: irssi -c localhost"
echo
echo -e "${BLUE}Learn more: https://jig.onl/docs${NC}"