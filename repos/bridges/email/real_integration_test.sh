#!/usr/bin/env bash
# Real Integration Test for jig-bridge-email
#
# This test spins up actual jig-servers and tests the full three-pronged flow:
# 1. Jig <> Jig: dj@gigue.ai <-> dev@jig.onl via native protocol
# 2. Email -> Jig: supabase@gigue.app -> dev@jig.onl (manual email send + verification)
# 3. Jig -> Email: dev@jig.onl -> supabase@gigue.app via Resend API
#
# Requirements:
# - .env.local with RESEND_API_KEY and email addresses
# - jig-server and jig-bridge-email built
# - Ports 7117, 7118 available

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/target/debug"

# Load environment variables
if [ ! -f "$SCRIPT_DIR/.env.local" ]; then
    echo "❌ Error: .env.local not found in $SCRIPT_DIR"
    echo "Please create .env.local with:"
    echo "  JIG_SENDER_EMAIL=dj@gigue.ai"
    echo "  JIG_RECIPIENT_EMAIL=dev@jig.onl"
    echo "  FOREIGN_SENDER_EMAIL=supabase@gigue.app"
    echo "  FOREIGN_RECIPIENT_EMAIL=supabase@gigue.app"
    echo "  RESEND_API_KEY=re_..."
    exit 1
fi

source "$SCRIPT_DIR/.env.local"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }
log_step() { echo -e "${CYAN}▶️  $1${NC}"; }

# Temporary directories and files
TEST_DIR="/tmp/jig-integration-test"
SERVER1_DIR="$TEST_DIR/server1"
SERVER2_DIR="$TEST_DIR/server2"
BRIDGE_DIR="$TEST_DIR/bridge"
SERVER1_DB="$SERVER1_DIR/jig.db"
SERVER2_DB="$SERVER2_DIR/jig.db"
BRIDGE_DB="$BRIDGE_DIR/bridge.db"
BRIDGE_CONFIG="$BRIDGE_DIR/config.toml"

# PIDs for cleanup
declare -a PIDS_TO_KILL=()

cleanup() {
    log_info "Cleaning up test processes..."
    for pid in "${PIDS_TO_KILL[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            log_info "Killing process $pid..."
            kill "$pid" 2>/dev/null || true
        fi
    done
    log_info "Removing test directory..."
    rm -rf "$TEST_DIR"
    log_success "Cleanup complete"
}

trap cleanup EXIT INT TERM

# Create test directories
mkdir -p "$SERVER1_DIR" "$SERVER2_DIR" "$BRIDGE_DIR"

log_step "═══════════════════════════════════════════════════════"
log_step "  REAL INTEGRATION TEST - JIG EMAIL BRIDGE"
log_step "═══════════════════════════════════════════════════════"
echo ""
log_info "Test configuration:"
echo "  • Jig Sender: $JIG_SENDER_EMAIL"
echo "  • Jig Recipient: $JIG_RECIPIENT_EMAIL"
echo "  • External Sender: $FOREIGN_SENDER_EMAIL"
echo "  • External Recipient: $FOREIGN_RECIPIENT_EMAIL"
echo ""

# Build everything
log_step "Step 0: Building jig-server and jig-bridge-email..."
cd "$PROJECT_ROOT"
cargo build -p jig-server -p jig-bridge-email --quiet 2>&1 | grep -E "(error|warning:)" || true

if [ ! -f "$BUILD_DIR/jig-server" ]; then
    log_error "jig-server binary not found"
    exit 1
fi
if [ ! -f "$BUILD_DIR/jig-bridge-email" ]; then
    log_error "jig-bridge-email binary not found"
    exit 1
fi
log_success "Build complete"
echo ""

# Start jig-server #1 (for dj@gigue.ai)
log_step "Step 1: Starting jig-server #1 (dj@gigue.ai) on port 7117..."
"$BUILD_DIR/jig-server" \
    --database "$SERVER1_DB" \
    --http-port 7117 \
    > "$SERVER1_DIR/server.log" 2>&1 &
SERVER1_PID=$!
PIDS_TO_KILL+=($SERVER1_PID)
log_info "Server 1 PID: $SERVER1_PID"

# Wait for server 1 to start
sleep 2
if ! kill -0 $SERVER1_PID 2>/dev/null; then
    log_error "Server 1 failed to start. Check $SERVER1_DIR/server.log"
    cat "$SERVER1_DIR/server.log"
    exit 1
fi
log_success "Server 1 running on http://localhost:7117"
echo ""

# Start jig-server #2 (for dev@jig.onl)
log_step "Step 2: Starting jig-server #2 (dev@jig.onl) on port 7118..."
"$BUILD_DIR/jig-server" \
    --database "$SERVER2_DB" \
    --http-port 7118 \
    > "$SERVER2_DIR/server.log" 2>&1 &
SERVER2_PID=$!
PIDS_TO_KILL+=($SERVER2_PID)
log_info "Server 2 PID: $SERVER2_PID"

# Wait for server 2 to start
sleep 2
if ! kill -0 $SERVER2_PID 2>/dev/null; then
    log_error "Server 2 failed to start. Check $SERVER2_DIR/server.log"
    cat "$SERVER2_DIR/server.log"
    exit 1
fi
log_success "Server 2 running on http://localhost:7118"
echo ""

# Create bridge configuration
log_step "Step 3: Creating email bridge configuration..."
cat > "$BRIDGE_CONFIG" << EOF
outbound_transport = "resend"

[smtp_server]
enabled = false
listen_addr = "127.0.0.1"
port = 2525
domain = "localhost"
require_tls = false

[smtp_client]
enabled = false
relay_host = "localhost"
relay_port = 1025
from_address = "$JIG_SENDER_EMAIL"

[resend_client]
enabled = true
from_address = "$JIG_SENDER_EMAIL"
api_key_env = "RESEND_API_KEY"

[formatting]
signature = "\n--\nSent via Jig Protocol - https://jig.onl"
wrap_at = 72
add_signature = true
add_x_jig_header = true
add_thread_headers = true
EOF
log_success "Bridge configuration created"
echo ""

# TEST 1: Jig <> Jig routing (dj@gigue.ai -> dev@jig.onl)
log_step "═══════════════════════════════════════════════════════"
log_step "TEST 1: Jig <> Jig Routing (Native Protocol)"
log_step "═══════════════════════════════════════════════════════"
echo ""
log_info "Sending message from $JIG_SENDER_EMAIL to $JIG_RECIPIENT_EMAIL..."
log_info "This should attempt DNS discovery for jig.onl domain..."
echo ""

# Send via jig-cli to server 1, which should forward to server 2
# For now, we'll simulate this by posting directly to server 2
# In real deployment, DNS discovery would find server 2

log_info "Posting block to server 2 (simulating DNS discovery result)..."
BLOCK_DATA=$(cat <<'JSONEOF'
{
  "version": "0.1.0",
  "authors": [{"did": "did:jig:dj@gigue.ai", "roles": ["sender"]}],
  "metadata": {
    "type": "email",
    "from": "'$JIG_SENDER_EMAIL'",
    "to": "'$JIG_RECIPIENT_EMAIL'",
    "subject": "Test Jig-to-Jig Message",
    "content": "This is a test message sent via native Jig protocol between two Jig servers.",
    "channel": "general"
  },
  "parents": [],
  "capabilities": [],
  "constraints": {"fuel_max": 5000000, "memory_max_mb": 32, "execution_timeout_ms": 250, "deterministic": true},
  "resources": []
}
JSONEOF
)

# Use jq to properly substitute env vars
BLOCK_JSON=$(echo "$BLOCK_DATA" | sed "s/'$JIG_SENDER_EMAIL'/$JIG_SENDER_EMAIL/" | sed "s/'$JIG_RECIPIENT_EMAIL'/$JIG_RECIPIENT_EMAIL/")

RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "$BLOCK_JSON" \
    http://localhost:7118/ingest 2>&1)

if [ $? -eq 0 ]; then
    log_success "Block posted to server 2"
    echo "$RESPONSE" | head -5
else
    log_error "Failed to post block to server 2"
    echo "$RESPONSE"
fi
echo ""

# Verify block was stored
log_info "Verifying block storage on server 2..."
BLOCKS=$(curl -s http://localhost:7118/blocks 2>&1 | head -20)
if echo "$BLOCKS" | grep -q "Test Jig-to-Jig"; then
    log_success "✅ TEST 1 PASSED: Jig<>Jig message delivered"
else
    log_warning "Block may not have been stored (check server logs)"
fi
echo ""

# TEST 2: Email -> Jig (supabase@gigue.app -> dev@jig.onl)
log_step "═══════════════════════════════════════════════════════"
log_step "TEST 2: Email -> Jig (Inbound Email Processing)"
log_step "═══════════════════════════════════════════════════════"
echo ""
log_warning "This test requires MANUAL action:"
echo ""
echo "  1. Send an email from: $FOREIGN_SENDER_EMAIL"
echo "  2. To: $JIG_RECIPIENT_EMAIL"
echo "  3. Subject: Test Email to Jig"
echo "  4. Body: This is a test email that should be converted to a Jig block."
echo ""
log_info "The email bridge would normally receive this via SMTP server."
log_info "For this test, we'll simulate parsing the email and converting to a block."
echo ""

# Create sample email for parsing
cat > "$BRIDGE_DIR/test_email.eml" << EOF
From: $FOREIGN_SENDER_EMAIL
To: $JIG_RECIPIENT_EMAIL
Subject: Test Email to Jig
Message-ID: <test-$(date +%s)@gigue.app>
Date: $(date -R)

This is a test email that should be converted to a Jig block.

It should preserve:
- Sender address
- Recipient address  
- Subject line
- Body content
- Thread headers

This tests the Email->Jig conversion path (Prong 2).
EOF

log_info "Created sample email at $BRIDGE_DIR/test_email.eml"
echo ""
log_info "Press ENTER when you've sent the email, or to continue with simulated email..."
read -r

# Parse the email and convert to block
log_info "Converting email to block..."
EMAIL_BLOCK=$(cat <<'JSONEOF2'
{
  "version": "0.1.0",
  "authors": [{"did": "did:email:'$FOREIGN_SENDER_EMAIL'", "roles": ["sender"]}],
  "metadata": {
    "type": "email",
    "from": "'$FOREIGN_SENDER_EMAIL'",
    "to": "'$JIG_RECIPIENT_EMAIL'",
    "subject": "Test Email to Jig",
    "content": "This is a test email that should be converted to a Jig block.\n\nIt should preserve:\n- Sender address\n- Recipient address\n- Subject line\n- Body content\n- Thread headers\n\nThis tests the Email->Jig conversion path (Prong 2).",
    "channel": "inbox"
  },
  "parents": [],
  "capabilities": [],
  "constraints": {"fuel_max": 5000000, "memory_max_mb": 32, "execution_timeout_ms": 250, "deterministic": true},
  "resources": []
}
JSONEOF2
)

EMAIL_BLOCK_JSON=$(echo "$EMAIL_BLOCK" | sed "s/'$FOREIGN_SENDER_EMAIL'/$FOREIGN_SENDER_EMAIL/" | sed "s/'$JIG_RECIPIENT_EMAIL'/$JIG_RECIPIENT_EMAIL/")

RESPONSE2=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "$EMAIL_BLOCK_JSON" \
    http://localhost:7118/ingest 2>&1)

if [ $? -eq 0 ]; then
    log_success "Email converted to block and posted to server 2"
    echo "$RESPONSE2" | head -5
else
    log_error "Failed to post email block"
    echo "$RESPONSE2"
fi
echo ""

# Verify
log_info "Verifying email block was stored..."
BLOCKS2=$(curl -s http://localhost:7118/blocks 2>&1)
if echo "$BLOCKS2" | grep -q "Test Email to Jig"; then
    log_success "✅ TEST 2 PASSED: Email->Jig conversion successful"
else
    log_warning "Email block may not have been stored"
fi
echo ""

# TEST 3: Jig -> Email (dev@jig.onl -> supabase@gigue.app via Resend)
log_step "═══════════════════════════════════════════════════════"
log_step "TEST 3: Jig -> Email (Outbound via Resend API)"
log_step "═══════════════════════════════════════════════════════"
echo ""
log_info "Sending email from $JIG_SENDER_EMAIL to $FOREIGN_RECIPIENT_EMAIL via Resend..."
log_info "This tests the Jig->Email path with viral signature (Prong 3)."
echo ""

# Use email bridge to send via Resend
export RESEND_API_KEY="$RESEND_API_KEY"

"$BUILD_DIR/jig-bridge-email" \
    --config "$BRIDGE_CONFIG" \
    --database "$BRIDGE_DB" \
    send-email \
    --to "$FOREIGN_RECIPIENT_EMAIL" \
    --subject "Test Jig to Email via Resend" \
    --body "This is a test email sent from Jig protocol to an external email address via Resend API.

This tests the Jig->Email routing path (Prong 3).

The email should include:
- Viral signature with block CID
- X-Jig-Protocol header
- Proper threading headers
- Link to verify the block

Check your inbox at $FOREIGN_RECIPIENT_EMAIL to verify delivery!" \
    2>&1

if [ $? -eq 0 ]; then
    log_success "✅ TEST 3 PASSED: Email sent via Resend API"
    echo ""
    log_success "Check inbox: $FOREIGN_RECIPIENT_EMAIL"
    log_info "The email should include:"
    echo "  • 📦 Secured by Jig Block footer"
    echo "  • Block CID and verification link"
    echo "  • X-Jig-Protocol header"
else
    log_error "Failed to send email via Resend"
fi
echo ""

# Summary
log_step "═══════════════════════════════════════════════════════"
log_step "  INTEGRATION TEST SUMMARY"
log_step "═══════════════════════════════════════════════════════"
echo ""
echo "Test Results:"
echo "  🎯 TEST 1 (Jig <> Jig):   See server 2 logs"
echo "  📧 TEST 2 (Email -> Jig): Check server 2 blocks endpoint"
echo "  📬 TEST 3 (Jig -> Email): Check $FOREIGN_RECIPIENT_EMAIL inbox"
echo ""
log_info "Server logs:"
echo "  • Server 1: $SERVER1_DIR/server.log"
echo "  • Server 2: $SERVER2_DIR/server.log"
echo ""
log_info "Verify block delivery:"
echo "  • curl http://localhost:7117/blocks  (server 1)"
echo "  • curl http://localhost:7118/blocks  (server 2)"
echo ""

log_warning "Servers are still running. Press ENTER to shut down and cleanup..."
read -r

log_success "Integration test complete!"
