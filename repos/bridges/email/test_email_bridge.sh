#!/bin/bash
# Start email bridge
./target/release/jig-bridge-email --config email.toml &
BRIDGE_PID=$!

# Send test email via SMTP
if command -v mail >/dev/null 2>&1; then
  echo "Test email body" | mail -s "Test Subject" test@localhost
fi

# Verify message appears in Jig (placeholder command)
./target/release/jig read --channel "#email" | grep "Test Subject"

# Send Jig message to email
echo "Reply from Jig" | ./target/release/jig send --channel "#email"

# Check email was sent (would need real SMTP for full test)
wait $BRIDGE_PID
