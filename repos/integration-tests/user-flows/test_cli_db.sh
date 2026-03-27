#!/bin/bash

# Test if CLI can read from existing database

DB="/tmp/cli-db-test.db"
export JIG_DB_PATH="$DB"

# Clean up old database
rm -f "$DB"

echo "=== Creating Test Database ==="
# Send some test messages to create the database
echo "Test message 1" | ./target/release/jig --anon --name alice --channel "#chan"
echo "Test message 2" | ./target/release/jig --anon --name bob --channel "#chan"
echo "Test message 3" | ./target/release/jig --anon --name alice --channel "#other"

echo -e "\n=== Database Contents ==="
sqlite3 "$DB" "SELECT channel, sender, substr(content, 1, 50) FROM messages;"

echo -e "\n=== CLI Read Test ==="
# Try reading from #chan
./target/release/jig --anon read --channel "#chan" --limit 10

echo -e "\n=== Direct Query Test ==="
sqlite3 "$DB" "SELECT COUNT(*) as count FROM messages WHERE channel = '#chan';"
sqlite3 "$DB" "SELECT COUNT(*) as total FROM messages;"