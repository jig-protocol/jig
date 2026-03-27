#!/bin/bash
# Verify that all tests use isolated databases and don't pollute ~/.jig/jig.db

set -e

echo "=== Verifying Test Database Isolation ==="
echo

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Backup existing database if it exists
if [ -f ~/.jig/jig.db ]; then
    echo "Backing up existing ~/.jig/jig.db..."
    cp ~/.jig/jig.db ~/.jig/jig.db.backup
    BACKUP_CREATED=true
else
    BACKUP_CREATED=false
fi

# Remove the default database to ensure tests don't use it
rm -f ~/.jig/jig.db

echo -e "${BLUE}Running all tests and checking for database pollution...${NC}"
echo

# Test 1: alice_bob.sh
echo -e "${BLUE}Testing alice_bob.sh...${NC}"
./test_alice_bob.sh > /dev/null 2>&1
if [ -f ~/.jig/jig.db ]; then
    echo -e "${RED}✗ alice_bob.sh created ~/.jig/jig.db - NOT ISOLATED${NC}"
    exit 1
else
    echo -e "${GREEN}✓ alice_bob.sh uses isolated database${NC}"
fi

# Test 2: pipe_mode.sh  
echo -e "${BLUE}Testing pipe_mode.sh...${NC}"
./test_pipe_mode.sh > /dev/null 2>&1
if [ -f ~/.jig/jig.db ]; then
    echo -e "${RED}✗ pipe_mode.sh created ~/.jig/jig.db - NOT ISOLATED${NC}"
    exit 1
else
    echo -e "${GREEN}✓ pipe_mode.sh uses isolated database${NC}"
fi

# Test 3: Direct CLI test with JIG_DB_PATH
echo -e "${BLUE}Testing direct CLI with JIG_DB_PATH...${NC}"
TEST_DB="/tmp/verify-test-$$.db"
export JIG_DB_PATH="$TEST_DB"
echo "test" | ./target/release/jig --anon --name test --channel "#test" > /dev/null 2>&1
if [ -f ~/.jig/jig.db ]; then
    echo -e "${RED}✗ CLI created ~/.jig/jig.db despite JIG_DB_PATH - NOT WORKING${NC}"
    exit 1
else
    echo -e "${GREEN}✓ CLI respects JIG_DB_PATH${NC}"
fi

# Verify the test database was actually created
if [ -f "$TEST_DB" ]; then
    echo -e "${GREEN}✓ Test database created at $TEST_DB${NC}"
    rm -f "$TEST_DB"
else
    echo -e "${RED}✗ Test database NOT created at $TEST_DB${NC}"
    exit 1
fi

# Restore backup if it existed
if [ "$BACKUP_CREATED" = true ]; then
    echo
    echo "Restoring original ~/.jig/jig.db..."
    mv ~/.jig/jig.db.backup ~/.jig/jig.db
fi

echo
echo -e "${GREEN}=== All tests properly isolated! ===${NC}"
echo
echo "Summary:"
echo "✓ alice_bob.sh uses isolated database"
echo "✓ pipe_mode.sh uses isolated database"  
echo "✓ CLI respects JIG_DB_PATH environment variable"
echo "✓ No test pollutes ~/.jig/jig.db"