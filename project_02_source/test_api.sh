#!/bin/bash

echo "======================================"
echo "        API INTEGRATION TESTS"
echo "======================================"
echo ""

BASE_URL="http://localhost:8080"
PASSED=0
FAILED=0

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

function test_endpoint() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"
    
    if echo "$actual" | grep -q "$expected"; then
        echo -e "${GREEN}✓${NC} $test_name"
        ((PASSED++))
    else
        echo -e "${RED}✗${NC} $test_name"
        echo "  Expected: $expected"
        echo "  Got: $actual"
        ((FAILED++))
    fi
}

echo "=== Test 1: Server Health Check ==="
RESPONSE=$(curl -s $BASE_URL/)
test_endpoint "Health check" "Server is running" "$RESPONSE"

echo ""
echo "=== Test 2: User Registration ==="
RESPONSE=$(curl -s -X POST $BASE_URL/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test_user_'$(date +%s)'","password":"testpass123"}')
test_endpoint "Register new user" "success" "$RESPONSE"

echo ""
echo "=== Test 3: User Login ==="
USERNAME="apitest_$(date +%s)"

# Register
curl -s -X POST $BASE_URL/api/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"testpass123\"}" > /dev/null

# Login
RESPONSE=$(curl -s -X POST $BASE_URL/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"testpass123\"}")
  
test_endpoint "Login with correct credentials" "token" "$RESPONSE"

TOKEN=$(echo $RESPONSE | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo -e "${RED}✗${NC} Failed to get token, skipping remaining tests"
    exit 1
fi

echo "  Token: ${TOKEN:0:30}..."

echo ""
echo "=== Test 4: Login with Wrong Password ==="
RESPONSE=$(curl -s -X POST $BASE_URL/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"wrongpass\"}")
test_endpoint "Login with wrong password" "error" "$RESPONSE"

echo ""
echo "=== Test 5: Create Note ==="
RESPONSE=$(curl -s -X POST $BASE_URL/api/notes/create \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"filename":"test.txt","encrypted_data":"dGVzdA==","iv":"aXY=","tag":"dGFn"}')
test_endpoint "Create note" "note_id" "$RESPONSE"

NOTE_ID=$(echo $RESPONSE | grep -o '"note_id":[0-9]*' | cut -d':' -f2)
echo "  Note ID: $NOTE_ID"

echo ""
echo "=== Test 6: Create Note Without Auth ==="
RESPONSE=$(curl -s -X POST $BASE_URL/api/notes/create \
  -H "Content-Type: application/json" \
  -d '{"filename":"test.txt","encrypted_data":"dGVzdA==","iv":"aXY=","tag":"dGFn"}')
test_endpoint "Create note without auth" "Unauthorized" "$RESPONSE"

echo ""
echo "=== Test 7: List Notes ==="
RESPONSE=$(curl -s -X GET $BASE_URL/api/notes/list \
  -H "Authorization: Bearer $TOKEN")
test_endpoint "List notes" "notes" "$RESPONSE"

echo ""
echo "=== Test 8: Get Note ==="
RESPONSE=$(curl -s -X GET "$BASE_URL/api/notes/$NOTE_ID" \
  -H "Authorization: Bearer $TOKEN")
test_endpoint "Get note" "encrypted_data" "$RESPONSE"

echo ""
echo "=== Test 9: Create Share Link ==="
RESPONSE=$(curl -s -X POST $BASE_URL/api/share/create \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"note_id\":$NOTE_ID,\"encrypted_key\":\"a2V5\",\"expire_minutes\":60,\"max_access\":5}")
test_endpoint "Create share link" "share_url" "$RESPONSE"

SHARE_TOKEN=$(echo $RESPONSE | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
echo "  Share token: ${SHARE_TOKEN:0:30}..."

echo ""
echo "=== Test 10: Access Share Link ==="
RESPONSE=$(curl -s -X GET "$BASE_URL/share/$SHARE_TOKEN")
test_endpoint "Access share link" "encrypted_key" "$RESPONSE"

echo ""
echo "=== Test 11: Access Non-existent Share Link ==="
RESPONSE=$(curl -s -X GET "$BASE_URL/share/nonexistent_token")
test_endpoint "Access non-existent link" "not found" "$RESPONSE"

echo ""
echo "======================================"
echo "         TEST SUMMARY"
echo "======================================"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo "======================================"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ ALL API TESTS PASSED!${NC}"
    exit 0
else
    echo -e "${RED}❌ SOME TESTS FAILED!${NC}"
    exit 1
fi