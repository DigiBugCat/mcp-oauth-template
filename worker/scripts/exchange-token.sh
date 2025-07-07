#!/bin/bash

# Exchange authorization code for token
# Usage: ./scripts/exchange-token.sh <CODE> <CODE_VERIFIER> <CLIENT_ID> <CLIENT_SECRET>

if [ $# -ne 4 ]; then
    echo "Usage: $0 <CODE> <CODE_VERIFIER> <CLIENT_ID> <CLIENT_SECRET>"
    exit 1
fi

CODE=$1
CODE_VERIFIER=$2
CLIENT_ID=$3
CLIENT_SECRET=$4
BASE_URL="${BASE_URL:-http://localhost:8787}"

echo "Exchanging code for token..."
echo ""

TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"authorization_code\",
    \"code\": \"$CODE\",
    \"client_id\": \"$CLIENT_ID\",
    \"client_secret\": \"$CLIENT_SECRET\",
    \"redirect_uri\": \"http://localhost:3000/callback\",
    \"code_verifier\": \"$CODE_VERIFIER\"
  }")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

if [ "$ACCESS_TOKEN" = "null" ]; then
    echo "Failed to get token:"
    echo "$TOKEN_RESPONSE" | jq '.'
    exit 1
fi

echo "Token received successfully:"
echo "$TOKEN_RESPONSE" | jq '.'
echo ""

echo "Testing authenticated request to MCP endpoint..."
curl -i "$BASE_URL/" \
  -H "Authorization: Bearer $ACCESS_TOKEN"