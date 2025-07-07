#!/bin/bash

# Test script for OAuth flow
# Usage: ./scripts/test-oauth.sh

BASE_URL="${BASE_URL:-http://localhost:8787}"

echo "OAuth Test Script"
echo "================="
echo "Base URL: $BASE_URL"
echo ""

# Function to generate PKCE challenge
generate_pkce() {
    # Generate code verifier (43-128 characters)
    CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c 1-43)
    
    # Generate code challenge (SHA256 of verifier)
    CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
    
    echo "Code Verifier: $CODE_VERIFIER"
    echo "Code Challenge: $CODE_CHALLENGE"
}

# Test 1: Check metadata endpoints
echo "1. Testing metadata endpoints..."
echo "   Authorization Server Metadata:"
curl -s "$BASE_URL/.well-known/oauth-authorization-server" | jq '.' || echo "Failed"
echo ""
echo "   Protected Resource Metadata:"
curl -s "$BASE_URL/.well-known/oauth-protected-resource" | jq '.' || echo "Failed"
echo ""

# Test 2: Register a client
echo "2. Registering test client..."
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/oauth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "OAuth Test Client",
    "redirect_uris": ["http://localhost:3000/callback"]
  }')

CLIENT_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.client_id')
CLIENT_SECRET=$(echo "$REGISTER_RESPONSE" | jq -r '.client_secret')

if [ "$CLIENT_ID" = "null" ]; then
    echo "Failed to register client:"
    echo "$REGISTER_RESPONSE" | jq '.'
    exit 1
fi

echo "Client registered successfully:"
echo "  Client ID: $CLIENT_ID"
echo "  Client Secret: $CLIENT_SECRET"
echo ""

# Test 3: Generate authorization URL
echo "3. Generating authorization URL with PKCE..."
generate_pkce
echo ""

AUTH_URL="$BASE_URL/oauth/authorize?client_id=$CLIENT_ID&redirect_uri=http://localhost:3000/callback&response_type=code&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256&scope=mcp"

echo "Authorization URL:"
echo "$AUTH_URL"
echo ""
echo "Next steps:"
echo "1. Open the above URL in your browser"
echo "2. Complete GitHub authentication"
echo "3. Copy the 'code' parameter from the callback URL"
echo "4. Run: ./scripts/exchange-token.sh <CODE> '$CODE_VERIFIER' '$CLIENT_ID' '$CLIENT_SECRET'"