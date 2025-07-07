#!/bin/bash

# Load environment variables
if [ -f .env ]; then
    source .env
fi

echo "🔍 Starting log tail for mcp-oauth-test-dev-worker..."
echo "Note: You need to trigger the OAuth flow in another terminal/browser to see logs"
echo ""
echo "Test URL: https://${SUBDOMAIN}.${DOMAIN}/oauth/authorize?response_type=code&client_id=claude-desktop-client&redirect_uri=https://claude.ai/api/mcp/auth_callback&code_challenge=test&code_challenge_method=S256&state=test"
echo ""
echo "Press Ctrl+C to stop..."
echo ""

# Use wrangler with the API token
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN}" npx wrangler tail mcp-oauth-test-dev-worker --format pretty