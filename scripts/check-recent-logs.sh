#!/bin/bash

# Alternative: Check if there were any recent errors in the worker
echo "🔍 Checking recent worker invocations..."

# Get worker analytics for the last hour
END_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_TIME=$(date -u -v-1H +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d '1 hour ago' +"%Y-%m-%dT%H:%M:%SZ")

curl -s -X GET "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/analytics/stored" \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"filters\": {
      \"scriptName\": [\"mcp-oauth-test-dev-worker\"],
      \"datetime_geq\": \"${START_TIME}\",
      \"datetime_leq\": \"${END_TIME}\"
    },
    \"limit\": 100
  }" | jq '.result.data[] | {datetime, status, duration, logs}'

echo ""
echo "To see live logs, you'll need to:"
echo "1. Open Cloudflare Dashboard: https://dash.cloudflare.com"
echo "2. Go to Workers & Pages → mcp-oauth-test-dev-worker → Logs"
echo "3. Or update your API token with User:Memberships:Read permission"