# OAuth MCP Spec Compliance Migration Guide

This guide documents the migration from the legacy `@cloudflare/workers-oauth-provider` implementation to the new MCP-compliant OAuth 2.1 server.

## Overview

The refactored OAuth implementation provides:
- Full MCP (Model Context Protocol) specification compliance
- OAuth 2.1 compliance with mandatory PKCE
- RFC 7591 Dynamic Client Registration
- Enhanced security with token hashing and constant-time comparisons
- Removal of query parameter token support (security vulnerability)
- Clean modular architecture

## Key Changes

### 1. Environment Variables

**Old:**
```env
OAUTH_KV=oauth-kv-namespace
SESSION_KV=session-kv-namespace
```

**New:**
```env
KV=oauth-kv-namespace  # Single KV namespace
```

**New Optional Variables:**
```env
# Security
TOKEN_ENCRYPTION_KEY=hex-encoded-32-byte-key
ALLOWED_HOSTS=example.com,api.example.com
ALLOWED_ORIGINS=https://app.example.com
DISABLE_RATE_LIMITING=false

# GitHub org/team validation
GITHUB_ACCESS_TOKEN=ghp_xxxx
```

### 2. KV Storage Patterns

**Token Storage:**
- Old: `token:${token}` → token data
- New: `tok:${sha256(token)}` → token data with hashed lookup

**Client Storage:**
- Pattern remains: `client:${client_id}` → client data
- Added: `reg_token:${registration_token}` → client_id mapping

**Session Storage:**
- Old: `session:${session_id}` → session data
- New: `auth_session:${session_id}` → authorization session data

### 3. Token Format

Tokens are no longer accepted in query parameters:
```javascript
// ❌ Old (now rejected)
GET /mcp/resource?token=abc123

// ✅ New (required)
GET /mcp/resource
Authorization: Bearer abc123
```

### 4. Client Registration

Dynamic client registration is now supported:

```bash
# Register a new client
curl -X POST https://your-domain.com/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My MCP Client",
    "redirect_uris": ["https://app.example.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "mcp"
  }'

# Response includes registration_access_token for management
```

### 5. PKCE Requirements

PKCE is now mandatory for all authorization code flows:

```javascript
// Authorization request MUST include:
const params = new URLSearchParams({
  client_id: 'your-client-id',
  redirect_uri: 'https://app.example.com/callback',
  response_type: 'code',
  state: 'random-state',
  code_challenge: codeChallenge,       // Required
  code_challenge_method: 'S256',       // Only S256 supported
  scope: 'mcp'
});
```

### 6. Discovery Endpoints

The server provides standard OAuth 2.0 discovery:

```bash
# OAuth authorization server metadata
GET /.well-known/oauth-authorization-server

# OAuth protected resource metadata  
GET /.well-known/oauth-protected-resource
```

## Migration Steps

### Step 1: Update Environment

1. Rename `OAUTH_KV` to `KV` in your wrangler.toml or environment
2. Remove `SESSION_KV` (now uses single KV namespace)
3. Add optional security environment variables as needed

### Step 2: Update Clients

Pre-configured clients in `PRECONFIGURED_OAUTH_CLIENTS` remain compatible, but ensure:
- Public clients (like Claude Desktop) have `client_secret: ""`
- All clients have proper `redirect_uris` arrays
- Grant types include both `authorization_code` and `refresh_token`

### Step 3: Update Token Handling

If you have custom token validation:
1. Tokens are now hashed before storage
2. Use the TokenManager class for all token operations
3. Remove any query parameter token handling

### Step 4: Test OAuth Flows

Test each OAuth flow:

1. **Authorization Code Flow (with PKCE)**
   ```bash
   # Start authorization
   GET /oauth/authorize?client_id=...&code_challenge=...&code_challenge_method=S256
   
   # Exchange code for token
   POST /oauth/token
   grant_type=authorization_code&code=...&code_verifier=...
   ```

2. **Client Credentials Flow**
   ```bash
   POST /oauth/token
   grant_type=client_credentials&client_id=...&client_secret=...
   ```

3. **Refresh Token Flow**
   ```bash
   POST /oauth/token
   grant_type=refresh_token&refresh_token=...
   ```

### Step 5: Update MCP Integration

MCP endpoints now strictly require Bearer tokens:

```javascript
// Update your MCP client configuration
fetch('/mcp/endpoint', {
  headers: {
    'Authorization': 'Bearer ' + accessToken,
    'MCP-Protocol-Version': '2024-11-05',
    'Accept': 'text/event-stream' // For SSE
  }
});
```

## Security Improvements

1. **Token Hashing**: All tokens are SHA-256 hashed before storage
2. **No Query Tokens**: Query parameter tokens are explicitly rejected
3. **Constant-Time Comparisons**: Prevents timing attacks
4. **Rate Limiting**: Built-in rate limiting for registration and token endpoints
5. **DNS Rebinding Protection**: Host header validation
6. **CORS**: Proper CORS handling for all endpoints

## Troubleshooting

### Invalid Token Errors

If you get "Invalid or expired token" errors:
1. Ensure tokens are sent in Authorization header
2. Check token hasn't expired (1 hour lifetime)
3. Verify the token was issued by this server

### PKCE Validation Failures

If PKCE validation fails:
1. Ensure code_verifier is 43-128 characters
2. Use only S256 method (plain is not supported)
3. Verify challenge calculation is correct

### Client Not Found

For "Client not found" errors:
1. Check client is registered (dynamically or pre-configured)
2. Verify client_id matches exactly
3. Use `/oauth/register` endpoint for dynamic registration

## Rollback Plan

If you need to rollback:
1. Keep the old worker code as backup
2. Restore environment variable names
3. Note: Tokens issued by new system won't work with old system

## Support

For issues or questions:
1. Check the OAuth error responses - they follow RFC standards
2. Enable debug logging with `LOG_LEVEL=debug`
3. Review audit logs for token issuance history
4. Use `/health` endpoint to verify configuration