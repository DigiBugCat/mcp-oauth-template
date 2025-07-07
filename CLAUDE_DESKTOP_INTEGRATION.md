# Claude Desktop OAuth Integration Notes

This document captures the specific implementation details and quirks discovered while integrating OAuth 2.1 with Claude Desktop and other MCP clients.

## Key Discoveries

### 1. PKCE Support for Public Clients

**Issue**: Claude Desktop and MCP Playground don't send `client_secret` in token requests.

**Solution**: Implemented PKCE (Proof Key for Code Exchange) support that bypasses the OAuth provider library's token exchange:

```typescript
// In index.ts - Handle PKCE token exchange before OAuth provider
if (url.pathname === '/oauth/token' && request.method === 'POST') {
  const formData = await request.formData();
  const grantType = formData.get('grant_type');
  
  if (grantType === 'authorization_code' && formData.get('code_verifier')) {
    // Custom PKCE validation logic
    // OAuth provider library doesn't support public clients properly
  }
}
```

### 2. Token Format Requirements

**Issue**: The `@cloudflare/workers-oauth-provider` library expects tokens in format `{userId}:{grantId}:{random-secret}`.

**Solution**: 
- Changed token format to `token_{UUID}` matching other implementations
- Store tokens using the token itself as the key in KV storage
- Implemented manual Bearer token validation for MCP routes

### 3. SSE Authentication Limitations

**Issue**: Browser EventSource API doesn't support Authorization headers, causing "Failed to fetch" errors.

**Solution**: Added query parameter authentication as fallback:

```typescript
// Accept token from either header or query parameter
const authHeader = request.headers.get('Authorization');
const queryToken = new URL(request.url).searchParams.get('token');

let token = authHeader ? authHeader.substring(7) : queryToken;
```

### 4. MCP Protocol Requirements

**Discovery**: MCP servers use a dual-transport system:
- GET requests for SSE (Server-Sent Events) - server to client
- POST requests for JSON-RPC - client to server
- Server sends initial SSE event with sessionId: `event: endpoint\ndata: /mcp?sessionId=xxx`
- All subsequent POST requests must include this sessionId

### 5. Manual Route Handling

**Issue**: OAuth provider library intercepts all requests to protected routes, preventing custom authentication.

**Solution**: Handle MCP routes manually before the OAuth provider:

```typescript
// In index.ts fetch handler
if (url.pathname === '/mcp' || url.pathname.startsWith('/mcp/')) {
  return mcpAuthHandler(request, env, ctx);
}

// Let OAuth provider handle its routes
return provider.fetch(request, env, ctx);
```

## Working Configuration

### Pre-registered Clients

The system includes two pre-registered OAuth clients that work differently:

1. **Claude Desktop** (`claude-desktop-client`)
   - Public client (no secret)
   - Uses PKCE for security
   - Redirect URI: `https://claude.ai/api/mcp/auth_callback`

2. **Test Client** (`test-client`)
   - Confidential client (has secret)
   - For testing without PKCE
   - Redirect URI: `http://localhost:3000/oauth_callback`

### Critical Implementation Details

1. **No Approval Dialog**: All registered clients are trusted implicitly. The approval handler auto-approves without user consent UI.

2. **GitHub as Identity Provider Only**: GitHub OAuth is used solely for user authentication. The Worker generates its own authorization codes and tokens.

3. **Single Domain Architecture**: Everything goes through the Worker. No separate subdomain needed for the MCP server.

4. **CORS Headers Required**: Browser-based MCP clients need comprehensive CORS headers on all responses.

## Browser vs Native Client Differences

### Claude Desktop (Native)
- Can send Authorization headers properly
- Works with standard OAuth flow
- No CORS issues

### MCP Playground (Browser)
- Cannot send Authorization headers with EventSource
- Needs CORS headers on all responses
- Would benefit from cookie-based auth or query parameter tokens

## Debugging Tips

1. **Enable Debug Logging**:
   ```typescript
   const logger = createLogger('ServiceName', env);
   logger.debug('Detailed information', { data });
   ```

2. **Check Token Format**:
   - Tokens should be `token_{UUID}` format
   - Stored in KV with token as key (not a constructed key)

3. **Monitor SSE Connections**:
   - MCP server should return 200 with `Content-Type: text/event-stream`
   - First event should contain sessionId
   - Check browser DevTools for "Failed to fetch" errors

4. **Test OAuth Flow**:
   ```bash
   make test-oauth
   ```

## Future Improvements

1. **Cookie-Based Authentication**: Would solve EventSource header limitations
2. **WebSocket Transport**: Alternative to SSE that supports headers
3. **Token in URL**: Already implemented as fallback
4. **Session Management**: Track SSE sessions for better debugging