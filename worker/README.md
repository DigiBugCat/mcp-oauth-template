# MCP OAuth Server with GitHub Authentication

This is an OAuth 2.1 server that protects MCP (Model Context Protocol) servers using GitHub authentication. Built with Cloudflare Workers and the `@cloudflare/workers-oauth-provider` package.

## Architecture

```
[MCP Client] → [OAuth Worker] → [GitHub OAuth]
                     ↓
              [Validates User]
                     ↓
           [Proxies to MCP Server]
```

## Features

- **OAuth 2.1 with PKCE** - Full compliance with OAuth 2.1 security best practices
- **GitHub Authentication** - Users authenticate via GitHub OAuth
- **Flexible Access Control** - Support for:
  - GitHub usernames
  - GitHub organizations
  - GitHub teams (org/team format)
  - Email domains
- **Dynamic Client Registration** - MCP clients can register dynamically
- **Token Management** - Automatic token lifecycle with KV storage
- **MCP Proxy** - Authenticated requests are proxied to your Docker MCP server

## Setup

### 1. Create GitHub OAuth App

1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Create a new OAuth App with:
   - **Application name**: Your app name
   - **Homepage URL**: Your domain
   - **Authorization callback URL**: 
     - Local: `http://localhost:8787/callback`
     - Production: `https://your-domain.com/callback`

### 2. Configure Environment

Copy `.dev.vars.example` to `.dev.vars`:

```bash
cp .dev.vars.example .dev.vars
```

Edit `.dev.vars` with your values:

```bash
# Required
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
COOKIE_ENCRYPTION_KEY=random_string_at_least_32_chars
MCP_SERVER_URL=http://localhost:8080

# Optional Access Control
ALLOWED_GITHUB_USERS=user1,user2
ALLOWED_GITHUB_ORGS=org1,org2
ALLOWED_GITHUB_TEAMS=org1/team1,org2/team2
ALLOWED_EMAIL_DOMAINS=company.com
```

### 3. Create KV Namespace

```bash
# For local development
wrangler kv:namespace create OAUTH_KV --preview

# For production
wrangler kv:namespace create OAUTH_KV
```

Update `wrangler.toml` with the namespace IDs.

### 4. Run Locally

```bash
npm run dev
```

The server will be available at `http://localhost:8787`

## Endpoints

### OAuth Endpoints
- `GET /oauth/authorize` - OAuth authorization endpoint
- `POST /oauth/token` - Token exchange endpoint
- `POST /oauth/register` - Dynamic client registration

### OAuth Metadata
- `GET /.well-known/oauth-authorization-server` - Server metadata
- `GET /.well-known/oauth-protected-resource` - Resource metadata

### Protected Endpoints
- `/* ` - All requests to root are proxied to MCP server (requires auth)
- `/mcp/*` - MCP-specific paths (requires auth)

## Testing

### 1. Register a Test Client

```bash
curl -X POST http://localhost:8787/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test MCP Client",
    "redirect_uris": ["http://localhost:3000/callback"]
  }'
```

Save the returned `client_id` and `client_secret`.

### 2. Test OAuth Flow

1. Visit in browser:
```
http://localhost:8787/oauth/authorize?
  client_id=YOUR_CLIENT_ID&
  redirect_uri=http://localhost:3000/callback&
  response_type=code&
  code_challenge=CHALLENGE&
  code_challenge_method=S256
```

2. You'll be redirected to GitHub to authenticate
3. After approval, you'll get a code in the callback
4. Exchange the code for a token:

```bash
curl -X POST http://localhost:8787/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "YOUR_CODE",
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET",
    "redirect_uri": "http://localhost:3000/callback",
    "code_verifier": "YOUR_VERIFIER"
  }'
```

### 3. Access Protected MCP Endpoint

```bash
curl http://localhost:8787/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Deployment

### 1. Set Production Secrets

```bash
wrangler secret put GITHUB_CLIENT_ID
wrangler secret put GITHUB_CLIENT_SECRET
wrangler secret put COOKIE_ENCRYPTION_KEY
wrangler secret put MCP_SERVER_URL

# Optional
wrangler secret put ALLOWED_GITHUB_USERS
wrangler secret put ALLOWED_GITHUB_ORGS
wrangler secret put ALLOWED_GITHUB_TEAMS
wrangler secret put ALLOWED_EMAIL_DOMAINS
```

### 2. Deploy

```bash
npm run deploy
```

## Access Control

The server validates users in this order:
1. **Allowed Users** - Exact GitHub username match
2. **Allowed Orgs** - User is member of specified GitHub org
3. **Allowed Teams** - User is member of specified GitHub team
4. **Allowed Email Domains** - User's primary email domain matches

If no restrictions are configured, all authenticated GitHub users are allowed.

## How It Works

1. **Client Registration**: MCP clients register and receive OAuth credentials
2. **Authorization**: Users are redirected to GitHub for authentication
3. **Validation**: After GitHub auth, the server validates the user against access rules
4. **Token Issuance**: Valid users receive OAuth tokens with their GitHub info
5. **API Access**: Tokens are validated and user info is forwarded to the MCP server

The OAuth provider handles all token management, storage, and validation automatically.

## Troubleshooting

### "Invalid client_id" Error
- Ensure the client is registered via `/oauth/register`
- Check that you're using the correct client_id

### "User not authorized" Error
- Verify the user meets your access control criteria
- Check environment variables are set correctly

### Connection to MCP Server Failed
- Ensure MCP_SERVER_URL is correct
- Verify the MCP server is running and accessible

### Cookie Errors
- Ensure COOKIE_ENCRYPTION_KEY is at least 32 characters
- Check that cookies are enabled in your browser

## Security Notes

- All secrets should be set via `wrangler secret` for production
- COOKIE_ENCRYPTION_KEY should be a cryptographically random string
- Use HTTPS in production for all endpoints
- Tokens are encrypted and stored securely in Workers KV