# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a template for deploying MCP (Model Context Protocol) servers with OAuth 2.1 authentication using Cloudflare Workers, GitHub as the identity provider, and Docker for service orchestration.

## Architecture

The system consists of three main components:

1. **Cloudflare Worker (OAuth Server)**: Handles OAuth 2.1 authorization flows, validates GitHub credentials, and proxies authenticated requests to the MCP server
2. **MCP Server**: The actual MCP implementation running in Docker (example server provided)
3. **Cloudflare Tunnel**: Provides secure external access to the Docker services

### Request Flow
- OAuth endpoints: Client → Worker → GitHub OAuth → Worker
- MCP requests: Client → Worker (validates token) → Tunnel → MCP Server

### Domain Architecture
The system uses a single domain with the OAuth Worker as the entry point:
- **Single Domain**: `subdomain.domain.com` (all requests go through Worker)
- **OAuth Endpoints**: `/oauth/*`, `/callback`, `/approve` (handled directly by Worker)
- **MCP Endpoints**: All other paths (proxied through tunnel to MCP server)

This simplified architecture:
1. Provides a single endpoint for all interactions
2. Worker validates authentication then proxies to MCP server
3. Tunnel provides secure connection without needing public DNS

### OAuth Flow
1. Client requests authorization → Immediately redirects to GitHub (no approval dialog)
2. User authenticates with GitHub → Redirects back to OAuth server
3. Server validates against access rules → Issues tokens if authorized
4. All API requests include Bearer token → Worker validates and proxies to MCP server

## Development Commands

### Full Deployment
```bash
make deploy    # Builds Worker, deploys infrastructure, starts Docker services
make destroy   # Tears down all resources
make status    # Check deployment status
make logs      # View Docker logs
make clean     # Clean build artifacts
```

### Worker Development
```bash
cd worker
npm install           # Install dependencies
wrangler dev         # Local development server
wrangler deploy      # Deploy to Cloudflare
vitest               # Run tests
```

### Testing OAuth Flow
```bash
make test-oauth      # Tests the OAuth flow with test client
```

## Configuration

Create `.env` from `.env.example` with required variables:

- **Cloudflare**: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`
- **GitHub OAuth**: `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`
- **Access Control**: `ALLOWED_GITHUB_USERS`, `ALLOWED_GITHUB_ORGS`, `ALLOWED_GITHUB_TEAMS`, `ALLOWED_EMAIL_DOMAINS`
- **Service Naming**: `SERVICE_TYPE`, `PROJECT_NAME`, `ENVIRONMENT`
- **Domain**: `DOMAIN`, `SUBDOMAIN`

Resources are automatically named using the pattern: `{SERVICE_TYPE}-{PROJECT_NAME}-{ENVIRONMENT}-{RESOURCE_TYPE}`

## Key Implementation Details

### OAuth 2.1 Compliance
- Authorization Code flow with mandatory PKCE
- Pre-registered clients in `worker/src/index.ts` (Claude Desktop + test client)
- Tokens expire after 1 hour
- GitHub used as identity provider

### Worker Request Flow
1. OAuth endpoints (`/authorize`, `/token`) handled by oauth-provider library
2. All other requests are authenticated then proxied to MCP server via tunnel
3. Access control checked against GitHub user/org/team/email configuration

### Infrastructure Management
- Terraform creates: KV namespaces, Worker deployment, Cloudflare tunnel, DNS records
- State stored locally in `terraform/terraform.tfstate`
- Docker Compose manages: MCP server + Cloudflare tunnel daemon

### Adding New MCP Servers
Replace the example server in `docker/docker-compose.yml`:
```yaml
mcp-server:
  image: your-mcp-server:tag
  # ... your configuration
```

## Common Tasks

### Update OAuth Clients
Edit `worker/src/index.ts` to modify pre-registered clients in the `clients` Map.

### Change Access Control
Update `.env` variables and redeploy:
```bash
make deploy
```

### Debug OAuth Issues
1. Check Worker logs: `wrangler tail --env production`
2. Check Docker logs: `make logs`
3. Test OAuth flow: `make test-oauth`

### Deploy to Different Domain
Update `DOMAIN` and `SUBDOMAIN` in `.env`, then `make deploy`.

## Deployment Steps

### Prerequisites
1. **Cloudflare Account**: With API token having these permissions:
   - Zone:Read, Zone:DNS:Edit
   - Account:Cloudflare Tunnel:Edit
   - Account:Workers Scripts:Edit
   - Account:Workers KV Storage:Edit

2. **GitHub OAuth App**: Create at GitHub Settings → Developer settings → OAuth Apps
   - Authorization callback URL: `https://your-subdomain.your-domain.com/callback`

3. **Docker**: Running locally (e.g., Docker Desktop or Colima)

### Step-by-Step Deployment

1. **Clone and Configure**
   ```bash
   git clone <this-repo>
   cd cloudflare-mcp-oauth-template
   cp .env.example .env
   # Edit .env with your values
   ```

2. **Set Required Variables**
   ```bash
   # Cloudflare
   CLOUDFLARE_API_TOKEN=your-api-token
   CLOUDFLARE_ACCOUNT_ID=your-account-id
   CLOUDFLARE_ZONE_ID=your-zone-id
   
   # Domain
   DOMAIN=yourdomain.com
   SUBDOMAIN=mcp-oauth
   
   # GitHub OAuth
   GITHUB_CLIENT_ID=your-github-client-id
   GITHUB_CLIENT_SECRET=your-github-client-secret
   
   # Service Naming (for multi-project management)
   SERVICE_TYPE=mcp
   PROJECT_NAME=myproject
   ENVIRONMENT=production
   
   # Access Control (optional)
   ALLOWED_GITHUB_USERS=user1,user2
   ALLOWED_GITHUB_ORGS=myorg
   ```

3. **Deploy Everything**
   ```bash
   make deploy
   ```
   This will:
   - Build the Worker with wrangler
   - Deploy infrastructure with Terraform
   - Start Docker services
   - Configure Cloudflare tunnel

4. **Test the Deployment**
   ```bash
   make test-oauth
   # Visit the URL and complete GitHub authentication
   ```

5. **Configure Claude Desktop**
   Add to Claude Desktop config:
   ```json
   {
     "mcpServers": {
       "your-server": {
         "url": "https://your-subdomain.yourdomain.com",
         "oauth": {
           "provider": "your-server",
           "clientId": "claude-desktop-client"
         }
       }
     }
   }
   ```

### Troubleshooting

**Worker Build Errors**
- Ensure wrangler is installed: `npm install -g wrangler`
- Check Node.js version: requires Node 18+

**Terraform Errors**
- Verify API token permissions
- Check account/zone IDs are correct
- Run `terraform init` in terraform directory

**OAuth Flow Issues**
- Verify GitHub OAuth callback URL matches your domain
- Check Worker logs: `wrangler tail`
- Ensure COOKIE_ENCRYPTION_KEY is being set (auto-generated)

**Docker Connection Issues**
- Verify Docker is running: `docker ps`
- Check tunnel logs: `docker logs <tunnel-container-id>`
- Ensure MCP server is accessible at configured port

## Implementation Notes

### Security Considerations
- All OAuth clients are trusted implicitly (no approval dialog)
- Access control via GitHub users/orgs/teams/email domains
- Tokens expire after 1 hour
- PKCE required for all OAuth flows
- Cookie encryption key auto-generated per deployment

### Resource Naming
All resources follow the pattern: `{SERVICE_TYPE}-{PROJECT_NAME}-{ENVIRONMENT}-{RESOURCE}`
- Tunnel: `mcp-myproject-production-tunnel`
- Worker: `mcp-myproject-production-worker`
- KV namespaces: `mcp-myproject-production-oauth-kv`

### Advanced Configuration

**Custom Origin Settings** (for long-running MCP connections):
Already configured in Terraform with:
- Connect timeout: 30s
- TCP keep-alive: 30s
- Keep-alive timeout: 60s

**Multiple MCP Servers**:
Add additional ingress rules in `terraform/main.tf` for different paths/services.

**Client Registration**:
- Pre-configured: Claude Desktop + test client
- Dynamic: POST to `/oauth/register` endpoint
- No registration protection (suitable for personal use)