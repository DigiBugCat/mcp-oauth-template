# Using This Template

This file explains how to use this repository as a template for creating MCP servers with OAuth authentication.

## Quick Start

1. **Use this template** - Click "Use this template" button on GitHub
2. **Clone your new repository**
3. **Set up environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your values
   ```
4. **Deploy**:
   ```bash
   make deploy
   ```

## Required Setup

### Prerequisites
- Cloudflare account with API token
- GitHub OAuth App (create at github.com/settings/developers)
- Docker and Docker Compose installed
- Terraform installed
- Node.js 18+ installed

### Environment Variables
You must configure these in `.env`:

#### Cloudflare
- `CLOUDFLARE_API_TOKEN` - API token with Zone:Edit and Account:Cloudflare Tunnel:Edit permissions
- `CLOUDFLARE_ACCOUNT_ID` - Your Cloudflare account ID

#### GitHub OAuth
- `GITHUB_CLIENT_ID` - From your GitHub OAuth App
- `GITHUB_CLIENT_SECRET` - From your GitHub OAuth App

#### Access Control (at least one required)
- `ALLOWED_GITHUB_USERS` - Comma-separated GitHub usernames
- `ALLOWED_GITHUB_ORGS` - Comma-separated GitHub organizations
- `ALLOWED_GITHUB_TEAMS` - Comma-separated teams (format: org/team)
- `ALLOWED_EMAIL_DOMAINS` - Comma-separated email domains

#### Service Configuration
- `DOMAIN` - Your domain (e.g., example.com)
- `SUBDOMAIN` - Subdomain for the service (e.g., mcp-oauth)
- `WORKER_NAME` - Unique name for the Cloudflare Worker
- `TUNNEL_NAME` - Unique name for the Cloudflare Tunnel

## Customization Steps

### 1. Replace the Example MCP Server

Edit `docker/docker-compose.yml` to use your actual MCP server:

```yaml
mcp-server:
  image: your-mcp-server:tag
  container_name: ${TUNNEL_NAME}-mcp-server
  # Add your configuration here
  environment:
    - YOUR_ENV_VAR=value
  volumes:
    - ./your-data:/data
  networks:
    - tunnel_network
```

### 2. Update OAuth Clients

Edit `worker/src/index.ts` to add/modify OAuth clients:

```typescript
const clients = new Map([
  ["claude_desktop_client_id", {
    name: "Claude Desktop",
    redirect_uris: ["http://localhost:3000/callback"],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    scope: "read write",
    token_endpoint_auth_method: "none"
  }],
  // Add your clients here
]);
```

### 3. Configure Your GitHub OAuth App

In your GitHub OAuth App settings:
- **Authorization callback URL**: `https://your-subdomain.your-domain.com/callback`
- **Homepage URL**: `https://your-subdomain.your-domain.com`

## Deployment

```bash
# Full deployment
make deploy

# Check status
make status

# View logs
make logs

# Destroy everything
make destroy
```

## Testing

Test the OAuth flow:
```bash
make test-oauth
```

This will open your browser and walk through the OAuth flow.

## Troubleshooting

### Common Issues

1. **"Worker not found" error**
   - Wait 30-60 seconds after deployment for DNS propagation
   - Check Worker logs: `cd worker && wrangler tail --env production`

2. **"Unauthorized" errors**
   - Verify your GitHub user/org/team is in the allowed list
   - Check `.env` configuration
   - Ensure GitHub OAuth app settings are correct

3. **"Tunnel not connecting"**
   - Check Docker logs: `docker logs cloudflare-tunnel`
   - Verify Cloudflare credentials in `.env`

### Debug Commands

```bash
# Check Worker logs
cd worker && wrangler tail --env production

# Check Docker logs
docker logs cloudflare-tunnel
docker logs mcp-server

# Test OAuth endpoint
curl https://your-subdomain.your-domain.com/.well-known/oauth-authorization-server
```

## Security Notes

- Never commit `.env` or `terraform.tfstate` files
- Rotate `GITHUB_CLIENT_SECRET` regularly
- Use specific GitHub users/orgs/teams for access control
- Review Worker logs for suspicious activity

## Next Steps

After deploying:
1. Add your MCP server to Claude Desktop with the OAuth URL
2. Configure any additional MCP server settings
3. Set up monitoring/alerting as needed