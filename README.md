# Cloudflare MCP OAuth Template

A production-ready OAuth 2.1 server for MCP (Model Context Protocol) servers with full compliance to the MCP authorization specification. Provides secure authentication via GitHub OAuth with enterprise-grade security features.

## Overview

This template provides:
- **OAuth 2.1 Compliant** - Full implementation with mandatory PKCE (S256 only)
- **MCP Specification Compliant** - Follows Model Context Protocol authorization requirements
- **GitHub Authentication** - Secure identity verification via GitHub OAuth
- **Dynamic Client Registration** - RFC 7591 compliant with registration access tokens
- **Token Security** - SHA-256 hashed storage, no query parameter tokens allowed
- **Access Control** - Flexible rules for users, organizations, teams, and email domains
- **Rate Limiting** - DDoS protection via Durable Objects
- **Audit Logging** - Complete authorization event tracking
- **Metrics & Monitoring** - Built-in health checks and metrics endpoints
- **Token Management** - Introspection (RFC 7662) and revocation (RFC 7009)
- **Infrastructure as Code** - Terraform automation for all resources
- **Secure Tunnel** - Cloudflare Tunnel for MCP server exposure
- Enterprise-grade logging with configurable levels

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ MCP Client  │────▶│ OAuth Worker     │────▶│ MCP Server      │
│ (Claude)    │     │ (Edge)           │     │ (Docker)        │
└─────────────┘     └──────────────────┘     └─────────────────┘
       │                    │                          │
       │                    ▼                          ▼
       │            ┌──────────────────┐     ┌─────────────────┐
       │            │ GitHub OAuth     │     │ Cloudflare      │
       │            │ Workers KV       │     │ Tunnel          │
       │            └──────────────────┘     └─────────────────┘
       │                                               │
       └──────────────────────────────────────────────┘
                    (Single domain - all through Worker)

Domain Architecture:
- Single endpoint: subdomain.domain.com (Worker handles everything)
- OAuth paths: /oauth/*, /callback, /approve (handled by Worker)
- MCP paths: All other paths (Worker proxies to MCP via tunnel)
```

## Quick Start

### Prerequisites

- Cloudflare account with Workers enabled
- Docker and Docker Compose
- Terraform installed
- Node.js 18+ (for Worker development)

### 1. Create GitHub OAuth App

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in:
   - **Application name**: Your MCP Server Name
   - **Homepage URL**: `https://your-subdomain.your-domain.com`
   - **Authorization callback URL**: `https://your-subdomain.your-domain.com/oauth/callback`
4. Save the Client ID and Client Secret

### 2. Clone and Configure

```bash
git clone https://github.com/your-org/cloudflare-mcp-oauth-template
cd cloudflare-mcp-oauth-template

# Copy environment template
cp .env.example .env

# Edit .env with your configuration
```

Required variables:
- `CLOUDFLARE_API_TOKEN` - API token with Workers, KV, and DNS permissions
- `CLOUDFLARE_ACCOUNT_ID` - Your Cloudflare account ID
- `CLOUDFLARE_ZONE_ID` - Zone ID for your domain
- `DOMAIN` - Your domain (e.g., example.com)
- `SUBDOMAIN` - Subdomain for the MCP server
- `SERVICE_TYPE` - Type of service (e.g., mcp, api, web)
- `PROJECT_NAME` - Your project name (e.g., oauth-example, chatbot)
- `ENVIRONMENT` - Environment (production, staging, development)
- `GITHUB_CLIENT_ID` - From GitHub OAuth App
- `GITHUB_CLIENT_SECRET` - From GitHub OAuth App

The deployment will automatically generate consistent names:
- Tunnel: `${SERVICE_TYPE}-${PROJECT_NAME}-${ENVIRONMENT}-tunnel`
- Worker: `${SERVICE_TYPE}-${PROJECT_NAME}-${ENVIRONMENT}-worker`
- KV Namespaces: `${SERVICE_TYPE}-${PROJECT_NAME}-${ENVIRONMENT}-oauth-kv`

### 3. Deploy

```bash
make deploy
```

This will:
1. Build the OAuth Worker
2. Deploy infrastructure with Terraform (creates tunnel and outputs credentials)
3. Generate tunnel configuration files from Terraform outputs
4. Start Docker services with mounted credentials

### 4. Register with Claude Desktop

1. Open Claude Desktop settings
2. Go to Developer > Model Context Protocol
3. Add server with URL: `https://your-subdomain.your-domain.com` (no `/mcp` suffix needed)
4. Complete GitHub authentication when prompted

## OAuth Flow

1. **Authorization Request**: Claude initiates OAuth flow with PKCE
2. **GitHub Authentication**: User signs in with GitHub
3. **Access Control**: Worker validates user against configured rules
4. **Token Exchange**: Authorization code exchanged for access token
5. **Authenticated Access**: All MCP requests include Bearer token

## Access Control

Configure who can access your MCP server using environment variables:

### Allow Specific Users
```bash
ALLOWED_GITHUB_USERS=alice,bob,charlie
```

### Allow Organization Members
```bash
ALLOWED_GITHUB_ORGS=my-org,another-org
```

### Allow Team Members
```bash
ALLOWED_GITHUB_TEAMS=my-org/developers,my-org/admins
```

### Allow Email Domains
```bash
ALLOWED_EMAIL_DOMAINS=company.com,partner.com
```

**Note**: If no restrictions are set, all authenticated GitHub users are allowed.

## Resource Naming Convention

To avoid conflicts when deploying multiple services, this template uses a structured naming convention:

```
{SERVICE_TYPE}-{PROJECT_NAME}-{ENVIRONMENT}-{RESOURCE_TYPE}
```

Examples:
- `mcp-chatbot-production-tunnel`
- `mcp-analytics-staging-worker`
- `api-gateway-development-oauth-kv`

This ensures:
- No naming conflicts between projects
- Clear identification of resources in Cloudflare dashboard
- Easy filtering by service type, project, or environment
- Consistent naming across all infrastructure components

## Customization

### Adding Your MCP Server

Replace the example MCP server in `docker/docker-compose.yml`:

```yaml
services:
  mcp-server:
    image: your-mcp-server:latest
    container_name: ${MCP_SERVER_NAME}-server
    environment:
      - YOUR_ENV_VARS=values
    ports:
      - "127.0.0.1:8080:8080"
```

### Pre-registered Clients

The template includes two pre-registered OAuth clients:
- **Claude Desktop**: `claude-desktop-client`
- **Test Client**: `test-client` (for development)

Add more clients in `terraform/main.tf`.

### Advanced Origin Configuration

The template includes configurable origin request settings for MCP servers that may require longer timeouts or custom connection behavior:

```hcl
# In terraform/variables.tf, customize the defaults:
variable "origin_request_config" {
  default = {
    connect_timeout    = "30s"    # Connection timeout
    tcp_keep_alive     = "30s"    # TCP keep-alive interval
    keep_alive_timeout = "60s"    # Keep-alive timeout
    no_tls_verify      = false    # Set to true for self-signed certs
  }
}
```

This is particularly useful for:
- MCP servers with long-running operations
- Development environments with self-signed certificates
- Servers requiring persistent connections for streaming

## API Endpoints

### OAuth Endpoints
- `GET /oauth/authorize` - OAuth authorization endpoint
- `POST /oauth/token` - Token endpoint (supports authorization_code and refresh_token grants)
- `POST /oauth/register` - Dynamic client registration (RFC 7591)
- `POST /oauth/introspect` - Token introspection (RFC 7662)
- `POST /oauth/revoke` - Token revocation (RFC 7009)
- `GET /.well-known/oauth-authorization-server` - OAuth metadata

### Monitoring Endpoints
- `GET /health` - Health check endpoint with dependency status
- `GET /metrics` - Metrics endpoint with query parameters:
  - `?name=metric_name` - Get specific metric
  - `?hours=24` - Time range in hours (default: 1)
  - `?aggregation=sum` - Aggregation type (sum, avg, max, min, count)

### Configuration Options
- `LOG_LEVEL` - Set to ERROR, WARN, INFO, or DEBUG (default: INFO)
- `RATE_LIMITER` - Automatically configured when deployed (10 requests/minute per IP)

## Operations

### View Logs
```bash
make logs
```

### Check Status
```bash
make status
```

### Destroy Deployment
```bash
make destroy
```

### Clean Build Artifacts
```bash
make clean
```

## Troubleshooting

### Common Issues

1. **"Invalid client_id" error**
   - Ensure client is pre-registered in Terraform
   - Check that client_id matches exactly

2. **"User not authorized" error**
   - Check access control environment variables
   - Ensure user meets configured criteria

3. **GitHub OAuth errors**
   - Verify GitHub OAuth App configuration
   - Check callback URL matches exactly
   - Ensure Client ID and Secret are correct

4. **Tunnel connection issues**
   - Check Docker logs: `make logs`
   - Verify tunnel credentials were generated
   - Ensure MCP server is healthy

### Debug Commands

```bash
# Check Worker logs
wrangler tail mcp-oauth-YOUR_SERVER_NAME

# Test OAuth metadata
curl https://your-subdomain.your-domain.com/.well-known/oauth-authorization-server

# Check tunnel status
docker exec YOUR_SERVER_NAME-cloudflared cloudflared tunnel info
```

## Security Best Practices

1. **Access Control**: Always configure access restrictions in production
2. **HTTPS Only**: All traffic is encrypted via Cloudflare
3. **Token Expiration**: Access tokens expire after 1 hour
4. **PKCE Required**: All OAuth flows must use PKCE
5. **No Password Storage**: Authentication delegated to GitHub

## License

MIT