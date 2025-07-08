# Changelog

## [2.0.0] - 2025-01-08

### Added
- Full MCP (Model Context Protocol) specification compliance
- OAuth 2.1 implementation from scratch (removed @cloudflare/workers-oauth-provider dependency)
- Mandatory PKCE with S256 only support
- Dynamic client registration (RFC 7591)
- Token introspection endpoint (RFC 7662)
- Token revocation endpoint (RFC 7009)
- SHA-256 token hashing for secure storage
- Public client support (for Claude Desktop)
- Comprehensive security middleware
- DNS rebinding protection
- Constant-time string comparisons
- Token binding support
- SSE (Server-Sent Events) transport support

### Changed
- Complete rewrite using Hono framework
- Single KV namespace (consolidated from two)
- Improved error handling with RFC-compliant responses
- Enhanced logging with structured output
- Better CORS handling per endpoint

### Security
- Tokens no longer accepted in query parameters (MCP compliance)
- All tokens hashed before storage
- Rate limiting on all sensitive endpoints
- Origin validation for all requests

### Removed
- @cloudflare/workers-oauth-provider dependency
- Query parameter token support
- Plain PKCE method support (S256 only)

## [1.0.0] - Initial Release
- Basic OAuth implementation with GitHub
- Cloudflare Tunnel integration
- Docker support for MCP servers