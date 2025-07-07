# Security Considerations

This document outlines the security considerations for the Cloudflare MCP OAuth Template and provides guidance for production hardening.

## ⚠️ Development vs Production

This template is designed for **local development and personal use**. It prioritizes ease of use over security. Before deploying to production, you MUST address the security issues outlined below.

## Known Security Trade-offs

### 1. CORS Configuration
- **Current**: Allows all origins (`Access-Control-Allow-Origin: *`)
- **Risk**: Any website can make requests to your OAuth server
- **Fix**: Implement origin validation based on registered client redirect URIs

### 2. OAuth Client Registration
- **Current**: `/oauth/register` endpoint is unrestricted
- **Risk**: Anyone can register unlimited OAuth clients
- **Fix**: Add authentication to registration endpoint or disable it entirely

### 3. Token Storage
- **Current**: Tokens stored unencrypted in Cloudflare KV
- **Risk**: Compromise of KV storage exposes all tokens
- **Fix**: Encrypt tokens before storage using a separate encryption key

### 4. Rate Limiting
- **Current**: Minimal rate limiting on token endpoint only
- **Risk**: Susceptible to abuse and DoS attacks
- **Fix**: Implement comprehensive rate limiting on all endpoints

### 5. Session Security
- **Current**: Session data stored unencrypted
- **Risk**: Session hijacking if KV is compromised
- **Fix**: Encrypt session data and implement session validation

## Production Hardening Checklist

### Critical Security Updates

1. **CORS Security**
   ```typescript
   // Instead of:
   headers.set('Access-Control-Allow-Origin', '*')
   
   // Use:
   const allowedOrigins = ['https://app.example.com']
   const origin = request.headers.get('Origin')
   if (allowedOrigins.includes(origin)) {
     headers.set('Access-Control-Allow-Origin', origin)
   }
   ```

2. **Secure Client Registration**
   - Remove public registration endpoint
   - Pre-register all clients through Terraform
   - Or add admin authentication to registration

3. **Token Encryption**
   ```typescript
   // Add encryption before storing tokens
   const encryptedToken = await encrypt(token, env.TOKEN_ENCRYPTION_KEY)
   await env.OAUTH_KV.put(tokenKey, encryptedToken)
   ```

4. **Comprehensive Rate Limiting**
   - Apply to all OAuth endpoints
   - Implement per-client and per-IP limits
   - Use Cloudflare Rate Limiting rules

5. **Input Validation**
   - Validate all input parameters
   - Sanitize redirect URIs
   - Implement CSRF protection

### Infrastructure Security

1. **Secrets Management**
   - Never commit `.env` files
   - Use Cloudflare Workers Secrets
   - Rotate credentials regularly

2. **Access Control**
   - Always configure GitHub access restrictions
   - Use principle of least privilege
   - Audit access logs regularly

3. **Network Security**
   - Keep services bound to localhost
   - Use Cloudflare Tunnel for external access
   - Enable Cloudflare security features (WAF, DDoS protection)

4. **Docker Security**
   - Run containers as non-root user
   - Set resource limits
   - Keep base images updated

## Local Development Best Practices

1. **Separate Environments**
   - Use `.env.local` for local development
   - Use `.env.production` for production config
   - Never mix credentials between environments

2. **Git Security**
   - Keep sensitive files in `.gitignore`
   - Use `git-secrets` to prevent accidental commits
   - Review commits before pushing

3. **Credential Rotation**
   - Rotate OAuth secrets periodically
   - Update API tokens regularly
   - Document rotation procedures

## Security Monitoring

1. **Audit Logging**
   - Monitor all authentication attempts
   - Track token usage patterns
   - Alert on suspicious activity

2. **Error Handling**
   - Never expose internal errors to clients
   - Log errors securely without sensitive data
   - Implement proper error responses

## Reporting Security Issues

If you discover a security vulnerability in this template:

1. Do NOT open a public issue
2. Contact the maintainers privately
3. Provide detailed information about the vulnerability
4. Allow time for a fix before public disclosure

## Additional Resources

- [OWASP OAuth 2.0 Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [Cloudflare Workers Security](https://developers.cloudflare.com/workers/platform/security/)
- [GitHub OAuth Apps Security](https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps)