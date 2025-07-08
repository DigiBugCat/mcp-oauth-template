import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { Env } from '../types';

// Import endpoints
import { authorizeEndpoint } from './endpoints/authorize';
import { tokenEndpoint } from './endpoints/token';
import { introspectEndpoint } from './endpoints/introspect';
import { revokeEndpoint } from './endpoints/revoke';

// Import registration handler
import { registrationEndpoint } from '../registration/dynamic';

/**
 * OAuth 2.1 Server Implementation
 * Compliant with RFC 6749, RFC 6750, RFC 7636 (PKCE), RFC 7662 (Introspection),
 * RFC 7009 (Revocation), RFC 7591 (Dynamic Registration), and MCP specifications
 */
export const oauthServer = new Hono<{ Bindings: Env }>();

// Apply CORS middleware to all OAuth endpoints
oauthServer.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
}));

// OAuth 2.1 Endpoints
oauthServer.route('/authorize', authorizeEndpoint);
oauthServer.route('/token', tokenEndpoint);
oauthServer.route('/introspect', introspectEndpoint);
oauthServer.route('/revoke', revokeEndpoint);

// Dynamic Client Registration (RFC 7591)
oauthServer.route('/register', registrationEndpoint);


// Health check for OAuth server
oauthServer.get('/health', async (c) => {
  return c.json({
    status: 'healthy',
    service: 'oauth-server',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
  });
});

// Handle 404s for OAuth routes
oauthServer.all('*', (c) => {
  return c.json({
    error: 'invalid_request',
    error_description: 'The requested OAuth endpoint does not exist',
  }, 404);
});