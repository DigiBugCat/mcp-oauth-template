import { Hono } from 'hono';
import type { Env } from '../../types';
import { createLogger } from '../../logger';
import { TokenManager } from '../tokens';
import { ClientCredentialsGrant } from '../grants/client-credentials';

/**
 * OAuth 2.0 Token Introspection Endpoint (RFC 7662)
 * Allows clients to query the status and metadata of tokens
 */

export const introspectEndpoint = new Hono<{ Bindings: Env }>();

/**
 * POST /oauth/introspect
 * Introspect access or refresh tokens
 */
introspectEndpoint.post('/', async (c) => {
  const logger = createLogger('IntrospectEndpoint', c.env);
  
  // Parse request body
  let body: any;
  const contentType = c.req.header('content-type') || '';
  
  if (contentType.includes('application/x-www-form-urlencoded')) {
    body = await c.req.parseBody();
  } else if (contentType.includes('application/json')) {
    body = await c.req.json();
  } else {
    return c.json({
      error: 'invalid_request',
      error_description: 'Content-Type must be application/x-www-form-urlencoded or application/json',
    }, 400);
  }

  // Extract token
  const token = body.token;
  const tokenTypeHint = body.token_type_hint; // Optional hint: access_token or refresh_token
  
  if (!token) {
    return c.json({
      error: 'invalid_request',
      error_description: 'Missing required parameter: token',
    }, 400);
  }

  logger.info('Token introspection request', {
    token_prefix: token.substring(0, 10),
    token_type_hint: tokenTypeHint,
  });

  // Authenticate the client making the introspection request
  const clientCredentialsGrant = new ClientCredentialsGrant(c.env);
  const clientCreds = clientCredentialsGrant.extractClientCredentials(c.req.raw, body);
  
  if (!clientCreds.client_id || !clientCreds.client_secret) {
    logger.warn('Missing client credentials');
    return c.json({
      error: 'invalid_client',
      error_description: 'Client authentication required',
    }, 401);
  }

  // Validate client credentials
  const clientValidation = await clientCredentialsGrant.validateClientCredentials(
    clientCreds.client_id,
    clientCreds.client_secret
  );

  if (!clientValidation.valid) {
    logger.warn('Invalid client credentials', { client_id: clientCreds.client_id });
    return c.json({
      error: 'invalid_client',
      error_description: 'Client authentication failed',
    }, 401);
  }

  // Validate token
  const tokenManager = new TokenManager(c.env);
  const tokenData = await tokenManager.validateToken(token);

  // If token is invalid or expired, return active: false
  if (!tokenData) {
    logger.debug('Token not found or expired');
    return c.json({
      active: false,
    }, 200, {
      'Cache-Control': 'no-store',
      'Pragma': 'no-cache',
      'Access-Control-Allow-Origin': '*',
    });
  }

  // Check if requesting client is authorized to introspect this token
  // Policy: Client can only introspect its own tokens
  if (tokenData.client_id !== clientCreds.client_id) {
    logger.warn('Client not authorized to introspect token', {
      token_client: tokenData.client_id,
      requesting_client: clientCreds.client_id,
    });
    
    // Return inactive to not leak information
    return c.json({
      active: false,
    }, 200, {
      'Cache-Control': 'no-store',
      'Pragma': 'no-cache',
      'Access-Control-Allow-Origin': '*',
    });
  }

  // Build introspection response
  const response: any = {
    active: true,
    scope: tokenData.scope,
    client_id: tokenData.client_id,
    token_type: tokenData.token_type === 'refresh' ? 'refresh_token' : 'access_token',
    exp: tokenData.expires_at,
    iat: tokenData.issued_at,
  };

  // Add user context if available
  if (tokenData.user_id) {
    response.sub = tokenData.user_id;
    response.username = tokenData.user_login;
    response.email = tokenData.user_email;
  }

  // Add grant type if available
  if (tokenData.grant_type) {
    response.grant_type = tokenData.grant_type;
  }

  logger.info('Token introspection successful', {
    client_id: clientCreds.client_id,
    token_type: response.token_type,
    active: true,
  });

  return c.json(response, 200, {
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  });
});

/**
 * OPTIONS handler for CORS preflight
 */
introspectEndpoint.options('/', (c) => {
  return c.text('', 204, {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  });
});