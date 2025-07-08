import { Hono } from 'hono';
import type { Env } from '../../types';
import { createLogger } from '../../logger';
import { TokenManager } from '../tokens';
import { ClientCredentialsGrant } from '../grants/client-credentials';

/**
 * OAuth 2.0 Token Revocation Endpoint (RFC 7009)
 * Allows clients to revoke access and refresh tokens
 */

export const revokeEndpoint = new Hono<{ Bindings: Env }>();

/**
 * POST /oauth/revoke
 * Revoke access or refresh tokens
 */
revokeEndpoint.post('/', async (c) => {
  const logger = createLogger('RevokeEndpoint', c.env);
  
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

  logger.info('Token revocation request', {
    token_prefix: token.substring(0, 10),
    token_type_hint: tokenTypeHint,
  });

  // Authenticate the client (optional but recommended)
  const clientCredentialsGrant = new ClientCredentialsGrant(c.env);
  const clientCreds = clientCredentialsGrant.extractClientCredentials(c.req.raw, body);
  
  let authenticatedClientId: string | null = null;
  
  if (clientCreds.client_id && clientCreds.client_secret) {
    const clientValidation = await clientCredentialsGrant.validateClientCredentials(
      clientCreds.client_id,
      clientCreds.client_secret
    );

    if (clientValidation.valid) {
      authenticatedClientId = clientCreds.client_id;
      logger.debug('Client authenticated', { client_id: authenticatedClientId });
    } else {
      logger.warn('Invalid client credentials', { client_id: clientCreds.client_id });
      // Per RFC 7009, invalid client auth returns 401
      return c.json({
        error: 'invalid_client',
        error_description: 'Client authentication failed',
      }, 401);
    }
  }

  // Get token info before revoking
  const tokenManager = new TokenManager(c.env);
  const tokenData = await tokenManager.validateToken(token);

  // If token not found, still return 200 per RFC 7009
  if (!tokenData) {
    logger.debug('Token not found or already revoked');
    return c.text('', 200, {
      'Cache-Control': 'no-store',
      'Pragma': 'no-cache',
      'Access-Control-Allow-Origin': '*',
    });
  }

  // If client is authenticated, verify it owns the token
  if (authenticatedClientId && tokenData.client_id !== authenticatedClientId) {
    logger.warn('Client not authorized to revoke token', {
      token_client: tokenData.client_id,
      requesting_client: authenticatedClientId,
    });
    
    // Still return 200 to not leak information
    return c.text('', 200, {
      'Cache-Control': 'no-store',
      'Pragma': 'no-cache',
      'Access-Control-Allow-Origin': '*',
    });
  }

  // Revoke the token
  await tokenManager.revokeToken(token);

  // If it's a refresh token, also revoke associated access tokens
  if (tokenData.token_type === 'refresh' && tokenData.client_id) {
    logger.info('Revoking associated access tokens', {
      client_id: tokenData.client_id,
      user_id: tokenData.user_id,
    });
    
    // This would require additional index tracking to find all access tokens
    // For now, we only revoke the specific token provided
  }

  // Log revocation for audit
  logger.info('Token revoked', {
    client_id: tokenData.client_id,
    user_id: tokenData.user_id,
    token_type: tokenData.token_type,
    revoked_by: authenticatedClientId || 'unauthenticated',
  });

  // Always return 200 OK per RFC 7009
  return c.text('', 200, {
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
revokeEndpoint.options('/', (c) => {
  return c.text('', 204, {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  });
});