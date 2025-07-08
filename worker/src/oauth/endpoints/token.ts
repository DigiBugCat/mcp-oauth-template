import { Hono } from 'hono';
import type { Env } from '../../types';
import { createLogger } from '../../logger';
import { AuthorizationCodeGrant } from '../grants/authorization-code';
import { ClientCredentialsGrant } from '../grants/client-credentials';
import { TokenManager } from '../tokens';

/**
 * OAuth 2.1 Token Endpoint
 * Handles all token grant types: authorization_code, client_credentials, refresh_token
 */

export const tokenEndpoint = new Hono<{ Bindings: Env }>();

/**
 * POST /oauth/token
 * Issues tokens based on grant type
 */
tokenEndpoint.post('/', async (c) => {
  const logger = createLogger('TokenEndpoint', c.env);
  
  // CRITICAL: No query parameters allowed per MCP spec
  const url = new URL(c.req.url);
  if (url.search) {
    logger.warn('Query parameters rejected', { 
      search: url.search,
      params: Object.fromEntries(url.searchParams),
    });
    
    return c.json({
      error: 'invalid_request',
      error_description: 'Query parameters are not allowed on token endpoint',
    }, 400);
  }

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

  const grantType = body.grant_type;
  
  logger.info('Token request', {
    grant_type: grantType,
    client_id: body.client_id,
    has_code: !!body.code,
    has_refresh_token: !!body.refresh_token,
  });

  // Route to appropriate grant handler
  switch (grantType) {
    case 'authorization_code':
      return handleAuthorizationCodeGrant(c, body);
      
    case 'client_credentials':
      return handleClientCredentialsGrant(c, body);
      
    case 'refresh_token':
      return handleRefreshTokenGrant(c, body);
      
    default:
      return c.json({
        error: 'unsupported_grant_type',
        error_description: `Grant type '${grantType}' is not supported`,
      }, 400);
  }
});

/**
 * Handle authorization code grant
 */
async function handleAuthorizationCodeGrant(
  c: any,
  body: any
): Promise<Response> {
  const logger = createLogger('TokenEndpoint:AuthCode', c.env);
  
  // Extract client credentials
  const clientCredentialsGrant = new ClientCredentialsGrant(c.env);
  const clientCreds = clientCredentialsGrant.extractClientCredentials(c.req.raw, body);
  
  const clientId = clientCreds.client_id || body.client_id;
  const clientSecret = clientCreds.client_secret || body.client_secret;
  
  // Validate required parameters
  if (!body.code) {
    return c.json({
      error: 'invalid_request',
      error_description: 'Missing required parameter: code',
    }, 400);
  }
  
  if (!body.redirect_uri) {
    return c.json({
      error: 'invalid_request',
      error_description: 'Missing required parameter: redirect_uri',
    }, 400);
  }
  
  if (!body.code_verifier) {
    return c.json({
      error: 'invalid_request',
      error_description: 'Missing required parameter: code_verifier (PKCE)',
    }, 400);
  }
  
  if (!clientId) {
    return c.json({
      error: 'invalid_request',
      error_description: 'Missing required parameter: client_id',
    }, 400);
  }

  // Check if client exists and validate credentials if provided
  const clientData = await c.env.KV.get(`client:${clientId}`);
  if (!clientData) {
    logger.warn('Client not found', { client_id: clientId });
    return c.json({
      error: 'invalid_client',
      error_description: 'Client not found',
    }, 401);
  }

  const client = JSON.parse(clientData);
  
  // Check if client requires authentication
  const isPublicClient = !client.client_secret || client.token_endpoint_auth_method === 'none';
  
  
  if (!isPublicClient && clientSecret) {
    // Confidential client - validate credentials
    const validation = await clientCredentialsGrant.validateClientCredentials(
      clientId,
      clientSecret
    );
    
    if (!validation.valid) {
      logger.warn('Invalid client credentials', { client_id: clientId });
      return c.json({
        error: 'invalid_client',
        error_description: 'Client authentication failed',
      }, 401);
    }
  } else if (!isPublicClient && !clientSecret) {
    // Confidential client but no secret provided
    logger.warn('Client authentication required but not provided', { client_id: clientId });
    return c.json({
      error: 'invalid_client',
      error_description: 'Client authentication required',
    }, 401);
  }

  // Exchange code for tokens
  const authCodeGrant = new AuthorizationCodeGrant(c.env);
  const result = await authCodeGrant.exchangeCodeForTokens({
    code: body.code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: body.redirect_uri,
    code_verifier: body.code_verifier,
  });

  if (!result.success) {
    return c.json({
      error: result.error,
      error_description: result.error_description,
    }, 400);
  }

  // Return tokens with CORS headers
  return c.json(result.tokens, 200, {
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  });
}

/**
 * Handle client credentials grant
 */
async function handleClientCredentialsGrant(
  c: any,
  body: any
): Promise<Response> {
  const logger = createLogger('TokenEndpoint:ClientCreds', c.env);
  
  // Extract client credentials
  const clientCredentialsGrant = new ClientCredentialsGrant(c.env);
  const clientCreds = clientCredentialsGrant.extractClientCredentials(c.req.raw, body);
  
  // Use extracted credentials
  const params = {
    grant_type: 'client_credentials',
    client_id: clientCreds.client_id || body.client_id,
    client_secret: clientCreds.client_secret || body.client_secret,
    scope: body.scope,
  };

  const result = await clientCredentialsGrant.issueToken(params);

  if (!result.success) {
    const status = result.error === 'invalid_client' ? 401 : 400;
    return c.json({
      error: result.error,
      error_description: result.error_description,
    }, status);
  }

  // Return token with CORS headers
  return c.json(result.token, 200, {
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  });
}

/**
 * Handle refresh token grant
 */
async function handleRefreshTokenGrant(
  c: any,
  body: any
): Promise<Response> {
  const logger = createLogger('TokenEndpoint:Refresh', c.env);
  
  // Validate required parameters
  if (!body.refresh_token) {
    return c.json({
      error: 'invalid_request',
      error_description: 'Missing required parameter: refresh_token',
    }, 400);
  }

  const tokenManager = new TokenManager(c.env);
  
  // Validate refresh token
  const tokenData = await tokenManager.validateToken(body.refresh_token);
  
  if (!tokenData || tokenData.token_type !== 'refresh') {
    logger.warn('Invalid refresh token');
    return c.json({
      error: 'invalid_grant',
      error_description: 'Invalid refresh token',
    }, 400);
  }

  // Check if client_id matches (if provided)
  if (body.client_id && body.client_id !== tokenData.client_id) {
    logger.warn('Client ID mismatch', {
      provided: body.client_id,
      expected: tokenData.client_id,
    });
    return c.json({
      error: 'invalid_grant',
      error_description: 'Client ID mismatch',
    }, 400);
  }

  // Check scope (if provided, must be subset of original)
  let scope = tokenData.scope;
  if (body.scope) {
    const requestedScopes = body.scope.split(' ');
    const originalScopes = tokenData.scope.split(' ');
    const invalidScopes = requestedScopes.filter(s => !originalScopes.includes(s));
    
    if (invalidScopes.length > 0) {
      return c.json({
        error: 'invalid_scope',
        error_description: `Invalid scope: ${invalidScopes.join(' ')}`,
      }, 400);
    }
    
    scope = body.scope;
  }

  // Rotate tokens
  const { access_token, refresh_token } = await tokenManager.rotateTokens(
    body.refresh_token,
    { scope }
  );

  logger.info('Tokens refreshed', {
    client_id: tokenData.client_id,
    user_id: tokenData.user_id,
    scope,
  });

  // Return new tokens
  return c.json({
    access_token,
    refresh_token,
    token_type: 'Bearer',
    expires_in: 3600,
    scope,
  }, 200, {
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  });
}

/**
 * OPTIONS handler for CORS preflight
 */
tokenEndpoint.options('/', (c) => {
  return c.text('', 204, {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  });
});