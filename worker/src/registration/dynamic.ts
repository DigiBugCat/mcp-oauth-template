import { Hono } from 'hono';
import type { Env } from '../types';
import { validateRedirectUris, validateClientMetadata } from './validation';
import { createLogger } from '../logger';

/**
 * RFC 7591 Dynamic Client Registration Implementation
 * Allows clients to register themselves with the OAuth server
 */

export interface ClientRegistrationRequest {
  redirect_uris: string[];
  client_name: string;
  grant_types?: string[];
  response_types?: string[];
  scope?: string;
  token_endpoint_auth_method?: string;
  // MCP extensions
  mcp_version?: string;
  mcp_transport_types?: string[];
}

export interface ClientRegistrationResponse {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  client_name: string;
  grant_types: string[];
  response_types: string[];
  scope: string;
  token_endpoint_auth_method: string;
  client_id_issued_at: number;
  client_secret_expires_at: number;
  registration_access_token: string;
  registration_client_uri: string;
  // MCP extensions
  mcp_version?: string;
  mcp_transport_types?: string[];
}

export interface StoredClient {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  client_name: string;
  grant_types: string[];
  response_types: string[];
  scope: string;
  token_endpoint_auth_method: string;
  client_id_issued_at: number;
  client_secret_expires_at: number;
  registration_access_token: string;
  created_at: string;
  // MCP extensions
  mcp_version?: string;
  mcp_transport_types?: string[];
  // Additional metadata
  trusted?: boolean;
  created_by?: string;
}

export const registrationEndpoint = new Hono<{ Bindings: Env }>();

/**
 * POST /oauth/register - Register a new client
 */
registrationEndpoint.post('/', async (c) => {
  const logger = createLogger('Registration', c.env);
  
  try {
    const body = await c.req.json<ClientRegistrationRequest>();
    logger.debug('Registration request received', { client_name: body.client_name });
    
    // Validate required fields
    if (!body.redirect_uris || body.redirect_uris.length === 0) {
      logger.warn('Missing redirect_uris');
      return c.json({
        error: 'invalid_request',
        error_description: 'redirect_uris is required and must not be empty',
      }, 400);
    }
    
    if (!body.client_name) {
      logger.warn('Missing client_name');
      return c.json({
        error: 'invalid_request',
        error_description: 'client_name is required',
      }, 400);
    }
    
    // Validate redirect URIs
    const uriValidation = validateRedirectUris(body.redirect_uris);
    if (!uriValidation.valid) {
      logger.warn('Invalid redirect_uris', { error: uriValidation.error });
      return c.json({
        error: 'invalid_request',
        error_description: uriValidation.error,
      }, 400);
    }
    
    // Validate client metadata
    const metadataValidation = validateClientMetadata(body);
    if (!metadataValidation.valid) {
      logger.warn('Invalid client metadata', { error: metadataValidation.error });
      return c.json({
        error: 'invalid_request',
        error_description: metadataValidation.error,
      }, 400);
    }
    
    // Generate client credentials
    const clientId = generateClientId();
    const clientSecret = generateClientSecret();
    const registrationAccessToken = generateRegistrationAccessToken();
    
    // Determine auth method
    const authMethod = body.token_endpoint_auth_method || 'client_secret_post';
    const isPublicClient = authMethod === 'none';
    
    // Create client object
    const now = Math.floor(Date.now() / 1000);
    const client: StoredClient = {
      client_id: clientId,
      client_secret: isPublicClient ? undefined : clientSecret,
      redirect_uris: body.redirect_uris,
      client_name: body.client_name,
      grant_types: body.grant_types || ['authorization_code'],
      response_types: body.response_types || ['code'],
      scope: body.scope || 'mcp',
      token_endpoint_auth_method: authMethod,
      client_id_issued_at: now,
      client_secret_expires_at: 0, // No expiration
      registration_access_token: registrationAccessToken,
      created_at: new Date().toISOString(),
      // MCP extensions
      mcp_version: body.mcp_version,
      mcp_transport_types: body.mcp_transport_types,
      // Metadata
      trusted: false, // Dynamically registered clients are not trusted by default
      created_by: 'dynamic_registration',
    };
    
    // Store client
    await c.env.KV.put(
      `client:${clientId}`,
      JSON.stringify(client)
    );
    
    // Store registration access token mapping
    await c.env.KV.put(
      `reg_token:${registrationAccessToken}`,
      clientId,
      { expirationTtl: 365 * 24 * 60 * 60 } // 1 year
    );
    
    logger.info('Client registered successfully', {
      client_id: clientId,
      client_name: body.client_name,
      auth_method: authMethod,
    });
    
    // Build response
    const baseUrl = c.env.PUBLIC_URL || new URL(c.req.url).origin;
    const response: ClientRegistrationResponse = {
      client_id: clientId,
      client_secret: isPublicClient ? undefined : clientSecret,
      redirect_uris: client.redirect_uris,
      client_name: client.client_name,
      grant_types: client.grant_types,
      response_types: client.response_types,
      scope: client.scope,
      token_endpoint_auth_method: client.token_endpoint_auth_method,
      client_id_issued_at: client.client_id_issued_at,
      client_secret_expires_at: client.client_secret_expires_at,
      registration_access_token: registrationAccessToken,
      registration_client_uri: `${baseUrl}/oauth/register/${clientId}`,
      // MCP extensions
      mcp_version: client.mcp_version,
      mcp_transport_types: client.mcp_transport_types,
    };
    
    return c.json(response, 201);
  } catch (error) {
    logger.error('Registration failed', { error: error instanceof Error ? error.message : String(error) });
    return c.json({
      error: 'server_error',
      error_description: 'Failed to register client',
    }, 500);
  }
});

/**
 * GET /oauth/register/:client_id - Read client configuration
 */
registrationEndpoint.get('/:client_id', async (c) => {
  const logger = createLogger('Registration', c.env);
  const clientId = c.req.param('client_id');
  
  // Validate registration access token
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({
      error: 'invalid_token',
      error_description: 'Registration access token required',
    }, 401);
  }
  
  const token = authHeader.substring(7);
  const storedClientId = await c.env.KV.get(`reg_token:${token}`);
  
  if (!storedClientId || storedClientId !== clientId) {
    return c.json({
      error: 'invalid_token',
      error_description: 'Invalid registration access token',
    }, 401);
  }
  
  // Get client
  const clientData = await c.env.KV.get(`client:${clientId}`);
  if (!clientData) {
    return c.json({
      error: 'not_found',
      error_description: 'Client not found',
    }, 404);
  }
  
  const client: StoredClient = JSON.parse(clientData);
  const baseUrl = c.env.PUBLIC_URL || new URL(c.req.url).origin;
  
  const response: ClientRegistrationResponse = {
    client_id: client.client_id,
    client_secret: client.client_secret,
    redirect_uris: client.redirect_uris,
    client_name: client.client_name,
    grant_types: client.grant_types,
    response_types: client.response_types,
    scope: client.scope,
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    client_id_issued_at: client.client_id_issued_at,
    client_secret_expires_at: client.client_secret_expires_at,
    registration_access_token: client.registration_access_token,
    registration_client_uri: `${baseUrl}/oauth/register/${clientId}`,
    mcp_version: client.mcp_version,
    mcp_transport_types: client.mcp_transport_types,
  };
  
  return c.json(response);
});

/**
 * PUT /oauth/register/:client_id - Update client configuration
 */
registrationEndpoint.put('/:client_id', async (c) => {
  const logger = createLogger('Registration', c.env);
  const clientId = c.req.param('client_id');
  
  // Validate registration access token
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({
      error: 'invalid_token',
      error_description: 'Registration access token required',
    }, 401);
  }
  
  const token = authHeader.substring(7);
  const storedClientId = await c.env.KV.get(`reg_token:${token}`);
  
  if (!storedClientId || storedClientId !== clientId) {
    return c.json({
      error: 'invalid_token',
      error_description: 'Invalid registration access token',
    }, 401);
  }
  
  // Get existing client
  const existingData = await c.env.KV.get(`client:${clientId}`);
  if (!existingData) {
    return c.json({
      error: 'not_found',
      error_description: 'Client not found',
    }, 404);
  }
  
  const existing: StoredClient = JSON.parse(existingData);
  
  try {
    const body = await c.req.json<ClientRegistrationRequest>();
    
    // Validate updates
    if (body.redirect_uris) {
      const uriValidation = validateRedirectUris(body.redirect_uris);
      if (!uriValidation.valid) {
        return c.json({
          error: 'invalid_request',
          error_description: uriValidation.error,
        }, 400);
      }
    }
    
    // Update client
    const updated: StoredClient = {
      ...existing,
      redirect_uris: body.redirect_uris || existing.redirect_uris,
      client_name: body.client_name || existing.client_name,
      grant_types: body.grant_types || existing.grant_types,
      response_types: body.response_types || existing.response_types,
      scope: body.scope || existing.scope,
      mcp_version: body.mcp_version !== undefined ? body.mcp_version : existing.mcp_version,
      mcp_transport_types: body.mcp_transport_types || existing.mcp_transport_types,
    };
    
    await c.env.KV.put(
      `client:${clientId}`,
      JSON.stringify(updated)
    );
    
    logger.info('Client updated', { client_id: clientId });
    
    // Return updated client
    const baseUrl = c.env.PUBLIC_URL || new URL(c.req.url).origin;
    const response: ClientRegistrationResponse = {
      client_id: updated.client_id,
      client_secret: updated.client_secret,
      redirect_uris: updated.redirect_uris,
      client_name: updated.client_name,
      grant_types: updated.grant_types,
      response_types: updated.response_types,
      scope: updated.scope,
      token_endpoint_auth_method: updated.token_endpoint_auth_method,
      client_id_issued_at: updated.client_id_issued_at,
      client_secret_expires_at: updated.client_secret_expires_at,
      registration_access_token: updated.registration_access_token,
      registration_client_uri: `${baseUrl}/oauth/register/${clientId}`,
      mcp_version: updated.mcp_version,
      mcp_transport_types: updated.mcp_transport_types,
    };
    
    return c.json(response);
  } catch (error) {
    logger.error('Update failed', { error: error instanceof Error ? error.message : String(error) });
    return c.json({
      error: 'server_error',
      error_description: 'Failed to update client',
    }, 500);
  }
});

/**
 * DELETE /oauth/register/:client_id - Delete client
 */
registrationEndpoint.delete('/:client_id', async (c) => {
  const logger = createLogger('Registration', c.env);
  const clientId = c.req.param('client_id');
  
  // Validate registration access token
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({
      error: 'invalid_token',
      error_description: 'Registration access token required',
    }, 401);
  }
  
  const token = authHeader.substring(7);
  const storedClientId = await c.env.KV.get(`reg_token:${token}`);
  
  if (!storedClientId || storedClientId !== clientId) {
    return c.json({
      error: 'invalid_token',
      error_description: 'Invalid registration access token',
    }, 401);
  }
  
  // Delete client
  await c.env.KV.delete(`client:${clientId}`);
  await c.env.KV.delete(`reg_token:${token}`);
  
  // TODO: Revoke all tokens for this client
  
  logger.info('Client deleted', { client_id: clientId });
  
  return c.body(null, 204);
});

/**
 * Generate a unique client ID
 */
function generateClientId(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  const hex = Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
  return `client_${hex}`;
}

/**
 * Generate a secure client secret
 */
function generateClientSecret(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const base64 = btoa(String.fromCharCode(...array));
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generate a registration access token
 */
function generateRegistrationAccessToken(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const base64 = btoa(String.fromCharCode(...array));
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}