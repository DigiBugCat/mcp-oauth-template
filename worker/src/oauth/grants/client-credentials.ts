import type { Env } from '../../types';
import { createLogger } from '../../logger';
import { TokenManager } from '../tokens';

/**
 * Client Credentials Grant Implementation
 * OAuth 2.1 compliant for machine-to-machine authentication
 */

export interface ClientCredentialsRequest {
  grant_type: 'client_credentials';
  client_id: string;
  client_secret: string;
  scope?: string;
}

export class ClientCredentialsGrant {
  private readonly logger;
  
  constructor(private env: Env) {
    this.logger = createLogger('ClientCredentialsGrant', env);
  }

  /**
   * Validate client credentials
   */
  async validateClientCredentials(
    clientId: string, 
    clientSecret: string
  ): Promise<{
    valid: boolean;
    client?: {
      client_id: string;
      client_name: string;
      scope: string;
    };
  }> {
    // Retrieve client from KV
    const clientKey = `client:${clientId}`;
    const clientDataStr = await this.env.KV.get(clientKey);
    
    if (!clientDataStr) {
      this.logger.warn('Client not found', { client_id: clientId });
      return { valid: false };
    }

    let clientData;
    try {
      clientData = JSON.parse(clientDataStr);
    } catch {
      this.logger.error('Invalid client data', { client_id: clientId });
      return { valid: false };
    }

    // Constant-time comparison for client secret
    if (!this.constantTimeEqual(clientSecret, clientData.client_secret)) {
      this.logger.warn('Invalid client secret', { client_id: clientId });
      return { valid: false };
    }

    // Check if client is allowed to use client_credentials grant
    if (!clientData.grant_types || !clientData.grant_types.includes('client_credentials')) {
      this.logger.warn('Client not authorized for client_credentials grant', { 
        client_id: clientId,
        grant_types: clientData.grant_types,
      });
      return { valid: false };
    }

    return {
      valid: true,
      client: {
        client_id: clientData.client_id,
        client_name: clientData.client_name || clientData.client_id,
        scope: clientData.scope || 'mcp',
      },
    };
  }

  /**
   * Validate requested scope against client's allowed scope
   */
  validateScope(requestedScope: string | undefined, allowedScope: string): {
    valid: boolean;
    scope: string;
    error?: string;
  } {
    // If no scope requested, use client's default scope
    if (!requestedScope) {
      return { valid: true, scope: allowedScope };
    }

    const requested = requestedScope.split(' ').filter(s => s);
    const allowed = allowedScope.split(' ').filter(s => s);

    // Check if all requested scopes are allowed
    const unauthorized = requested.filter(s => !allowed.includes(s));
    
    if (unauthorized.length > 0) {
      this.logger.warn('Unauthorized scope requested', {
        requested,
        allowed,
        unauthorized,
      });
      return {
        valid: false,
        scope: '',
        error: `Unauthorized scope: ${unauthorized.join(' ')}`,
      };
    }

    return { valid: true, scope: requested.join(' ') };
  }

  /**
   * Issue access token for client credentials grant
   */
  async issueToken(params: ClientCredentialsRequest): Promise<{
    success: boolean;
    token?: {
      access_token: string;
      token_type: 'Bearer';
      expires_in: number;
      scope: string;
    };
    error?: string;
    error_description?: string;
  }> {
    // Validate grant_type
    if (params.grant_type !== 'client_credentials') {
      return {
        success: false,
        error: 'unsupported_grant_type',
        error_description: 'Only client_credentials grant type is supported by this endpoint',
      };
    }

    // Validate required parameters
    if (!params.client_id || !params.client_secret) {
      return {
        success: false,
        error: 'invalid_request',
        error_description: 'client_id and client_secret are required',
      };
    }

    // Validate client credentials
    const clientValidation = await this.validateClientCredentials(
      params.client_id,
      params.client_secret
    );

    if (!clientValidation.valid || !clientValidation.client) {
      return {
        success: false,
        error: 'invalid_client',
        error_description: 'Client authentication failed',
      };
    }

    // Validate scope
    const scopeValidation = this.validateScope(
      params.scope,
      clientValidation.client.scope
    );

    if (!scopeValidation.valid) {
      return {
        success: false,
        error: 'invalid_scope',
        error_description: scopeValidation.error,
      };
    }

    // Generate access token only (no refresh token for client credentials)
    const tokenManager = new TokenManager(this.env);
    const accessToken = await tokenManager.generateAccessToken();

    // Store token without user context (machine-to-machine)
    await tokenManager.storeToken(accessToken, {
      client_id: clientValidation.client.client_id,
      scope: scopeValidation.scope,
      token_type: 'access',
      grant_type: 'client_credentials',
    });

    this.logger.info('Client credentials token issued', {
      client_id: clientValidation.client.client_id,
      scope: scopeValidation.scope,
    });

    return {
      success: true,
      token: {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        scope: scopeValidation.scope,
      },
    };
  }

  /**
   * Constant-time string comparison to prevent timing attacks
   */
  private constantTimeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
  }

  /**
   * Parse client credentials from Authorization header
   */
  parseBasicAuth(authHeader: string): {
    client_id?: string;
    client_secret?: string;
  } {
    if (!authHeader.startsWith('Basic ')) {
      return {};
    }

    try {
      const base64 = authHeader.substring(6);
      const decoded = atob(base64);
      const [clientId, clientSecret] = decoded.split(':');
      
      return {
        client_id: clientId,
        client_secret: clientSecret,
      };
    } catch {
      return {};
    }
  }

  /**
   * Extract client credentials from request
   * Supports both Authorization header and body parameters
   */
  extractClientCredentials(request: Request, body: any): {
    client_id?: string;
    client_secret?: string;
  } {
    // First check Authorization header (preferred)
    const authHeader = request.headers.get('Authorization');
    if (authHeader && authHeader.startsWith('Basic ')) {
      const basicAuth = this.parseBasicAuth(authHeader);
      if (basicAuth.client_id && basicAuth.client_secret) {
        return basicAuth;
      }
    }

    // Fall back to body parameters
    return {
      client_id: body.client_id,
      client_secret: body.client_secret,
    };
  }
}