import type { Env } from '../../types';
import { createLogger } from '../../logger';
import { TokenManager } from '../tokens';
import { validateCodeVerifier } from '../pkce';

/**
 * Authorization Code Grant Implementation
 * OAuth 2.1 compliant with mandatory PKCE
 */

export interface AuthorizationCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: 'S256'; // Only S256 supported
  user_id?: string;
  user_email?: string;
  user_login?: string;
  scope: string;
  issued_at: number;
  expires_at: number;
  used: boolean;
}

export class AuthorizationCodeGrant {
  private readonly logger;
  private readonly CODE_TTL = 600; // 10 minutes
  private readonly CODE_PREFIX = 'code:';
  
  constructor(private env: Env) {
    this.logger = createLogger('AuthCodeGrant', env);
  }

  /**
   * Generate a secure authorization code
   */
  async generateAuthorizationCode(): Promise<string> {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Store authorization code with metadata
   */
  async storeAuthorizationCode(codeData: Omit<AuthorizationCode, 'issued_at' | 'expires_at' | 'used'>): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    
    const fullCodeData: AuthorizationCode = {
      ...codeData,
      issued_at: now,
      expires_at: now + this.CODE_TTL,
      used: false,
    };

    const key = `${this.CODE_PREFIX}${codeData.code}`;
    
    await this.env.KV.put(
      key,
      JSON.stringify(fullCodeData),
      { expirationTtl: this.CODE_TTL }
    );

    this.logger.info('Authorization code stored', {
      client_id: codeData.client_id,
      user_id: codeData.user_id,
      scope: codeData.scope,
    });
  }

  /**
   * Validate authorization request parameters
   */
  validateAuthorizationRequest(params: URLSearchParams): {
    valid: boolean;
    error?: string;
    error_description?: string;
  } {
    // Required parameters
    const clientId = params.get('client_id');
    const redirectUri = params.get('redirect_uri');
    const responseType = params.get('response_type');
    const codeChallenge = params.get('code_challenge');
    const codeChallengeMethod = params.get('code_challenge_method');
    const state = params.get('state');

    // Validate response_type
    if (!responseType || responseType !== 'code') {
      return {
        valid: false,
        error: 'unsupported_response_type',
        error_description: 'Only authorization code flow is supported',
      };
    }

    // Validate required parameters
    if (!clientId) {
      return {
        valid: false,
        error: 'invalid_request',
        error_description: 'client_id is required',
      };
    }

    if (!redirectUri) {
      return {
        valid: false,
        error: 'invalid_request',
        error_description: 'redirect_uri is required',
      };
    }

    // PKCE is mandatory in OAuth 2.1
    if (!codeChallenge) {
      return {
        valid: false,
        error: 'invalid_request',
        error_description: 'code_challenge is required (PKCE)',
      };
    }

    if (!codeChallengeMethod || codeChallengeMethod !== 'S256') {
      return {
        valid: false,
        error: 'invalid_request',
        error_description: 'code_challenge_method must be S256',
      };
    }

    // Validate code_challenge format (base64url)
    const base64urlRegex = /^[A-Za-z0-9_-]+$/;
    if (!base64urlRegex.test(codeChallenge)) {
      return {
        valid: false,
        error: 'invalid_request',
        error_description: 'Invalid code_challenge format',
      };
    }

    // State is recommended but not required
    if (state && state.length > 512) {
      return {
        valid: false,
        error: 'invalid_request',
        error_description: 'state parameter too long',
      };
    }

    return { valid: true };
  }

  /**
   * Exchange authorization code for tokens
   */
  async exchangeCodeForTokens(params: {
    code: string;
    client_id: string;
    client_secret?: string;
    redirect_uri: string;
    code_verifier: string;
  }): Promise<{
    success: boolean;
    tokens?: {
      access_token: string;
      refresh_token?: string;
      token_type: 'Bearer';
      expires_in: number;
      scope: string;
    };
    error?: string;
    error_description?: string;
  }> {
    const key = `${this.CODE_PREFIX}${params.code}`;
    
    // Retrieve code data
    const codeDataStr = await this.env.KV.get(key);
    
    if (!codeDataStr) {
      this.logger.warn('Authorization code not found', { code: params.code });
      return {
        success: false,
        error: 'invalid_grant',
        error_description: 'Authorization code not found or expired',
      };
    }

    let codeData: AuthorizationCode;
    try {
      codeData = JSON.parse(codeDataStr);
    } catch {
      return {
        success: false,
        error: 'server_error',
        error_description: 'Invalid code data',
      };
    }

    // Check if code has already been used
    if (codeData.used) {
      this.logger.warn('Authorization code already used', { 
        code: params.code,
        client_id: params.client_id,
      });
      
      // MUST revoke all tokens issued with this code per OAuth spec
      // This would be implemented with token revocation logic
      
      return {
        success: false,
        error: 'invalid_grant',
        error_description: 'Authorization code has already been used',
      };
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (now > codeData.expires_at) {
      this.logger.warn('Authorization code expired', { 
        code: params.code,
        expired_at: codeData.expires_at,
        now,
      });
      return {
        success: false,
        error: 'invalid_grant',
        error_description: 'Authorization code has expired',
      };
    }

    // Validate client_id matches
    if (params.client_id !== codeData.client_id) {
      this.logger.warn('Client ID mismatch', {
        provided: params.client_id,
        expected: codeData.client_id,
      });
      return {
        success: false,
        error: 'invalid_grant',
        error_description: 'Client ID mismatch',
      };
    }

    // Validate redirect_uri matches exactly
    if (params.redirect_uri !== codeData.redirect_uri) {
      this.logger.warn('Redirect URI mismatch', {
        provided: params.redirect_uri,
        expected: codeData.redirect_uri,
      });
      return {
        success: false,
        error: 'invalid_grant',
        error_description: 'Redirect URI mismatch',
      };
    }

    // Validate PKCE code_verifier
    const isValidPKCE = await validateCodeVerifier(
      params.code_verifier,
      codeData.code_challenge,
      'S256'
    );

    if (!isValidPKCE) {
      this.logger.warn('PKCE validation failed', {
        client_id: params.client_id,
      });
      return {
        success: false,
        error: 'invalid_grant',
        error_description: 'PKCE verification failed',
      };
    }

    // Mark code as used immediately to prevent replay
    codeData.used = true;
    await this.env.KV.put(key, JSON.stringify(codeData), {
      expirationTtl: 300, // Keep for 5 more minutes for audit
    });

    // Generate tokens
    const tokenManager = new TokenManager(this.env);
    const tokenResponse = await tokenManager.createAccessToken({
      client_id: codeData.client_id,
      user_id: codeData.user_id,
      user_email: codeData.user_email,
      user_login: codeData.user_login,
      scope: codeData.scope,
      grant_type: 'authorization_code',
      includeRefreshToken: true,
    });

    // Delete the used code
    await this.env.KV.delete(key);

    this.logger.info('Authorization code exchanged for tokens', {
      client_id: codeData.client_id,
      user_id: codeData.user_id,
      scope: codeData.scope,
    });

    return {
      success: true,
      tokens: tokenResponse,
    };
  }

  /**
   * Build authorization redirect URL
   */
  buildAuthorizationRedirect(params: {
    redirect_uri: string;
    code: string;
    state?: string;
  }): string {
    const url = new URL(params.redirect_uri);
    url.searchParams.set('code', params.code);
    
    if (params.state) {
      url.searchParams.set('state', params.state);
    }

    return url.toString();
  }

  /**
   * Build error redirect URL
   */
  buildErrorRedirect(params: {
    redirect_uri: string;
    error: string;
    error_description?: string;
    state?: string;
  }): string {
    const url = new URL(params.redirect_uri);
    url.searchParams.set('error', params.error);
    
    if (params.error_description) {
      url.searchParams.set('error_description', params.error_description);
    }
    
    if (params.state) {
      url.searchParams.set('state', params.state);
    }

    return url.toString();
  }
}