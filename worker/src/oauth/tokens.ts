import type { Env } from '../types';

/**
 * Secure Token Management System
 * Implements token generation, hashing, storage, and validation
 * with SHA-256 hashing before storage for security
 */

export interface TokenData {
  token_type: 'access_token' | 'refresh_token';
  client_id: string;
  user_id?: string;
  user_email?: string;
  user_login?: string;
  scope: string;
  expires_at: number;
  created_at: number;
  // For refresh tokens
  rotation_count?: number;
  parent_token_hash?: string;
}

export interface AccessTokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  scope: string;
  refresh_token?: string;
}

export class TokenManager {
  constructor(private env: Env) {}

  /**
   * Generate a cryptographically secure access token
   * 32 bytes = 256 bits of entropy
   */
  generateAccessToken(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return this.base64urlEncode(array);
  }

  /**
   * Generate a cryptographically secure refresh token
   * 64 bytes = 512 bits of entropy
   */
  generateRefreshToken(): string {
    const array = new Uint8Array(64);
    crypto.getRandomValues(array);
    return this.base64urlEncode(array);
  }

  /**
   * Hash a token using SHA-256
   */
  async hashToken(token: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(token);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Create and store an access token
   */
  async createAccessToken(params: {
    client_id: string;
    user_id?: string;
    user_email?: string;
    user_login?: string;
    scope: string;
    includeRefreshToken?: boolean;
  }): Promise<AccessTokenResponse> {
    const accessToken = this.generateAccessToken();
    const accessTokenHash = await this.hashToken(accessToken);
    
    const expiresIn = 3600; // 1 hour
    const now = Date.now();
    
    const tokenData: TokenData = {
      token_type: 'access_token',
      client_id: params.client_id,
      user_id: params.user_id,
      user_email: params.user_email,
      user_login: params.user_login,
      scope: params.scope,
      expires_at: now + (expiresIn * 1000),
      created_at: now,
    };

    // Store token with hashed key
    await this.env.KV.put(
      `tok:${accessTokenHash}`,
      JSON.stringify(tokenData),
      { expirationTtl: expiresIn }
    );

    // Create index for client lookup
    if (params.client_id) {
      await this.env.KV.put(
        `idx:client:${params.client_id}:${accessTokenHash}`,
        '1',
        { expirationTtl: expiresIn }
      );
    }

    // Create index for user lookup
    if (params.user_id) {
      await this.env.KV.put(
        `idx:user:${params.user_id}:${accessTokenHash}`,
        '1',
        { expirationTtl: expiresIn }
      );
    }

    const response: AccessTokenResponse = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      scope: params.scope,
    };

    // Include refresh token if requested
    if (params.includeRefreshToken) {
      const refreshToken = await this.createRefreshToken({
        client_id: params.client_id,
        user_id: params.user_id,
        user_email: params.user_email,
        user_login: params.user_login,
        scope: params.scope,
      });
      response.refresh_token = refreshToken;
    }

    return response;
  }

  /**
   * Create and store a refresh token
   */
  async createRefreshToken(params: {
    client_id: string;
    user_id?: string;
    user_email?: string;
    user_login?: string;
    scope: string;
    parent_token_hash?: string;
    rotation_count?: number;
  }): Promise<string> {
    const refreshToken = this.generateRefreshToken();
    const refreshTokenHash = await this.hashToken(refreshToken);
    
    const expiresIn = 30 * 24 * 60 * 60; // 30 days
    const now = Date.now();
    
    const tokenData: TokenData = {
      token_type: 'refresh_token',
      client_id: params.client_id,
      user_id: params.user_id,
      user_email: params.user_email,
      user_login: params.user_login,
      scope: params.scope,
      expires_at: now + (expiresIn * 1000),
      created_at: now,
      rotation_count: (params.rotation_count || 0) + 1,
      parent_token_hash: params.parent_token_hash,
    };

    // Store refresh token
    await this.env.KV.put(
      `tok:${refreshTokenHash}`,
      JSON.stringify(tokenData),
      { expirationTtl: expiresIn }
    );

    // Create indexes
    if (params.client_id) {
      await this.env.KV.put(
        `idx:client:${params.client_id}:${refreshTokenHash}`,
        '1',
        { expirationTtl: expiresIn }
      );
    }

    if (params.user_id) {
      await this.env.KV.put(
        `idx:user:${params.user_id}:${refreshTokenHash}`,
        '1',
        { expirationTtl: expiresIn }
      );
    }

    // Revoke parent token if rotating
    if (params.parent_token_hash) {
      await this.revokeTokenByHash(params.parent_token_hash);
    }

    return refreshToken;
  }

  /**
   * Validate a token and return its data
   */
  async validateToken(token: string): Promise<TokenData | null> {
    const tokenHash = await this.hashToken(token);
    const storedData = await this.env.KV.get(`tok:${tokenHash}`);
    
    if (!storedData) {
      return null;
    }

    const tokenData: TokenData = JSON.parse(storedData);
    
    // Check expiration
    if (tokenData.expires_at < Date.now()) {
      // Clean up expired token
      await this.revokeTokenByHash(tokenHash);
      return null;
    }

    return tokenData;
  }

  /**
   * Introspect a token (RFC 7662)
   */
  async introspectToken(token: string): Promise<{
    active: boolean;
    scope?: string;
    client_id?: string;
    username?: string;
    token_type?: string;
    exp?: number;
    iat?: number;
    sub?: string;
  }> {
    const tokenData = await this.validateToken(token);
    
    if (!tokenData) {
      return { active: false };
    }

    return {
      active: true,
      scope: tokenData.scope,
      client_id: tokenData.client_id,
      username: tokenData.user_login,
      token_type: tokenData.token_type,
      exp: Math.floor(tokenData.expires_at / 1000),
      iat: Math.floor(tokenData.created_at / 1000),
      sub: tokenData.user_id,
    };
  }

  /**
   * Revoke a token
   */
  async revokeToken(token: string): Promise<boolean> {
    const tokenHash = await this.hashToken(token);
    return this.revokeTokenByHash(tokenHash);
  }

  /**
   * Revoke a token by its hash
   */
  private async revokeTokenByHash(tokenHash: string): Promise<boolean> {
    // Get token data first to clean up indexes
    const storedData = await this.env.KV.get(`tok:${tokenHash}`);
    if (!storedData) {
      return false;
    }

    const tokenData: TokenData = JSON.parse(storedData);
    
    // Delete the token
    await this.env.KV.delete(`tok:${tokenHash}`);
    
    // Delete indexes
    if (tokenData.client_id) {
      await this.env.KV.delete(`idx:client:${tokenData.client_id}:${tokenHash}`);
    }
    
    if (tokenData.user_id) {
      await this.env.KV.delete(`idx:user:${tokenData.user_id}:${tokenHash}`);
    }

    return true;
  }

  /**
   * Get all tokens for a client
   */
  async getClientTokens(clientId: string): Promise<string[]> {
    const keys = await this.env.KV.list({
      prefix: `idx:client:${clientId}:`,
    });
    
    return keys.keys.map(key => {
      const parts = key.name.split(':');
      return parts[parts.length - 1]; // Return token hash
    });
  }

  /**
   * Get all tokens for a user
   */
  async getUserTokens(userId: string): Promise<string[]> {
    const keys = await this.env.KV.list({
      prefix: `idx:user:${userId}:`,
    });
    
    return keys.keys.map(key => {
      const parts = key.name.split(':');
      return parts[parts.length - 1]; // Return token hash
    });
  }

  /**
   * Revoke all tokens for a client
   */
  async revokeClientTokens(clientId: string): Promise<number> {
    const tokenHashes = await this.getClientTokens(clientId);
    let revoked = 0;
    
    for (const hash of tokenHashes) {
      if (await this.revokeTokenByHash(hash)) {
        revoked++;
      }
    }
    
    return revoked;
  }

  /**
   * Revoke all tokens for a user
   */
  async revokeUserTokens(userId: string): Promise<number> {
    const tokenHashes = await this.getUserTokens(userId);
    let revoked = 0;
    
    for (const hash of tokenHashes) {
      if (await this.revokeTokenByHash(hash)) {
        revoked++;
      }
    }
    
    return revoked;
  }

  /**
   * Base64url encode
   */
  private base64urlEncode(buffer: Uint8Array): string {
    const base64 = btoa(String.fromCharCode(...buffer));
    return base64
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
}