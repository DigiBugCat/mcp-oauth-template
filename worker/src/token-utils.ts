import { Env, AccessToken, RefreshToken } from './types';
import { createLogger } from './logger';

export class TokenManager {
  private env: Env;
  private logger: ReturnType<typeof createLogger>;

  constructor(env: Env) {
    this.env = env;
    this.logger = createLogger('TokenManager', env);
  }

  private generateToken(prefix: string = 'token'): string {
    // Match Rust implementation: prefix_{UUID}
    return `${prefix}_${crypto.randomUUID()}`;
  }

  async createAccessToken(data: {
    client_id: string;
    user_id: string;
    user_email: string;
    user_login: string;
    scope: string;
    includeRefreshToken?: boolean;
  }): Promise<{ access_token: string; refresh_token?: string; expires_in: number }> {
    const accessToken = this.generateToken('token');
    const expiresIn = 3600; // 1 hour
    const now = new Date();
    const expiresAt = new Date(now.getTime() + expiresIn * 1000);

    const tokenData: AccessToken = {
      token: accessToken,
      client_id: data.client_id,
      user_id: data.user_id,
      user_email: data.user_email,
      user_login: data.user_login,
      scope: data.scope,
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
    };

    let refreshToken: string | undefined;
    
    if (data.includeRefreshToken) {
      refreshToken = this.generateToken('refresh');
      tokenData.refresh_token = refreshToken;
      
      // Store refresh token with 30-day expiration
      const refreshExpiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
      const refreshTokenData: RefreshToken = {
        token: refreshToken,
        client_id: data.client_id,
        user_id: data.user_id,
        user_email: data.user_email,
        user_login: data.user_login,
        scope: data.scope,
        created_at: now.toISOString(),
        expires_at: refreshExpiresAt.toISOString(),
        access_token: accessToken,
      };
      
      await this.env.OAUTH_KV.put(
        refreshToken, // Use token itself as key, matching Rust
        JSON.stringify(refreshTokenData),
        { expirationTtl: 30 * 24 * 60 * 60 } // 30 days
      );
      
      this.logger.debug('Refresh token created', { 
        client_id: data.client_id,
        user_id: data.user_id,
      });
    }

    // Store access token using token itself as key
    await this.env.OAUTH_KV.put(
      accessToken, // Use token itself as key, matching Rust
      JSON.stringify(tokenData),
      { expirationTtl: expiresIn }
    );

    this.logger.info('Access token created', {
      client_id: data.client_id,
      user_id: data.user_id,
      has_refresh_token: !!refreshToken,
    });

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: expiresIn,
    };
  }

  async validateRefreshToken(refreshToken: string): Promise<RefreshToken | null> {
    const data = await this.env.OAUTH_KV.get(refreshToken);
    if (!data) {
      this.logger.debug('Refresh token not found');
      return null;
    }

    try {
      const tokenData = JSON.parse(data) as RefreshToken;
      const expiresAt = new Date(tokenData.expires_at);
      
      if (expiresAt < new Date()) {
        this.logger.debug('Refresh token expired', { 
          expires_at: tokenData.expires_at 
        });
        await this.env.OAUTH_KV.delete(refreshToken);
        return null;
      }

      return tokenData;
    } catch (error) {
      this.logger.error('Failed to parse refresh token', { error: error.message });
      return null;
    }
  }

  async revokeToken(token: string, tokenTypeHint?: 'access_token' | 'refresh_token'): Promise<boolean> {
    let revoked = false;

    // Try to revoke as access token
    if (!tokenTypeHint || tokenTypeHint === 'access_token') {
      const accessData = await this.env.OAUTH_KV.get(token);
      if (accessData) {
        await this.env.OAUTH_KV.delete(token);
        revoked = true;
        this.logger.info('Access token revoked');
      }
    }

    // Try to revoke as refresh token
    if (!tokenTypeHint || tokenTypeHint === 'refresh_token') {
      const refreshData = await this.env.OAUTH_KV.get(token);
      if (refreshData) {
        // Also revoke associated access token if any
        try {
          const tokenData = JSON.parse(refreshData) as RefreshToken;
          if (tokenData.access_token) {
            await this.env.OAUTH_KV.delete(tokenData.access_token);
          }
        } catch (error) {
          this.logger.error('Failed to revoke associated access token', { 
            error: error.message 
          });
        }
        
        await this.env.OAUTH_KV.delete(token);
        revoked = true;
        this.logger.info('Refresh token revoked');
      }
    }

    return revoked;
  }

  async introspectToken(token: string): Promise<{
    active: boolean;
    scope?: string;
    client_id?: string;
    username?: string;
    token_type?: string;
    exp?: number;
    iat?: number;
    sub?: string;
    aud?: string;
  }> {
    // Check if it's an access token
    const accessData = await this.env.OAUTH_KV.get(token);
    if (accessData) {
      try {
        const tokenData = JSON.parse(accessData) as AccessToken;
        const expiresAt = new Date(tokenData.expires_at);
        const createdAt = new Date(tokenData.created_at);
        
        if (expiresAt > new Date()) {
          return {
            active: true,
            scope: tokenData.scope,
            client_id: tokenData.client_id,
            username: tokenData.user_login,
            token_type: 'Bearer',
            exp: Math.floor(expiresAt.getTime() / 1000),
            iat: Math.floor(createdAt.getTime() / 1000),
            sub: tokenData.user_id,
            aud: tokenData.client_id,
          };
        }
      } catch (error) {
        this.logger.error('Failed to parse access token for introspection', { 
          error: error.message 
        });
      }
    }

    // Check if it's a refresh token
    const refreshData = await this.env.OAUTH_KV.get(token);
    if (refreshData) {
      try {
        const tokenData = JSON.parse(refreshData) as RefreshToken;
        const expiresAt = new Date(tokenData.expires_at);
        const createdAt = new Date(tokenData.created_at);
        
        if (expiresAt > new Date()) {
          return {
            active: true,
            scope: tokenData.scope,
            client_id: tokenData.client_id,
            username: tokenData.user_login,
            token_type: 'refresh_token',
            exp: Math.floor(expiresAt.getTime() / 1000),
            iat: Math.floor(createdAt.getTime() / 1000),
            sub: tokenData.user_id,
            aud: tokenData.client_id,
          };
        }
      } catch (error) {
        this.logger.error('Failed to parse refresh token for introspection', { 
          error: error.message 
        });
      }
    }

    return { active: false };
  }

  async validateAccessToken(accessToken: string): Promise<AccessToken | null> {
    const data = await this.env.OAUTH_KV.get(accessToken);
    if (!data) {
      this.logger.debug('Access token not found', { token: accessToken });
      return null;
    }

    try {
      const tokenData = JSON.parse(data) as AccessToken;
      const expiresAt = new Date(tokenData.expires_at);
      
      if (expiresAt < new Date()) {
        this.logger.debug('Access token expired', { 
          expires_at: tokenData.expires_at 
        });
        await this.env.OAUTH_KV.delete(accessToken);
        return null;
      }

      return tokenData;
    } catch (error) {
      this.logger.error('Failed to parse access token', { error: error.message });
      return null;
    }
  }
}