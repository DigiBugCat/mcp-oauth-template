import type { Env } from "./types";
import { TokenManager } from "./token-utils";
import { createLogger } from "./logger";
import { AuditLogger } from "./audit";

/**
 * Handle refresh token grant type
 * This extends the OAuth provider's token endpoint to support refresh tokens
 */
export async function handleRefreshTokenGrant(
  request: Request,
  env: Env,
  formData: FormData
): Promise<Response | null> {
  const logger = createLogger('RefreshTokenGrant', env);
  const audit = new AuditLogger(env);
  const tokenManager = new TokenManager(env);

  const grantType = formData.get('grant_type');
  if (grantType !== 'refresh_token') {
    return null; // Let the OAuth provider handle other grant types
  }

  const refreshToken = formData.get('refresh_token')?.toString();
  const clientId = formData.get('client_id')?.toString();
  const scope = formData.get('scope')?.toString();

  if (!refreshToken) {
    logger.error('Missing refresh token');
    return new Response(JSON.stringify({
      error: 'invalid_request',
      error_description: 'Missing refresh_token parameter',
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    // Validate refresh token
    const refreshTokenData = await tokenManager.validateRefreshToken(refreshToken);
    
    if (!refreshTokenData) {
      logger.warn('Invalid refresh token', { client_id: clientId });
      await audit.log(request, 'token_refreshed', {
        client_id: clientId || 'unknown',
        success: false,
        error_code: 'invalid_grant',
      });
      
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: 'The refresh token is invalid or expired',
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Verify client_id matches
    if (clientId && refreshTokenData.client_id !== clientId) {
      logger.warn('Client ID mismatch', { 
        provided: clientId,
        expected: refreshTokenData.client_id,
      });
      
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: 'The refresh token was issued to another client',
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Use requested scope or fall back to original scope
    const finalScope = scope || refreshTokenData.scope;

    // Create new access token
    const { access_token, expires_in } = await tokenManager.createAccessToken({
      client_id: refreshTokenData.client_id,
      user_id: refreshTokenData.user_id,
      user_email: refreshTokenData.user_email,
      user_login: refreshTokenData.user_login,
      scope: finalScope,
      includeRefreshToken: false, // Don't issue a new refresh token
    });

    logger.info('Token refreshed successfully', {
      client_id: refreshTokenData.client_id,
      user_id: refreshTokenData.user_id,
    });

    await audit.log(request, 'token_refreshed', {
      client_id: refreshTokenData.client_id,
      user_id: refreshTokenData.user_id,
      user_email: refreshTokenData.user_email,
      success: true,
    });

    return new Response(JSON.stringify({
      access_token,
      token_type: 'Bearer',
      expires_in,
      scope: finalScope,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });

  } catch (error) {
    logger.error('Error handling refresh token grant', { error: error.message });
    return new Response(JSON.stringify({
      error: 'server_error',
      error_description: 'An error occurred while processing the refresh token',
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

/**
 * Extend token response to include refresh tokens
 * This should be called after the OAuth provider issues an access token
 */
export async function extendTokenResponse(
  response: Response,
  env: Env,
  clientId: string,
  userData: {
    user_id: string;
    user_email: string;
    user_login: string;
  }
): Promise<Response> {
  const logger = createLogger('TokenExtension', env);
  
  // Only extend successful token responses
  if (response.status !== 200) {
    return response;
  }

  try {
    const responseData = await response.json();
    
    // If it already has a refresh token, don't modify
    if (responseData.refresh_token) {
      return new Response(JSON.stringify(responseData), {
        status: 200,
        headers: response.headers,
      });
    }

    // Check if this client should receive refresh tokens
    // You can implement logic here to only give refresh tokens to certain clients
    const shouldIssueRefreshToken = true; // For now, always issue refresh tokens

    if (shouldIssueRefreshToken && responseData.access_token) {
      const tokenManager = new TokenManager(env);
      
      // Generate refresh token
      const refreshToken = crypto.randomUUID();
      const now = new Date();
      const refreshExpiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 days

      // Store refresh token
      await env.OAUTH_KV.put(
        `refresh:${refreshToken}`,
        JSON.stringify({
          token: refreshToken,
          client_id: clientId,
          user_id: userData.user_id,
          user_email: userData.user_email,
          user_login: userData.user_login,
          scope: responseData.scope || 'mcp',
          created_at: now.toISOString(),
          expires_at: refreshExpiresAt.toISOString(),
          access_token: responseData.access_token,
        }),
        { expirationTtl: 30 * 24 * 60 * 60 } // 30 days
      );

      logger.info('Refresh token added to response', { client_id: clientId });

      // Add refresh token to response
      responseData.refresh_token = refreshToken;
    }

    return new Response(JSON.stringify(responseData), {
      status: 200,
      headers: response.headers,
    });

  } catch (error) {
    logger.error('Failed to extend token response', { error: error.message });
    // Return original response if extension fails
    return response;
  }
}