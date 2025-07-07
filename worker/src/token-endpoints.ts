import { Hono } from "hono";
import type { Env } from "./types";
import { createLogger } from "./logger";
import { AuditLogger } from "./audit";
import { TokenManager } from "./token-utils";
import { createHash } from "crypto";

const app = new Hono<{ Bindings: Env }>();

// Handle authorization code exchange for PKCE clients
app.post("/oauth/token/pkce", async (c) => {
  const logger = createLogger('PKCETokenExchange', c.env);
  const audit = new AuditLogger(c.env);
  const tokenManager = new TokenManager(c.env);

  try {
    const body = await c.req.parseBody();
    const grantType = body.grant_type as string;
    const code = body.code as string;
    const clientId = body.client_id as string;
    const codeVerifier = body.code_verifier as string;
    const redirectUri = body.redirect_uri as string;

    // Validate grant type
    if (grantType !== 'authorization_code') {
      return c.json({
        error: 'unsupported_grant_type',
        error_description: 'Only authorization_code grant type is supported',
      }, 400);
    }

    // Validate required parameters
    if (!code || !clientId || !codeVerifier || !redirectUri) {
      return c.json({
        error: 'invalid_request',
        error_description: 'Missing required parameters',
      }, 400);
    }

    // Get authorization code data
    const codeData = await c.env.OAUTH_KV.get(`code:${code}`);
    if (!codeData) {
      logger.warn('Invalid authorization code', { client_id: clientId });
      return c.json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code',
      }, 400);
    }

    const authCode = JSON.parse(codeData);

    // Validate client_id matches
    if (authCode.client_id !== clientId) {
      logger.warn('Client ID mismatch', { 
        provided: clientId,
        expected: authCode.client_id,
      });
      return c.json({
        error: 'invalid_grant',
        error_description: 'Authorization code was issued to another client',
      }, 400);
    }

    // Validate redirect_uri matches
    if (authCode.redirect_uri !== redirectUri) {
      logger.warn('Redirect URI mismatch', {
        provided: redirectUri,
        expected: authCode.redirect_uri,
      });
      return c.json({
        error: 'invalid_grant',
        error_description: 'Redirect URI mismatch',
      }, 400);
    }

    // Validate PKCE code_verifier
    if (authCode.code_challenge) {
      const encoder = new TextEncoder();
      const data = encoder.encode(codeVerifier);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const computedChallenge = btoa(String.fromCharCode(...hashArray))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      if (computedChallenge !== authCode.code_challenge) {
        logger.warn('PKCE verification failed', { client_id: clientId });
        return c.json({
          error: 'invalid_grant',
          error_description: 'PKCE verification failed',
        }, 400);
      }
    }

    // Delete the authorization code (one-time use)
    await c.env.OAUTH_KV.delete(`code:${code}`);

    // Create access token
    const { access_token, expires_in, refresh_token } = await tokenManager.createAccessToken({
      client_id: clientId,
      user_id: authCode.user_id,
      user_email: authCode.user_email,
      user_login: authCode.user_login,
      scope: authCode.scope || 'mcp',
      includeRefreshToken: true,
    });

    logger.info('Token issued successfully via PKCE', {
      client_id: clientId,
      user_id: authCode.user_id,
    });

    await audit.log(c.req.raw, 'token_issued', {
      client_id: clientId,
      user_id: authCode.user_id,
      user_email: authCode.user_email,
      success: true,
      details: {
        grant_type: 'authorization_code',
        pkce: true,
      },
    });

    return c.json({
      access_token,
      token_type: 'Bearer',
      expires_in,
      refresh_token,
      scope: authCode.scope || 'mcp',
    }, 200);

  } catch (error) {
    logger.error('PKCE token exchange failed', { error: error.message });
    return c.json({
      error: 'server_error',
      error_description: 'An error occurred processing the request',
    }, 500);
  }
});

// Token introspection endpoint (RFC 7662)
app.post("/oauth/introspect", async (c) => {
  const logger = createLogger('TokenIntrospection', c.env);
  const audit = new AuditLogger(c.env);
  const tokenManager = new TokenManager(c.env);

  try {
    const body = await c.req.parseBody();
    const token = body.token as string;
    const tokenTypeHint = body.token_type_hint as string;

    if (!token) {
      return c.json({ active: false }, 200);
    }

    // Get client credentials from Authorization header or body
    let clientId: string | undefined;
    const authHeader = c.req.header('Authorization');
    
    if (authHeader?.startsWith('Basic ')) {
      const credentials = atob(authHeader.substring(6));
      const [id] = credentials.split(':');
      clientId = id;
    } else {
      clientId = body.client_id as string;
    }

    logger.debug('Token introspection request', { 
      client_id: clientId,
      has_token: !!token,
      token_type_hint: tokenTypeHint,
    });

    const introspectionResult = await tokenManager.introspectToken(token);

    await audit.log(c.req.raw, 'token_introspected', {
      client_id: clientId || 'unknown',
      success: true,
      details: {
        active: introspectionResult.active,
        token_type: introspectionResult.token_type,
      },
    });

    return c.json(introspectionResult, 200);
  } catch (error) {
    logger.error('Token introspection failed', { error: error.message });
    return c.json({ active: false }, 200);
  }
});

// Token revocation endpoint (RFC 7009)
app.post("/oauth/revoke", async (c) => {
  const logger = createLogger('TokenRevocation', c.env);
  const audit = new AuditLogger(c.env);
  const tokenManager = new TokenManager(c.env);

  try {
    const body = await c.req.parseBody();
    const token = body.token as string;
    const tokenTypeHint = body.token_type_hint as 'access_token' | 'refresh_token' | undefined;

    if (!token) {
      return c.json({ error: 'invalid_request', error_description: 'Missing token parameter' }, 400);
    }

    // Get client credentials from Authorization header or body
    let clientId: string | undefined;
    const authHeader = c.req.header('Authorization');
    
    if (authHeader?.startsWith('Basic ')) {
      const credentials = atob(authHeader.substring(6));
      const [id] = credentials.split(':');
      clientId = id;
    } else {
      clientId = body.client_id as string;
    }

    logger.debug('Token revocation request', { 
      client_id: clientId,
      token_type_hint: tokenTypeHint,
    });

    const revoked = await tokenManager.revokeToken(token, tokenTypeHint);

    await audit.log(c.req.raw, 'token_revoked', {
      client_id: clientId || 'unknown',
      success: true,
      details: {
        revoked,
        token_type_hint: tokenTypeHint,
      },
    });

    // Always return 200 OK per RFC 7009
    return c.body(null, 200);
  } catch (error) {
    logger.error('Token revocation failed', { error: error.message });
    // Still return 200 OK even on error per RFC 7009
    return c.body(null, 200);
  }
});

export const TokenEndpointsHandler = app;