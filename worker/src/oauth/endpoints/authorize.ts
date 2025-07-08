import { Hono } from 'hono';
import type { Env } from '../../types';
import { createLogger } from '../../logger';
import { AuthorizationCodeGrant } from '../grants/authorization-code';
import { GitHubProvider, GitHubProviderWithToken, createGitHubAccessConfig } from '../../identity/github';

/**
 * OAuth 2.1 Authorization Endpoint
 * Handles authorization requests and redirects to identity provider
 */

export const authorizeEndpoint = new Hono<{ Bindings: Env }>();

/**
 * GET /oauth/authorize
 * Initiates the authorization flow
 */
authorizeEndpoint.get('/', async (c) => {
  const logger = createLogger('AuthorizeEndpoint', c.env);
  const url = new URL(c.req.url);
  const params = url.searchParams;
  
  logger.info('Authorization request', {
    client_id: params.get('client_id'),
    redirect_uri: params.get('redirect_uri'),
    response_type: params.get('response_type'),
    has_pkce: !!params.get('code_challenge'),
  });

  // Initialize grant handler
  const authCodeGrant = new AuthorizationCodeGrant(c.env);

  // Validate authorization request
  const validation = authCodeGrant.validateAuthorizationRequest(params);
  
  if (!validation.valid) {
    // If redirect_uri is valid, redirect with error
    const redirectUri = params.get('redirect_uri');
    const state = params.get('state');
    
    if (redirectUri && isValidRedirectUri(redirectUri)) {
      const errorUrl = authCodeGrant.buildErrorRedirect({
        redirect_uri: redirectUri,
        error: validation.error!,
        error_description: validation.error_description,
        state,
      });
      
      return c.redirect(errorUrl);
    }
    
    // Otherwise return JSON error
    return c.json({
      error: validation.error,
      error_description: validation.error_description,
    }, 400);
  }

  // Extract parameters
  const clientId = params.get('client_id')!;
  const redirectUri = params.get('redirect_uri')!;
  const state = params.get('state');
  const scope = params.get('scope') || 'mcp';
  const codeChallenge = params.get('code_challenge')!;
  const codeChallengeMethod = params.get('code_challenge_method')!;

  // Validate client exists
  const clientData = await getClient(c.env, clientId);
  if (!clientData) {
    logger.warn('Unknown client', { client_id: clientId });
    
    return c.json({
      error: 'invalid_client',
      error_description: 'Client not found',
    }, 400);
  }

  // Validate redirect_uri against registered URIs
  if (!isRegisteredRedirectUri(redirectUri, clientData.redirect_uris)) {
    logger.warn('Unregistered redirect URI', {
      client_id: clientId,
      redirect_uri: redirectUri,
      registered: clientData.redirect_uris,
    });
    
    return c.json({
      error: 'invalid_request',
      error_description: 'Redirect URI not registered for this client',
    }, 400);
  }

  // Store authorization session in KV
  const sessionId = crypto.randomUUID();
  const sessionData = {
    client_id: clientId,
    redirect_uri: redirectUri,
    state,
    scope,
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod,
    created_at: Date.now(),
  };
  
  await c.env.KV.put(
    `auth_session:${sessionId}`,
    JSON.stringify(sessionData),
    { expirationTtl: 600 } // 10 minutes
  );

  // Redirect to GitHub OAuth
  const githubProvider = new GitHubProvider(
    c.env.GITHUB_CLIENT_ID,
    c.env.GITHUB_CLIENT_SECRET,
    c.env
  );
  const authUrl = githubProvider.getAuthorizationUrl({
    client_id: c.env.GITHUB_CLIENT_ID,
    redirect_uri: `${c.env.PUBLIC_URL || new URL(c.req.url).origin}/oauth/authorize/callback`,
    state: sessionId, // Use session ID as state
    scope: 'read:user user:email',
  });

  logger.info('Redirecting to identity provider', {
    client_id: clientId,
    session_id: sessionId,
  });

  return c.redirect(authUrl);
});

/**
 * GET /callback
 * Handles the OAuth callback from GitHub
 */
authorizeEndpoint.get('/callback', async (c) => {
  const logger = createLogger('AuthorizeCallback', c.env);
  const url = new URL(c.req.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state'); // This is our session ID
  const error = url.searchParams.get('error');
  const errorDescription = url.searchParams.get('error_description');

  logger.info('OAuth callback received', {
    has_code: !!code,
    has_error: !!error,
    state,
  });

  // Retrieve session data
  if (!state) {
    return c.json({
      error: 'invalid_request',
      error_description: 'Missing state parameter',
    }, 400);
  }

  const sessionData = await c.env.KV.get(`auth_session:${state}`);
  if (!sessionData) {
    logger.warn('Session not found', { session_id: state });
    return c.json({
      error: 'invalid_request',
      error_description: 'Invalid or expired session',
    }, 400);
  }

  const session = JSON.parse(sessionData);
  
  // Handle provider errors
  if (error) {
    const authCodeGrant = new AuthorizationCodeGrant(c.env);
    const errorUrl = authCodeGrant.buildErrorRedirect({
      redirect_uri: session.redirect_uri,
      error: error,
      error_description: errorDescription,
      state: session.state,
    });
    
    return c.redirect(errorUrl);
  }

  if (!code) {
    const authCodeGrant = new AuthorizationCodeGrant(c.env);
    const errorUrl = authCodeGrant.buildErrorRedirect({
      redirect_uri: session.redirect_uri,
      error: 'server_error',
      error_description: 'No authorization code received',
      state: session.state,
    });
    
    return c.redirect(errorUrl);
  }

  // Exchange code with GitHub
  const githubProvider = new GitHubProvider(
    c.env.GITHUB_CLIENT_ID,
    c.env.GITHUB_CLIENT_SECRET,
    c.env
  );
  
  const redirectUri = `${c.env.PUBLIC_URL || new URL(c.req.url).origin}/oauth/authorize/callback`;
  
  let tokenResult;
  try {
    tokenResult = await githubProvider.exchangeCode(code, redirectUri);
  } catch (error) {
    logger.error('Failed to exchange code with GitHub', error);
    
    const authCodeGrant = new AuthorizationCodeGrant(c.env);
    const errorUrl = authCodeGrant.buildErrorRedirect({
      redirect_uri: session.redirect_uri,
      error: 'server_error',
      error_description: 'Failed to authenticate with identity provider',
      state: session.state,
    });
    
    return c.redirect(errorUrl);
  }

  // Get user info from GitHub
  let userInfo;
  try {
    userInfo = await githubProvider.getUserInfo(tokenResult.access_token);
  } catch (error) {
    logger.error('Failed to get user info', error);
    
    const authCodeGrant = new AuthorizationCodeGrant(c.env);
    const errorUrl = authCodeGrant.buildErrorRedirect({
      redirect_uri: session.redirect_uri,
      error: 'server_error',
      error_description: 'Failed to retrieve user information',
      state: session.state,
    });
    
    return c.redirect(errorUrl);
  }

  // Validate access rules with user's access token
  const githubProviderWithToken = new GitHubProviderWithToken(
    c.env.GITHUB_CLIENT_ID,
    c.env.GITHUB_CLIENT_SECRET,
    c.env,
    tokenResult.access_token
  );
  
  const accessConfig = createGitHubAccessConfig(c.env);
  const accessValid = await githubProviderWithToken.validateAccess(userInfo, accessConfig);
  
  if (!accessValid) {
    logger.warn('Access denied for user', {
      user_id: userInfo.id,
      login: userInfo.login,
      email: userInfo.email,
    });
    
    const authCodeGrant = new AuthorizationCodeGrant(c.env);
    const errorUrl = authCodeGrant.buildErrorRedirect({
      redirect_uri: session.redirect_uri,
      error: 'access_denied',
      error_description: 'User is not authorized to access this application',
      state: session.state,
    });
    
    return c.redirect(errorUrl);
  }

  // Generate authorization code
  const authCodeGrant = new AuthorizationCodeGrant(c.env);
  const authCode = await authCodeGrant.generateAuthorizationCode();
  
  // Store authorization code with user info
  await authCodeGrant.storeAuthorizationCode({
    code: authCode,
    client_id: session.client_id,
    redirect_uri: session.redirect_uri,
    code_challenge: session.code_challenge,
    code_challenge_method: session.code_challenge_method,
    user_id: userInfo.id.toString(),
    user_email: userInfo.email,
    user_login: userInfo.login,
    scope: session.scope,
  });

  // Clean up session
  await c.env.KV.delete(`auth_session:${state}`);

  // Redirect back to client with authorization code
  const successUrl = authCodeGrant.buildAuthorizationRedirect({
    redirect_uri: session.redirect_uri,
    code: authCode,
    state: session.state,
  });

  logger.info('Authorization successful', {
    client_id: session.client_id,
    user_id: userInfo.id,
    user_login: userInfo.login,
  });

  return c.redirect(successUrl);
});

/**
 * Helper: Get client data from KV
 */
async function getClient(env: Env, clientId: string): Promise<any | null> {
  const clientData = await env.KV.get(`client:${clientId}`);
  return clientData ? JSON.parse(clientData) : null;
}

/**
 * Helper: Validate redirect URI format
 */
function isValidRedirectUri(uri: string): boolean {
  try {
    const url = new URL(uri);
    
    // Must be HTTPS except for localhost
    if (url.protocol !== 'https:' && 
        url.hostname !== 'localhost' && 
        url.hostname !== '127.0.0.1' &&
        url.hostname !== '[::1]') {
      return false;
    }
    
    // No fragments allowed
    if (url.hash) {
      return false;
    }
    
    return true;
  } catch {
    return false;
  }
}

/**
 * Helper: Check if redirect URI is registered
 */
function isRegisteredRedirectUri(uri: string, registeredUris: string[]): boolean {
  // Exact match required
  return registeredUris.includes(uri);
}