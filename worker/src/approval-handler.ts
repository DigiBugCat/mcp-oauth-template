import { Hono } from "hono";
import type { Env } from "./types";
import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import type { Props } from "./oauth-utils";
import { createLogger } from "./logger";

const app = new Hono<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>();

// GET /approve - Show approval page after GitHub authentication
app.get("/approve", async (c) => {
  const logger = createLogger('Approval', c.env);
  const sessionId = c.req.query("session");
  
  // Log all details about the request
  const headers: Record<string, string> = {};
  c.req.raw.headers.forEach((value, key) => {
    headers[key] = value;
  });
  
  logger.debug('Approve endpoint called', {
    sessionId,
    url: c.req.url,
    headers,
    userAgent: c.req.header('user-agent'),
  });
  
  if (!sessionId) {
    logger.error('Missing session ID');
    return c.text("Missing session ID", 400);
  }
  
  // Get session data from KV
  const sessionData = await c.env.SESSION_KV.get(`approval:${sessionId}`);
  
  // Also check if there's any data at all in SESSION_KV for debugging
  const allKeys = await c.env.SESSION_KV.list();
  logger.debug('All session keys', { 
    keys: allKeys.keys.map(k => k.name),
    sessionId,
    lookingFor: `approval:${sessionId}`,
  });
  
  if (!sessionData) {
    logger.error('Session expired or invalid', { sessionId });
    
    // Check if this might be Claude Desktop trying to initiate auth
    const userAgent = c.req.header('user-agent') || '';
    if (userAgent.includes('Claude') || c.req.header('x-claude-desktop')) {
      logger.info('Detected Claude Desktop, creating pending session', { sessionId });
      
      // Create a pending session for Claude Desktop
      const sessionData = {
        oauthRequest: {
          clientId: 'claude-desktop',
          redirectUri: 'https://claude.ai/api/mcp/auth_callback',
          scope: ['mcp'],
          state: sessionId, // Use session ID as state
        },
        user: null,
        createdAt: Date.now(),
        pending: true,
      };
      
      await c.env.SESSION_KV.put(
        `approval:${sessionId}`,
        JSON.stringify(sessionData),
        { expirationTtl: 300 }
      );
      
      // Redirect to GitHub OAuth
      const baseUrl = c.env.PUBLIC_URL || c.req.url;
      const githubUrl = new URL('/oauth/authorize', baseUrl);
      githubUrl.searchParams.set('session', sessionId);
      githubUrl.searchParams.set('client_id', 'claude-desktop');
      githubUrl.searchParams.set('redirect_uri', 'https://claude.ai/api/mcp/auth_callback');
      githubUrl.searchParams.set('scope', 'mcp');
      
      return c.redirect(githubUrl.toString());
    }
    
    return c.text("Session expired or invalid", 400);
  }
  
  const session = JSON.parse(sessionData);
  
  // If session is pending, redirect to GitHub auth
  if (session.pending) {
    logger.info('Session pending GitHub auth, redirecting', { sessionId });
    const baseUrl = c.env.PUBLIC_URL || c.req.url;
    const githubUrl = new URL('/oauth/authorize', baseUrl);
    githubUrl.searchParams.set('session', sessionId);
    githubUrl.searchParams.set('client_id', session.oauthRequest.clientId);
    githubUrl.searchParams.set('redirect_uri', session.oauthRequest.redirectUri);
    githubUrl.searchParams.set('scope', 'mcp');
    
    return c.redirect(githubUrl.toString());
  }
  
  // Auto-approve for personal OAuth server
  logger.info('Auto-approving user', { 
    user: session.user.login,
    client_id: session.oauthRequest.clientId,
  });
  
  // Generate authorization code
  const code = crypto.randomUUID();
  
  // Store authorization code with all necessary data
  const authCodeData = {
    client_id: session.oauthRequest.clientId,
    user_id: session.user.id.toString(),
    user_email: session.user.email || "unknown",
    user_login: session.user.login,
    redirect_uri: session.oauthRequest.redirectUri,
    scope: Array.isArray(session.oauthRequest.scope) 
      ? session.oauthRequest.scope.join(' ') 
      : session.oauthRequest.scope || 'mcp',
    code_challenge: session.oauthRequest.codeChallenge,
    code_challenge_method: session.oauthRequest.codeChallengeMethod,
    expires_at: new Date(Date.now() + 600000).toISOString(), // 10 minutes
  };
  
  await c.env.OAUTH_KV.put(
    `code:${code}`,
    JSON.stringify(authCodeData),
    { expirationTtl: 600 } // 10 minutes
  );
  
  // Clean up session
  await c.env.SESSION_KV.delete(`approval:${sessionId}`);
  
  logger.info('Authorization code created', { 
    user: session.user.login,
    client_id: session.oauthRequest.clientId,
    code_prefix: code.substring(0, 8),
    full_code: code,
    stored_key: `code:${code}`,
    redirect_uri: session.oauthRequest.redirectUri,
    code_challenge: session.oauthRequest.codeChallenge ? 'present' : 'missing',
  });
  
  // Build redirect URL with authorization code
  const redirectUrl = new URL(session.oauthRequest.redirectUri);
  redirectUrl.searchParams.set('code', code);
  if (session.oauthRequest.state) {
    redirectUrl.searchParams.set('state', session.oauthRequest.state);
  }
  
  logger.info('Redirecting with authorization code', {
    redirect_url: redirectUrl.toString(),
    code,
    state: session.oauthRequest.state,
  });
  
  return c.redirect(redirectUrl.toString());
});

export { app as ApprovalHandler };