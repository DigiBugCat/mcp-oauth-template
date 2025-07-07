import { Hono } from "hono";
import type { Env } from "./types";
import { createLogger } from "./logger";

const app = new Hono<{ Bindings: Env }>();

// POST /oauth/initiate - Claude Desktop might use this to start auth flow
app.post("/oauth/initiate", async (c) => {
  const logger = createLogger('ClaudeIntegration', c.env);
  
  try {
    const body = await c.req.json();
    logger.debug('OAuth initiation request', { body });
    
    // Generate a session ID that Claude expects
    const sessionId = crypto.randomUUID();
    
    // Create a minimal session that can be used for approval
    const sessionData = {
      oauthRequest: {
        clientId: body.client_id || 'claude-desktop',
        redirectUri: body.redirect_uri || 'https://claude.ai/api/mcp/auth_callback',
        scope: ['mcp'],
        state: body.state,
      },
      // Placeholder user data - will be filled after GitHub auth
      user: null,
      createdAt: Date.now(),
      pending: true, // Mark as pending GitHub auth
    };
    
    // Store session
    await c.env.SESSION_KV.put(
      `approval:${sessionId}`,
      JSON.stringify(sessionData),
      { expirationTtl: 300 }
    );
    
    logger.info('Session initiated for Claude Desktop', { sessionId });
    
    const baseUrl = c.env.PUBLIC_URL || new URL(c.req.url).origin;
    
    // Return URLs for Claude to use
    return c.json({
      session_id: sessionId,
      approval_url: `${baseUrl}/approve?session=${sessionId}`,
      auth_url: `${baseUrl}/oauth/authorize?session=${sessionId}`,
      expires_in: 300,
    });
  } catch (error) {
    logger.error('Failed to initiate OAuth', { error: error.message });
    return c.json({ error: 'server_error' }, 500);
  }
});

// GET /oauth/status/:sessionId - Check session status
app.get("/oauth/status/:sessionId", async (c) => {
  const logger = createLogger('ClaudeIntegration', c.env);
  const sessionId = c.req.param('sessionId');
  
  const sessionData = await c.env.SESSION_KV.get(`approval:${sessionId}`);
  
  if (!sessionData) {
    return c.json({ status: 'expired' }, 404);
  }
  
  const session = JSON.parse(sessionData);
  
  if (session.pending) {
    return c.json({ status: 'pending' });
  }
  
  return c.json({ status: 'authorized' });
});

// PUT /approve - Create a session directly (Claude Desktop might use this)
app.put("/approve", async (c) => {
  const logger = createLogger('ClaudeIntegration', c.env);
  
  try {
    const sessionId = c.req.query('session');
    
    if (!sessionId) {
      logger.error('Missing session ID in PUT /approve');
      return c.json({ error: 'missing_session_id' }, 400);
    }
    
    logger.info('Creating session via PUT /approve', { sessionId });
    
    // Create a pending session
    const sessionData = {
      oauthRequest: {
        clientId: 'claude-desktop',
        redirectUri: 'https://claude.ai/api/mcp/auth_callback',
        scope: ['mcp'],
        state: sessionId,
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
    
    return c.json({ success: true });
  } catch (error) {
    logger.error('Failed to create session', { error: error.message });
    return c.json({ error: 'server_error' }, 500);
  }
});

export { app as ClaudeIntegrationHandler };