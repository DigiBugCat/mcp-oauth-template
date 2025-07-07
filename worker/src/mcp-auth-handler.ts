import type { Env } from "./types";
import { TokenManager } from "./token-utils";
import { createLogger } from "./logger";
import { mcpProxyHandler } from "./mcp-proxy";

/**
 * Manual authentication handler for MCP routes
 * Validates Bearer tokens and forwards authenticated requests
 */
export async function mcpAuthHandler(
  request: Request,
  env: Env,
  ctx: ExecutionContext
): Promise<Response> {
  const logger = createLogger('MCPAuth', env);
  
  // Handle CORS preflight requests
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400',
      },
    });
  }
  
  // Extract Bearer token from Authorization header OR query parameter
  const authHeader = request.headers.get('Authorization');
  const url = new URL(request.url);
  const queryToken = url.searchParams.get('token');
  
  let token: string | null = null;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  } else if (queryToken) {
    token = queryToken;
    logger.debug('Using token from query parameter');
  }
  
  if (!token) {
    logger.debug('Missing authentication token');
    return new Response(JSON.stringify({ error: 'invalid_token', error_description: 'Missing authentication token' }), {
      status: 401,
      headers: {
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    });
  }
  
  logger.debug('Validating token', { token_prefix: token.substring(0, 10) });
  
  // Validate token
  const tokenManager = new TokenManager(env);
  const tokenData = await tokenManager.validateAccessToken(token);
  
  if (!tokenData) {
    logger.warn('Invalid or expired token');
    return new Response(JSON.stringify({ error: 'invalid_token', error_description: 'Invalid or expired access token' }), {
      status: 401,
      headers: {
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    });
  }
  
  logger.info('Token validated successfully', {
    client_id: tokenData.client_id,
    user_id: tokenData.user_id,
  });
  
  // Create props object for the proxy handler
  const props = {
    user_id: tokenData.user_id,
    email: tokenData.user_email,
    login: tokenData.user_login,
    name: tokenData.user_login, // Use login as name if not available
  };
  
  // Forward to MCP proxy handler
  return mcpProxyHandler(request, env, { props });
}