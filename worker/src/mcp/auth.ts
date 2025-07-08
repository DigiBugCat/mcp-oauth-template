import type { Env } from '../types';
import { TokenManager } from '../oauth/tokens';
import { createLogger } from '../logger';
import { mcpProxyHandler } from './proxy';

/**
 * MCP Authentication Handler
 * Validates Bearer tokens and forwards authenticated requests to the MCP server
 * Fully compliant with MCP specification - NO query parameter tokens allowed
 */

export interface MCPAuthContext {
  props: {
    user_id?: string;
    email?: string;
    login?: string;
    name?: string;
    client_id: string;
    scope: string;
  };
}

/**
 * Validate Origin header to prevent DNS rebinding attacks
 */
function validateOrigin(request: Request, env: Env): boolean {
  const origin = request.headers.get('Origin');
  
  // No origin header is okay for non-browser clients
  if (!origin) {
    return true;
  }
  
  try {
    const originUrl = new URL(origin);
    
    // Allow localhost origins
    if (originUrl.hostname === 'localhost' || 
        originUrl.hostname === '127.0.0.1' ||
        originUrl.hostname === '[::1]') {
      return true;
    }
    
    // Check against allowed origins in environment
    if (env.ALLOWED_ORIGINS) {
      const allowedOrigins = env.ALLOWED_ORIGINS.split(',').map(o => o.trim());
      if (allowedOrigins.includes(origin)) {
        return true;
      }
    }
    
    // Check if origin matches our public URL
    if (env.PUBLIC_URL) {
      const publicUrl = new URL(env.PUBLIC_URL);
      if (originUrl.origin === publicUrl.origin) {
        return true;
      }
    }
    
    return false;
  } catch {
    return false;
  }
}

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
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, Accept, MCP-Protocol-Version',
        'Access-Control-Max-Age': '86400',
      },
    });
  }
  
  // Validate Origin header for security
  if (!validateOrigin(request, env)) {
    logger.warn('Invalid origin', { origin: request.headers.get('Origin') });
    return new Response(JSON.stringify({ 
      error: 'invalid_origin', 
      error_description: 'Origin not allowed' 
    }), {
      status: 403,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }
  
  // Extract Bearer token from Authorization header ONLY
  const authHeader = request.headers.get('Authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    logger.debug('Missing or invalid Authorization header');
    return new Response(JSON.stringify({ 
      error: 'invalid_token', 
      error_description: 'Bearer token required in Authorization header' 
    }), {
      status: 401,
      headers: {
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer realm="MCP"',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, Accept, MCP-Protocol-Version',
      },
    });
  }
  
  const token = authHeader.substring(7);
  
  // Log but explicitly reject any query parameter tokens
  const url = new URL(request.url);
  if (url.searchParams.has('token')) {
    logger.warn('Query parameter token rejected per MCP spec');
    return new Response(JSON.stringify({ 
      error: 'invalid_request', 
      error_description: 'Tokens must not be sent in query parameters' 
    }), {
      status: 400,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
    });
  }
  
  logger.debug('Validating token', { token_prefix: token.substring(0, 10) });
  
  // Validate token using new token manager
  const tokenManager = new TokenManager(env);
  const tokenData = await tokenManager.validateToken(token);
  
  if (!tokenData) {
    logger.warn('Invalid or expired token');
    return new Response(JSON.stringify({ 
      error: 'invalid_token', 
      error_description: 'Invalid or expired access token' 
    }), {
      status: 401,
      headers: {
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer realm="MCP", error="invalid_token"',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, Accept, MCP-Protocol-Version',
      },
    });
  }
  
  // Check token scope includes 'mcp'
  const scopes = tokenData.scope.split(' ');
  if (!scopes.includes('mcp')) {
    logger.warn('Token missing required mcp scope', { scope: tokenData.scope });
    return new Response(JSON.stringify({ 
      error: 'insufficient_scope', 
      error_description: 'Token does not have required mcp scope' 
    }), {
      status: 403,
      headers: {
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer realm="MCP", error="insufficient_scope", scope="mcp"',
        'Access-Control-Allow-Origin': '*',
      },
    });
  }
  
  logger.info('Token validated successfully', {
    client_id: tokenData.client_id,
    user_id: tokenData.user_id,
    scope: tokenData.scope,
  });
  
  // Create context for the proxy handler
  const authContext: MCPAuthContext = {
    props: {
      user_id: tokenData.user_id,
      email: tokenData.user_email,
      login: tokenData.user_login,
      name: tokenData.user_login, // Use login as name if not available
      client_id: tokenData.client_id,
      scope: tokenData.scope,
    },
  };
  
  // Forward to MCP proxy handler
  return mcpProxyHandler(request, env, authContext);
}

/**
 * Create an MCP-compliant error response
 */
export function mcpErrorResponse(
  error: string,
  description: string,
  status: number,
  additionalHeaders?: Record<string, string>
): Response {
  return new Response(JSON.stringify({
    error,
    error_description: description,
  }), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, Accept, MCP-Protocol-Version',
      ...additionalHeaders,
    },
  });
}