import type { Env } from '../types';
import type { MCPAuthContext } from './auth';
import { createLogger } from '../logger';

/**
 * MCP Proxy Handler
 * Forwards authenticated requests to the Docker MCP server
 * Supports SSE streaming and MCP-specific headers
 */

/**
 * Generate or validate session ID
 */
function getOrCreateSessionId(request: Request): string {
  const sessionId = request.headers.get('Mcp-Session-Id');
  
  if (sessionId && /^[a-zA-Z0-9_-]{1,128}$/.test(sessionId)) {
    return sessionId;
  }
  
  // Generate new session ID
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function mcpProxyHandler(
  request: Request,
  env: Env,
  ctx: MCPAuthContext
): Promise<Response> {
  const logger = createLogger('MCPProxy', env);
  
  // Check Accept header for SSE support
  const acceptHeader = request.headers.get('Accept') || '';
  const supportsSse = acceptHeader.includes('text/event-stream');
  const supportsJson = acceptHeader.includes('application/json');
  
  logger.debug('Proxying authenticated request', {
    method: request.method,
    path: new URL(request.url).pathname,
    user_id: ctx.props.user_id,
    client_id: ctx.props.client_id,
    accept: acceptHeader,
    supports_sse: supportsSse,
  });
  
  // Validate MCP server URL
  if (!env.MCP_SERVER_URL) {
    logger.error('MCP_SERVER_URL not configured');
    return new Response(JSON.stringify({
      error: 'server_error',
      error_description: 'MCP server not configured',
    }), { 
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
    });
  }

  // Parse request URL
  const url = new URL(request.url);
  const mcpPath = url.pathname;
  
  // Build target URL
  const targetUrl = new URL(mcpPath, env.MCP_SERVER_URL);
  targetUrl.search = url.search;
  
  logger.debug('Target URL', { target: targetUrl.toString() });

  // Prepare headers for proxied request
  const headers = new Headers(request.headers);
  
  // Remove headers that shouldn't be forwarded
  headers.delete('host');
  headers.delete('authorization'); // MCP server doesn't need OAuth token
  headers.delete('cf-connecting-ip');
  headers.delete('cf-ipcountry');
  headers.delete('cf-ray');
  headers.delete('cf-visitor');
  
  // Add user context headers
  headers.set('X-User-ID', ctx.props.user_id || 'anonymous');
  headers.set('X-User-Email', ctx.props.email || '');
  headers.set('X-User-Login', ctx.props.login || '');
  headers.set('X-User-Name', ctx.props.name || '');
  headers.set('X-Client-ID', ctx.props.client_id);
  headers.set('X-OAuth-Scope', ctx.props.scope);
  
  // Handle MCP-Protocol-Version
  const mcpVersion = request.headers.get('MCP-Protocol-Version');
  if (mcpVersion) {
    headers.set('MCP-Protocol-Version', mcpVersion);
  }
  
  // Handle session ID
  const sessionId = getOrCreateSessionId(request);
  headers.set('Mcp-Session-Id', sessionId);
  
  // Add origin if missing
  if (!headers.has('origin')) {
    headers.set('origin', new URL(request.url).origin);
  }

  try {
    // Forward request to MCP server
    const response = await fetch(targetUrl.toString(), {
      method: request.method,
      headers: headers,
      body: request.body,
      redirect: 'manual',
      // @ts-ignore - duplex is needed for streaming but not in TS types
      duplex: 'half',
    });

    logger.debug('MCP server response', {
      status: response.status,
      content_type: response.headers.get('content-type'),
      mcp_version: response.headers.get('MCP-Protocol-Version'),
    });

    // Handle version negotiation
    const responseMcpVersion = response.headers.get('MCP-Protocol-Version');
    if (mcpVersion && responseMcpVersion && mcpVersion !== responseMcpVersion) {
      logger.info('MCP version negotiation', {
        requested: mcpVersion,
        server_version: responseMcpVersion,
      });
    }

    // Handle SSE responses
    if (response.headers.get('content-type')?.includes('text/event-stream')) {
      logger.info('Handling SSE response', { 
        user_id: ctx.props.user_id,
        session_id: sessionId,
        status: response.status,
      });
      
      const sseHeaders = new Headers({
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no', // Disable nginx buffering
        'X-Content-Type-Options': 'nosniff',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, Accept, MCP-Protocol-Version, Mcp-Session-Id',
        'Access-Control-Expose-Headers': 'MCP-Protocol-Version, Mcp-Session-Id',
      });
      
      // Preserve important headers
      if (responseMcpVersion) {
        sseHeaders.set('MCP-Protocol-Version', responseMcpVersion);
      }
      sseHeaders.set('Mcp-Session-Id', sessionId);
      
      // Stream the response
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: sseHeaders,
      });
    }

    // Handle regular JSON responses
    const responseHeaders = new Headers(response.headers);
    
    // Add CORS headers
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept, MCP-Protocol-Version, Mcp-Session-Id');
    responseHeaders.set('Access-Control-Expose-Headers', 'MCP-Protocol-Version, Mcp-Session-Id');
    
    // Ensure session ID is in response
    responseHeaders.set('Mcp-Session-Id', sessionId);
    
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
    });
    
  } catch (error) {
    logger.error('Failed to connect to MCP server', {
      error: error instanceof Error ? error.message : String(error),
      target: targetUrl.toString(),
    });
    
    return new Response(JSON.stringify({
      error: 'bad_gateway',
      error_description: 'Failed to connect to MCP server',
    }), { 
      status: 502,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, Accept, MCP-Protocol-Version, Mcp-Session-Id',
      },
    });
  }
}

/**
 * Health check for MCP server connectivity
 */
export async function mcpHealthCheck(env: Env): Promise<{
  healthy: boolean;
  latency?: number;
  error?: string;
}> {
  if (!env.MCP_SERVER_URL) {
    return { healthy: false, error: 'MCP_SERVER_URL not configured' };
  }
  
  const start = Date.now();
  
  try {
    const response = await fetch(env.MCP_SERVER_URL, {
      method: 'HEAD',
      signal: AbortSignal.timeout(5000),
    });
    
    const latency = Date.now() - start;
    
    return {
      healthy: response.ok || response.status === 405, // 405 Method Not Allowed is okay
      latency,
    };
  } catch (error) {
    return {
      healthy: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}