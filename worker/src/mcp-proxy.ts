import type { Env } from "./types";
import type { Props } from "./oauth-utils";
import { createLogger } from "./logger";

/**
 * MCP Proxy Handler - forwards authenticated requests to the Docker MCP server
 */
export async function mcpProxyHandler(
  request: Request,
  env: Env,
  ctx: { props: Props }
): Promise<Response> {
  const logger = createLogger('MCPProxy', env);
  
  logger.debug('Proxying authenticated request', {
    method: request.method,
    path: new URL(request.url).pathname,
    user_id: ctx.props.user_id,
  });
  
  // Get the MCP server URL from environment
  if (!env.MCP_SERVER_URL) {
    logger.error('MCP_SERVER_URL not configured');
    return new Response("MCP server URL not configured", { status: 500 });
  }

  // Parse the request URL to get the path
  const url = new URL(request.url);
  const mcpPath = url.pathname;
  
  // Build the target URL
  const targetUrl = new URL(mcpPath, env.MCP_SERVER_URL);
  targetUrl.search = url.search;
  
  logger.debug('Target URL', { target: targetUrl.toString() });

  // Create headers for the proxied request
  const headers = new Headers(request.headers);
  
  // Remove host header to avoid conflicts
  headers.delete('host');
  
  // Add authentication headers from OAuth props
  headers.set('X-User-ID', ctx.props.user_id);
  headers.set('X-User-Email', ctx.props.email);
  headers.set('X-User-Login', ctx.props.login);
  headers.set('X-User-Name', ctx.props.name);
  
  // Remove OAuth authorization header since MCP server doesn't need it
  headers.delete('authorization');
  
  // Add origin header if missing (some SSE implementations require it)
  if (!headers.has('origin')) {
    headers.set('origin', new URL(request.url).origin);
  }

  try {
    // Forward the request to the MCP server
    const response = await fetch(targetUrl.toString(), {
      method: request.method,
      headers: headers,
      body: request.body,
      redirect: 'manual',
    });

    logger.debug('MCP server response', {
      status: response.status,
      content_type: response.headers.get('content-type'),
    });

    // Handle SSE (Server-Sent Events) properly
    if (response.headers.get('content-type')?.includes('text/event-stream')) {
      logger.info('Handling SSE response', { 
        user_id: ctx.props.user_id,
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
      });
      
      // For SSE, we need to ensure proper streaming
      const headers = new Headers({
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no', // Disable buffering for nginx
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Expose-Headers': 'Content-Type',
      });
      
      // Copy any important headers from the original response
      const transferHeaders = ['x-session-id', 'x-mcp-version'];
      for (const header of transferHeaders) {
        const value = response.headers.get(header);
        if (value) {
          headers.set(header, value);
        }
      }
      
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers,
      });
    }

    // For regular responses, forward as-is
    const responseHeaders = new Headers(response.headers);
    
    // Remove any internal headers
    responseHeaders.delete('x-powered-by');
    
    // Add CORS headers
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
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
    return new Response('Failed to connect to MCP server', { 
      status: 502,
      headers: { 
        'Content-Type': 'text/plain',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    });
  }
}

/**
 * Root proxy handler - handles unauthenticated requests to root path
 */
export async function rootProxyHandler(
  request: Request,
  env: Env,
  ctx: { props?: Props }
): Promise<Response> {
  const logger = createLogger('RootProxy', env);
  logger.debug('Handling root request', { method: request.method });

  // For root path, return a simple message
  const url = new URL(request.url);
  if (url.pathname === '/' && request.method === 'GET') {
    return new Response('MCP OAuth Server', {
      status: 200,
      headers: { 'Content-Type': 'text/plain' },
    });
  }

  // For other paths, proxy to MCP server (if needed)
  return mcpProxyHandler(request, env, ctx);
}