import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { GitHubHandler } from "./github-handler";
import { mcpProxyHandler } from "./mcp-proxy";
import { initializeClients } from "./client-init";
import { createLogger } from "./logger";
import { validateConfiguration, getConfigSummary } from "./config-validator";
import { AuditLogger } from "./audit";
import { checkRateLimit, RateLimiter } from "./rate-limiter";
import { MetricsCollector } from "./metrics";
import { handleRefreshTokenGrant } from "./oauth-extensions";
import { mcpAuthHandler } from "./mcp-auth-handler";
import type { Env } from "./types";
import type { Props } from "./oauth-utils";

export { RateLimiter };

/**
 * Wrapper class for the MCP proxy handler
 */
class MCPProxyHandler {
  async fetch(request: Request, env: Env, ctx: { props: Props }): Promise<Response> {
    return mcpProxyHandler(request, env, ctx);
  }
}

/**
 * Main OAuth Provider configuration
 */
const provider = new OAuthProvider({
  // Protected API routes - these require OAuth authentication
  // Using /mcp as the protected route prefix
  apiRoute: "/mcp",
  
  // Handler for authenticated API requests - proxies to MCP server
  apiHandler: new MCPProxyHandler(),
  
  // Handler for non-API routes (authorization, callbacks, metadata)
  defaultHandler: GitHubHandler,
  
  // OAuth endpoints
  authorizeEndpoint: "/oauth/authorize",
  tokenEndpoint: "/oauth/token", 
  clientRegistrationEndpoint: "/oauth/register",
  
  // Token introspection endpoint
  introspectionEndpoint: "/oauth/introspect",
  
  // Token revocation endpoint
  revocationEndpoint: "/oauth/revoke",
  
  // Token exchange callback for auditing
  tokenExchangeCallback: async (props, accessToken) => {
    // props.env might not be available in this callback
    console.log('Token exchange callback', { 
      client_id: props.client_id,
      has_access_token: !!accessToken,
    });
    return accessToken;
  },
});

// Health check handler
async function handleHealthCheck(env: Env): Promise<Response> {
  const logger = createLogger('HealthCheck', env);
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: env.ENVIRONMENT || 'development',
    config: getConfigSummary(env),
    checks: {
      oauth_kv: false,
      session_kv: false,
      mcp_server: false,
      github_oauth: false,
    },
  };

  try {
    // Check KV namespaces
    await env.OAUTH_KV.get('health_check');
    health.checks.oauth_kv = true;
    
    await env.SESSION_KV.get('health_check');
    health.checks.session_kv = true;

    // Check MCP server connectivity
    try {
      const response = await fetch(env.MCP_SERVER_URL, {
        method: 'HEAD',
        signal: AbortSignal.timeout(5000),
      });
      health.checks.mcp_server = response.ok || response.status === 405;
    } catch {
      health.checks.mcp_server = false;
    }

    // Check GitHub OAuth config
    health.checks.github_oauth = !!(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET);

    // Overall health status
    const allHealthy = Object.values(health.checks).every(check => check === true);
    health.status = allHealthy ? 'healthy' : 'degraded';

  } catch (error) {
    logger.error('Health check failed', { error: error instanceof Error ? error.message : String(error) });
    health.status = 'unhealthy';
  }

  const statusCode = health.status === 'healthy' ? 200 : 503;
  
  return new Response(JSON.stringify(health, null, 2), {
    status: statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  });
}

// Metrics endpoint handler
async function handleMetricsEndpoint(request: Request, env: Env): Promise<Response> {
  const logger = createLogger('MetricsEndpoint', env);
  const url = new URL(request.url);
  
  // Parse query parameters
  const metricName = url.searchParams.get('name');
  const aggregation = url.searchParams.get('aggregation') as 'sum' | 'avg' | 'max' | 'min' | 'count' || 'sum';
  const hoursAgo = parseInt(url.searchParams.get('hours') || '1');
  
  const endTime = Date.now();
  const startTime = endTime - (hoursAgo * 60 * 60 * 1000);
  
  try {
    const metrics = new MetricsCollector(env);
    
    if (metricName) {
      // Get aggregated metrics for a specific metric
      const aggregated = await metrics.getAggregatedMetrics(startTime, endTime, metricName, aggregation);
      
      return new Response(JSON.stringify({
        metric: metricName,
        aggregation,
        timeRange: {
          start: new Date(startTime).toISOString(),
          end: new Date(endTime).toISOString(),
        },
        data: aggregated,
      }, null, 2), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'max-age=60',
        },
      });
    } else {
      // Get raw metrics
      const rawMetrics = await metrics.getMetrics(startTime, endTime);
      
      // Group by metric name for summary
      const summary: Record<string, { count: number; latest: number }> = {};
      for (const metric of rawMetrics) {
        if (!summary[metric.name]) {
          summary[metric.name] = { count: 0, latest: 0 };
        }
        summary[metric.name].count++;
        summary[metric.name].latest = metric.value;
      }
      
      return new Response(JSON.stringify({
        timeRange: {
          start: new Date(startTime).toISOString(),
          end: new Date(endTime).toISOString(),
        },
        summary,
        totalMetrics: rawMetrics.length,
      }, null, 2), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'max-age=60',
        },
      });
    }
  } catch (error) {
    logger.error('Failed to fetch metrics', { error: error.message });
    return new Response(JSON.stringify({ error: 'Failed to fetch metrics' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Wrapper to ensure clients are initialized and add our custom endpoints
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const startTime = Date.now();
    const logger = createLogger('Main', env);
    const audit = new AuditLogger(env);
    const metrics = new MetricsCollector(env);
    
    try {
      const url = new URL(request.url);
      logger.debug('Request received', {
        method: request.method,
        path: url.pathname,
        client_ip: request.headers.get('CF-Connecting-IP'),
        user_agent: request.headers.get('User-Agent'),
        origin: request.headers.get('Origin'),
        referer: request.headers.get('Referer'),
      });
      
      // Validate configuration on first request
      try {
        validateConfiguration(env);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error('Configuration validation failed', { error: errorMessage });
        const response = new Response('Service misconfigured', { status: 500 });
        await metrics.recordRequestMetrics(request, response, startTime);
        return response;
      }
      
      // Initialize clients on first request (this is idempotent)
      await initializeClients(env);
      
      // Handle CORS preflight requests globally
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
      
      // Handle metadata endpoints before OAuth provider
      if (url.pathname === '/.well-known/oauth-authorization-server' && request.method === 'GET') {
        const baseUrl = env.PUBLIC_URL || url.origin;
        return new Response(JSON.stringify({
          issuer: baseUrl,
          authorization_endpoint: `${baseUrl}/oauth/authorize`,
          token_endpoint: `${baseUrl}/oauth/token`,
          registration_endpoint: `${baseUrl}/oauth/register`,
          introspection_endpoint: `${baseUrl}/oauth/introspect`,
          revocation_endpoint: `${baseUrl}/oauth/revoke`,
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code", "refresh_token"],
          scopes_supported: ["mcp"],
          code_challenge_methods_supported: ["S256"],
          token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
          introspection_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
          revocation_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
          service_documentation: "https://github.com/modelcontextprotocol/specification",
          ui_locales_supported: ["en"],
          // Add MCP-specific metadata
          mcp_endpoint: `${baseUrl}/mcp`,
          mcp_transport_types: ["sse", "http"],
        }, null, 2), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
          }
        });
      }
      
      if (url.pathname === '/.well-known/oauth-protected-resource' && request.method === 'GET') {
        const baseUrl = env.PUBLIC_URL || url.origin;
        return new Response(JSON.stringify({
          resource: baseUrl,
          authorization_servers: [baseUrl],
          scopes_supported: ["mcp"],
          bearer_methods_supported: ["header"],
          resource_documentation: "https://github.com/modelcontextprotocol/specification",
        }, null, 2), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
          }
        });
      }
      
      // Health check endpoint
      if (url.pathname === '/health' && request.method === 'GET') {
        return handleHealthCheck(env);
      }
      
      // Metrics endpoint
      if (url.pathname === '/metrics' && request.method === 'GET') {
        return handleMetricsEndpoint(request, env);
      }
      
      // Handle MCP routes with manual authentication
      if (url.pathname === '/mcp' || url.pathname.startsWith('/mcp/')) {
        logger.debug('Handling MCP route with manual authentication');
        const response = await mcpAuthHandler(request, env, ctx);
        await metrics.recordRequestMetrics(request, response, startTime);
        return response;
      }
      
      // Apply rate limiting to token endpoint
      if (url.pathname === '/oauth/token' && request.method === 'POST') {
        // Log the original request before any modifications
        const debugClone = request.clone();
        const debugFormData = await debugClone.formData();
        const debugParams: Record<string, string> = {};
        for (const [key, value] of debugFormData.entries()) {
          debugParams[key] = value.toString();
        }
        logger.info('Token exchange request (original)', {
          grant_type: debugParams.grant_type,
          client_id: debugParams.client_id,
          client_secret: debugParams.client_secret ? 'present' : 'missing',
          code: debugParams.code ? 'present' : 'missing',
          code_verifier: debugParams.code_verifier ? 'present' : 'missing',
          redirect_uri: debugParams.redirect_uri,
          user_agent: request.headers.get('User-Agent'),
        });
        
        const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
        const rateLimitKey = `token:${clientIp}`;
        
        const rateLimitResult = await checkRateLimit(env, rateLimitKey, {
          windowMs: 60000, // 1 minute
          maxRequests: 10, // 10 requests per minute
        });
        
        if (!rateLimitResult.allowed) {
          await audit.log(request, 'token_issued', {
            client_id: 'unknown',
            success: false,
            error_code: 'rate_limit_exceeded',
            details: { rate_limit: rateLimitResult },
          });
          
          metrics.recordCounter('oauth_rate_limit_exceeded', 1, {
            endpoint: 'token',
            client_ip: clientIp,
          });
          
          const response = new Response(JSON.stringify({
            error: 'rate_limit_exceeded',
            error_description: 'Too many requests. Please try again later.',
          }), {
            status: 429,
            headers: {
              'Content-Type': 'application/json',
              'Retry-After': rateLimitResult.retryAfter?.toString() || '60',
              'X-RateLimit-Limit': '10',
              'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
              'X-RateLimit-Reset': rateLimitResult.reset.toString(),
            },
          });
          
          await metrics.recordRequestMetrics(request, response, startTime);
          return response;
        }
        
        // Check if this is a refresh token grant
        const formData = await request.clone().formData();
        const grantType = formData.get('grant_type')?.toString();
        
        if (grantType === 'refresh_token') {
          const refreshResponse = await handleRefreshTokenGrant(request, env, formData);
          if (refreshResponse) {
            await metrics.recordRequestMetrics(request, refreshResponse, startTime);
            return refreshResponse;
          }
        }
        
        // Handle PKCE token exchange ourselves since OAuth provider doesn't support it properly
        if (grantType === 'authorization_code' && formData.get('code_verifier')) {
          const code = formData.get('code')?.toString();
          const clientId = formData.get('client_id')?.toString();
          const codeVerifier = formData.get('code_verifier')?.toString();
          const redirectUri = formData.get('redirect_uri')?.toString();
          
          if (!code || !clientId || !codeVerifier || !redirectUri) {
            const response = new Response(JSON.stringify({
              error: 'invalid_request',
              error_description: 'Missing required parameters',
            }), {
              status: 400,
              headers: { 'Content-Type': 'application/json' },
            });
            await metrics.recordRequestMetrics(request, response, startTime);
            return response;
          }
          
          // Get authorization code data
          logger.debug('Looking up authorization code', {
            code,
            lookup_key: `code:${code}`,
          });
          
          const codeData = await env.OAUTH_KV.get(`code:${code}`);
          if (!codeData) {
            // List all keys to debug
            const allKeys = await env.OAUTH_KV.list({ prefix: 'code:' });
            logger.warn('Invalid authorization code', { 
              client_id: clientId,
              code,
              lookup_key: `code:${code}`,
              available_codes: allKeys.keys.map(k => k.name),
            });
            const response = new Response(JSON.stringify({
              error: 'invalid_grant',
              error_description: 'Invalid or expired authorization code',
            }), {
              status: 400,
              headers: { 'Content-Type': 'application/json' },
            });
            await metrics.recordRequestMetrics(request, response, startTime);
            return response;
          }
          
          const authCode = JSON.parse(codeData);
          
          // Validate client_id matches
          if (authCode.client_id !== clientId) {
            logger.warn('Client ID mismatch', { 
              provided: clientId,
              expected: authCode.client_id,
            });
            const response = new Response(JSON.stringify({
              error: 'invalid_grant',
              error_description: 'Authorization code was issued to another client',
            }), {
              status: 400,
              headers: { 'Content-Type': 'application/json' },
            });
            await metrics.recordRequestMetrics(request, response, startTime);
            return response;
          }
          
          // Validate redirect_uri matches
          if (authCode.redirect_uri !== redirectUri) {
            logger.warn('Redirect URI mismatch', {
              provided: redirectUri,
              expected: authCode.redirect_uri,
            });
            const response = new Response(JSON.stringify({
              error: 'invalid_grant',
              error_description: 'Redirect URI mismatch',
            }), {
              status: 400,
              headers: { 'Content-Type': 'application/json' },
            });
            await metrics.recordRequestMetrics(request, response, startTime);
            return response;
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
              const response = new Response(JSON.stringify({
                error: 'invalid_grant',
                error_description: 'PKCE verification failed',
              }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' },
              });
              await metrics.recordRequestMetrics(request, response, startTime);
              return response;
            }
          }
          
          // Delete the authorization code (one-time use)
          await env.OAUTH_KV.delete(`code:${code}`);
          
          // Create access token
          const tokenManager = new (await import('./token-utils')).TokenManager(env);
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
          
          await audit.log(request, 'token_issued', {
            client_id: clientId,
            user_id: authCode.user_id,
            user_email: authCode.user_email,
            success: true,
            details: {
              grant_type: 'authorization_code',
              pkce: true,
            },
          });
          
          const response = new Response(JSON.stringify({
            access_token,
            token_type: 'Bearer',
            expires_in,
            refresh_token,
            scope: authCode.scope || 'mcp',
          }), {
            status: 200,
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            },
          });
          
          await metrics.recordRequestMetrics(request, response, startTime);
          return response;
        }
        
      }
      
      // Log all requests to see what's happening
      if (url.pathname === '/oauth/register') {
        logger.info('Registration request received', {
          method: request.method,
          headers: Object.fromEntries(request.headers.entries()),
        });
      }
      
      
      // Clone request for potential later use
      const clonedRequest = request.clone();
      
      // Pass through to the OAuth provider
      const response = await provider.fetch(request, env, ctx);
      
      // Handle token endpoint specially
      if (url.pathname === '/oauth/token' && request.method === 'POST') {
        // Read the response body once
        const responseText = await response.text();
        let responseData = null;
        
        try {
          responseData = JSON.parse(responseText);
        } catch (e) {
          // Not JSON response
        }
        
        // Create new response with CORS headers
        const newResponse = new Response(responseText, {
          status: response.status,
          statusText: response.statusText,
          headers: new Headers(response.headers)
        });
        newResponse.headers.set('Access-Control-Allow-Origin', '*');
        newResponse.headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
        newResponse.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        
        // Audit logging
        if (response.status === 200 && responseData?.access_token) {
          // Parse request body to get client_id from the cloned request
          const formData = await clonedRequest.formData().catch(() => null);
          const clientId = formData?.get('client_id')?.toString() || 'unknown';
          
          await audit.log(request, 'token_issued', {
            client_id: clientId,
            success: true,
            details: {
              grant_type: formData?.get('grant_type')?.toString(),
              scope: responseData.scope,
            },
          });
        }
        
        // Record metrics and return the new response
        await metrics.recordRequestMetrics(request, newResponse, startTime);
        return newResponse;
      }
      
      logger.debug('Request completed', {
        status: response.status,
        path: url.pathname,
      });
      
      // Record metrics
      await metrics.recordRequestMetrics(request, response, startTime);
      
      return response;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const errorStack = error instanceof Error ? error.stack : undefined;
      
      logger.error('Request failed', { 
        error: errorMessage,
        stack: errorStack,
      });
      
      const errorResponse = new Response('Internal Server Error', { status: 500 });
      await metrics.recordRequestMetrics(request, errorResponse, startTime);
      return errorResponse;
    }
  },
  
  // Scheduled handler for periodic cleanup
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const logger = createLogger('Scheduler', env);
    logger.info('Starting periodic cleanup');
    
    try {
      const now = Date.now();
      let deletedCount = 0;
      
      // List all keys
      const allKeys = await env.OAUTH_KV.list();
      
      for (const key of allKeys.keys) {
        // Check different key types - new format uses token itself as key
        if (key.name.startsWith('token_') || key.name.startsWith('refresh_') || 
            key.name.startsWith('code:') || key.name.startsWith('session:') ||
            // Legacy format support
            key.name.startsWith('token:') || key.name.startsWith('refresh:')) {
          const value = await env.OAUTH_KV.get(key.name);
          if (value) {
            try {
              const data = JSON.parse(value);
              // Check if expired
              if (data.expires_at && new Date(data.expires_at).getTime() < now) {
                await env.OAUTH_KV.delete(key.name);
                deletedCount++;
                logger.debug('Deleted expired item', { key: key.name });
              }
            } catch (e) {
              // If we can't parse it, it's probably old/corrupted, delete it
              await env.OAUTH_KV.delete(key.name);
              deletedCount++;
              logger.warn('Deleted invalid item', { key: key.name });
            }
          }
        }
      }
      
      // Clean up sessions from SESSION_KV as well
      const sessionKeys = await env.SESSION_KV.list();
      for (const key of sessionKeys.keys) {
        const value = await env.SESSION_KV.get(key.name);
        if (value) {
          try {
            const data = JSON.parse(value);
            // Session data has createdAt timestamp
            if (data.createdAt && (now - data.createdAt) > 300000) { // 5 minutes
              await env.SESSION_KV.delete(key.name);
              deletedCount++;
              logger.debug('Deleted expired session', { key: key.name });
            }
          } catch (e) {
            // Delete invalid sessions
            await env.SESSION_KV.delete(key.name);
            deletedCount++;
          }
        }
      }
      
      logger.info('Cleanup completed', { deletedCount });
    } catch (error) {
      logger.error('Cleanup failed', { error: error instanceof Error ? error.message : String(error) });
    }
  }
};