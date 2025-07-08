import { Hono } from 'hono';
import type { Env } from './types';
import { createLogger } from './logger';
import { AuditLogger } from './audit';
import { MetricsCollector } from './metrics';
import { validateConfiguration, getConfigSummary } from './config-validator';
import { initializeClients } from './client-init';

// Import new OAuth server
import { oauthServer } from './oauth/server';
import { mcpAuthHandler } from './mcp/auth';

// Import security middleware
import { 
  securityHeaders,
  dnsRebindingProtection,
  requestValidation,
  corsMiddleware
} from './security/middleware';
import { DEFAULT_MCP_CORS } from './security/utils';

// Create main application
const app = new Hono<{ Bindings: Env }>();

// Global middleware
app.use('*', securityHeaders);
app.use('*', dnsRebindingProtection);
app.use('*', requestValidation);

// Health check endpoint
app.get('/health', async (c) => {
  const logger = createLogger('HealthCheck', c.env);
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: c.env.ENVIRONMENT || 'development',
    config: getConfigSummary(c.env),
    checks: {
      kv: false,
      mcp_server: false,
      github_oauth: false,
    },
  };

  try {
    // Check KV namespace
    await c.env.KV.get('health_check');
    health.checks.kv = true;

    // Check MCP server connectivity
    if (c.env.MCP_SERVER_URL) {
      try {
        const response = await fetch(c.env.MCP_SERVER_URL, {
          method: 'HEAD',
          signal: AbortSignal.timeout(5000),
        });
        health.checks.mcp_server = response.ok || response.status === 405;
      } catch {
        health.checks.mcp_server = false;
      }
    }

    // Check GitHub OAuth config
    health.checks.github_oauth = !!(c.env.GITHUB_CLIENT_ID && c.env.GITHUB_CLIENT_SECRET);

    // Overall health status
    const allHealthy = Object.values(health.checks).every(check => check === true);
    health.status = allHealthy ? 'healthy' : 'degraded';

  } catch (error) {
    logger.error('Health check failed', { 
      error: error instanceof Error ? error.message : String(error) 
    });
    health.status = 'unhealthy';
  }

  const statusCode = health.status === 'healthy' ? 200 : 503;
  
  return c.json(health, statusCode);
});

// Metrics endpoint
app.get('/metrics', async (c) => {
  const logger = createLogger('MetricsEndpoint', c.env);
  const url = new URL(c.req.url);
  
  // Parse query parameters
  const metricName = url.searchParams.get('name');
  const aggregation = url.searchParams.get('aggregation') as 'sum' | 'avg' | 'max' | 'min' | 'count' || 'sum';
  const hoursAgo = parseInt(url.searchParams.get('hours') || '1');
  
  const endTime = Date.now();
  const startTime = endTime - (hoursAgo * 60 * 60 * 1000);
  
  try {
    const metrics = new MetricsCollector(c.env);
    
    if (metricName) {
      // Get aggregated metrics for a specific metric
      const aggregated = await metrics.getAggregatedMetrics(
        startTime, 
        endTime, 
        metricName, 
        aggregation
      );
      
      return c.json({
        metric: metricName,
        aggregation,
        timeRange: {
          start: new Date(startTime).toISOString(),
          end: new Date(endTime).toISOString(),
        },
        data: aggregated,
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
      
      return c.json({
        timeRange: {
          start: new Date(startTime).toISOString(),
          end: new Date(endTime).toISOString(),
        },
        summary,
        totalMetrics: rawMetrics.length,
      });
    }
  } catch (error) {
    logger.error('Failed to fetch metrics', { 
      error: error instanceof Error ? error.message : String(error) 
    });
    return c.json({ error: 'Failed to fetch metrics' }, 500);
  }
});

// OAuth 2.0 Discovery Endpoints (RFC 8414) - must be at root level
app.get('/.well-known/oauth-authorization-server', async (c) => {
  const baseUrl = c.env.PUBLIC_URL || new URL(c.req.url).origin;
  
  return c.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    registration_endpoint: `${baseUrl}/oauth/register`,
    introspection_endpoint: `${baseUrl}/oauth/introspect`,
    revocation_endpoint: `${baseUrl}/oauth/revoke`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token'],
    scopes_supported: ['mcp'],
    code_challenge_methods_supported: ['S256'], // Only S256, plain is not supported
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    introspection_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    revocation_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    service_documentation: 'https://github.com/modelcontextprotocol/specification',
    ui_locales_supported: ['en'],
    // MCP-specific metadata
    mcp_endpoint: `${baseUrl}/mcp`,
    mcp_transport_types: ['sse', 'http'],
  });
});

app.get('/.well-known/oauth-protected-resource', async (c) => {
  const baseUrl = c.env.PUBLIC_URL || new URL(c.req.url).origin;
  
  return c.json({
    resource: baseUrl,
    authorization_servers: [baseUrl],
    scopes_supported: ['mcp'],
    bearer_methods_supported: ['header'], // No query parameter support!
    resource_documentation: 'https://github.com/modelcontextprotocol/specification',
  });
});

// Mount OAuth server at /oauth
app.route('/oauth', oauthServer);

// MCP endpoints with optional authentication
app.all('/mcp/*', corsMiddleware(DEFAULT_MCP_CORS), async (c) => {
  // Check if authentication is disabled
  if (c.env.DISABLE_MCP_AUTH === 'true') {
    const { mcpProxyHandler } = await import('./mcp/proxy');
    return mcpProxyHandler(c.req.raw, c.env, null);
  } else {
    return mcpAuthHandler(c.req.raw, c.env, c.executionCtx);
  }
});

app.all('/mcp', corsMiddleware(DEFAULT_MCP_CORS), async (c) => {
  // Check if authentication is disabled
  if (c.env.DISABLE_MCP_AUTH === 'true') {
    const { mcpProxyHandler } = await import('./mcp/proxy');
    return mcpProxyHandler(c.req.raw, c.env, null);
  } else {
    return mcpAuthHandler(c.req.raw, c.env, c.executionCtx);
  }
});

// Root handler
app.get('/', (c) => {
  return c.text('MCP OAuth Server');
});

// Main export
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const startTime = Date.now();
    const logger = createLogger('Main', env);
    const audit = new AuditLogger(env);
    const metrics = new MetricsCollector(env);
    
    try {
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
      
      // Log request details
      const url = new URL(request.url);
      logger.debug('Request received', {
        method: request.method,
        path: url.pathname,
        client_ip: request.headers.get('CF-Connecting-IP'),
        user_agent: request.headers.get('User-Agent'),
        origin: request.headers.get('Origin'),
        referer: request.headers.get('Referer'),
      });
      
      // Process request through Hono app
      const response = await app.fetch(request, env, ctx);
      
      // Audit logging for specific endpoints
      if (url.pathname === '/oauth/token' && request.method === 'POST' && response.status === 200) {
        try {
          const responseClone = response.clone();
          const responseData = await responseClone.json();
          
          if (responseData.access_token) {
            const formData = await request.clone().formData().catch(() => null);
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
        } catch {
          // Ignore audit logging errors
        }
      }
      
      // Record metrics
      await metrics.recordRequestMetrics(request, response, startTime);
      
      logger.debug('Request completed', {
        status: response.status,
        path: url.pathname,
      });
      
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
      
      // List all keys with different prefixes
      const prefixes = ['tok:', 'code:', 'auth_session:', 'reg_token:', 'ratelimit:'];
      
      for (const prefix of prefixes) {
        const keys = await env.KV.list({ prefix });
        
        for (const key of keys.keys) {
          const value = await env.KV.get(key.name);
          
          if (value) {
            try {
              const data = JSON.parse(value);
              
              // Check various expiration fields
              let isExpired = false;
              
              if (data.expires_at) {
                isExpired = new Date(data.expires_at).getTime() < now;
              } else if (data.expiresAt) {
                isExpired = new Date(data.expiresAt).getTime() < now;
              } else if (data.created_at && prefix === 'auth_session:') {
                // Sessions expire after 10 minutes
                isExpired = (now - new Date(data.created_at).getTime()) > 600000;
              } else if (data.resetAt && prefix === 'ratelimit:') {
                // Rate limit entries expire after their reset time
                isExpired = data.resetAt < now;
              }
              
              if (isExpired) {
                await env.KV.delete(key.name);
                deletedCount++;
                logger.debug('Deleted expired item', { key: key.name, prefix });
              }
            } catch (e) {
              // If we can't parse it, it's probably old/corrupted
              if (prefix !== 'ratelimit:') { // Rate limit keys might not be JSON
                await env.KV.delete(key.name);
                deletedCount++;
                logger.warn('Deleted invalid item', { key: key.name, prefix });
              }
            }
          }
        }
      }
      
      logger.info('Cleanup completed', { deletedCount });
    } catch (error) {
      logger.error('Cleanup failed', { 
        error: error instanceof Error ? error.message : String(error) 
      });
    }
  }
};

// Export Durable Objects
export { RateLimiter } from './rate-limiter';