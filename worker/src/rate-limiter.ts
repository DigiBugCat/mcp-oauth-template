import { createLogger } from './logger';

interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
}

export class RateLimiter implements DurableObject {
  private state: DurableObjectState;
  private logger: ReturnType<typeof createLogger>;

  constructor(state: DurableObjectState, env: any) {
    this.state = state;
    this.logger = createLogger('RateLimiter', env);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const key = url.searchParams.get('key');
    const windowMs = parseInt(url.searchParams.get('windowMs') || '60000');
    const maxRequests = parseInt(url.searchParams.get('maxRequests') || '10');

    if (!key) {
      return new Response(JSON.stringify({ error: 'Missing key parameter' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const now = Date.now();
    const windowStart = now - windowMs;

    // Get current request count for this key
    const requests = (await this.state.storage.get<number[]>(key)) || [];
    
    // Filter out expired requests
    const validRequests = requests.filter(timestamp => timestamp > windowStart);
    
    // Check if limit exceeded
    if (validRequests.length >= maxRequests) {
      const oldestRequest = Math.min(...validRequests);
      const resetTime = oldestRequest + windowMs;
      const retryAfter = Math.ceil((resetTime - now) / 1000);

      this.logger.info('Rate limit exceeded', {
        key,
        requests: validRequests.length,
        maxRequests,
        retryAfter,
      });

      return new Response(JSON.stringify({
        allowed: false,
        limit: maxRequests,
        remaining: 0,
        reset: resetTime,
        retryAfter,
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'X-RateLimit-Limit': maxRequests.toString(),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': resetTime.toString(),
          'Retry-After': retryAfter.toString(),
        },
      });
    }

    // Add current request
    validRequests.push(now);
    await this.state.storage.put(key, validRequests);

    // Schedule cleanup of this key after window expires
    await this.state.storage.setAlarm(now + windowMs + 1000);

    const remaining = maxRequests - validRequests.length;
    const reset = now + windowMs;

    return new Response(JSON.stringify({
      allowed: true,
      limit: maxRequests,
      remaining,
      reset,
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'X-RateLimit-Limit': maxRequests.toString(),
        'X-RateLimit-Remaining': remaining.toString(),
        'X-RateLimit-Reset': reset.toString(),
      },
    });
  }

  async alarm(): Promise<void> {
    // Clean up expired entries
    const now = Date.now();
    const keys = await this.state.storage.list<number[]>();
    
    for (const [key, requests] of keys) {
      const validRequests = requests.filter(timestamp => timestamp > now - 3600000); // Keep for 1 hour
      if (validRequests.length === 0) {
        await this.state.storage.delete(key);
      } else if (validRequests.length !== requests.length) {
        await this.state.storage.put(key, validRequests);
      }
    }
  }
}

export async function checkRateLimit(
  env: { RATE_LIMITER?: DurableObjectNamespace },
  key: string,
  config: RateLimitConfig = { windowMs: 60000, maxRequests: 10 }
): Promise<{ allowed: boolean; remaining: number; reset: number; retryAfter?: number }> {
  if (!env.RATE_LIMITER) {
    // If rate limiter is not configured, allow all requests
    return { allowed: true, remaining: config.maxRequests, reset: Date.now() + config.windowMs };
  }

  const id = env.RATE_LIMITER.idFromName(key);
  const stub = env.RATE_LIMITER.get(id);
  
  const response = await stub.fetch(
    `http://rate-limiter/check?key=${encodeURIComponent(key)}&windowMs=${config.windowMs}&maxRequests=${config.maxRequests}`
  );
  
  return await response.json();
}