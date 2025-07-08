import { Context, Next } from 'hono';
import type { Env } from '../types';
import { createLogger } from '../logger';
import { 
  validateHost, 
  getRateLimitKey, 
  RateLimiter,
  buildCORSHeaders,
  DEFAULT_OAUTH_CORS,
  DEFAULT_MCP_CORS,
  type CORSConfig
} from './utils';

/**
 * Security Middleware for OAuth and MCP endpoints
 */

// Rate limiters (per worker instance)
const registrationLimiter = new RateLimiter(10, 60 * 60 * 1000); // 10 per hour
const tokenLimiter = new RateLimiter(100, 60 * 1000); // 100 per minute
const authLimiter = new RateLimiter(20, 60 * 1000); // 20 per minute

/**
 * DNS rebinding protection middleware
 */
export async function dnsRebindingProtection(
  c: Context<{ Bindings: Env }>,
  next: Next
) {
  const logger = createLogger('SecurityMiddleware', c.env);
  
  // Get allowed hosts from environment or use defaults
  const allowedHosts = c.env.ALLOWED_HOSTS 
    ? c.env.ALLOWED_HOSTS.split(',').map(h => h.trim())
    : [];
  
  // Add public URL host if configured
  if (c.env.PUBLIC_URL) {
    try {
      const publicUrl = new URL(c.env.PUBLIC_URL);
      allowedHosts.push(publicUrl.hostname);
    } catch {
      // Invalid PUBLIC_URL
    }
  }
  
  if (allowedHosts.length > 0 && !validateHost(c.req, allowedHosts)) {
    logger.warn('DNS rebinding attack blocked', {
      host: c.req.header('host'),
      allowed: allowedHosts,
    });
    
    return c.json({
      error: 'invalid_request',
      error_description: 'Invalid host header',
    }, 400);
  }
  
  await next();
}

/**
 * Rate limiting middleware factory
 */
export function rateLimitMiddleware(
  type: 'registration' | 'token' | 'auth'
) {
  return async function(c: Context<{ Bindings: Env }>, next: Next) {
    const logger = createLogger('RateLimiter', c.env);
    
    // Skip rate limiting if disabled
    if (c.env.DISABLE_RATE_LIMITING === 'true') {
      await next();
      return;
    }
    
    const key = getRateLimitKey(c.req, type);
    
    let limiter: RateLimiter;
    switch (type) {
      case 'registration':
        limiter = registrationLimiter;
        break;
      case 'token':
        limiter = tokenLimiter;
        break;
      case 'auth':
        limiter = authLimiter;
        break;
    }
    
    if (!limiter.check(key)) {
      logger.warn('Rate limit exceeded', { type, key });
      
      return c.json({
        error: 'rate_limit_exceeded',
        error_description: 'Too many requests, please try again later',
      }, 429);
    }
    
    // Cleanup old entries periodically
    if (Math.random() < 0.01) { // 1% chance
      limiter.cleanup();
    }
    
    await next();
  };
}

/**
 * CORS middleware factory
 */
export function corsMiddleware(
  config: CORSConfig = DEFAULT_OAUTH_CORS
) {
  return async function(c: Context<{ Bindings: Env }>, next: Next) {
    // Handle preflight requests
    if (c.req.method === 'OPTIONS') {
      const headers = buildCORSHeaders(c.req, config);
      return new Response(null, {
        status: 204,
        headers,
      });
    }
    
    // Add CORS headers to response
    await next();
    
    const headers = buildCORSHeaders(c.req, config);
    headers.forEach((value, key) => {
      c.res.headers.set(key, value);
    });
  };
}

/**
 * Security headers middleware
 */
export async function securityHeaders(
  c: Context<{ Bindings: Env }>,
  next: Next
) {
  await next();
  
  // Add security headers
  c.res.headers.set('X-Content-Type-Options', 'nosniff');
  c.res.headers.set('X-Frame-Options', 'DENY');
  c.res.headers.set('X-XSS-Protection', '1; mode=block');
  c.res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.res.headers.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
  // Add CSP for JSON responses
  if (c.res.headers.get('content-type')?.includes('application/json')) {
    c.res.headers.set(
      'Content-Security-Policy',
      "default-src 'none'; frame-ancestors 'none'"
    );
  }
}

/**
 * Request validation middleware
 */
export async function requestValidation(
  c: Context<{ Bindings: Env }>,
  next: Next
) {
  const logger = createLogger('RequestValidation', c.env);
  
  // Check Content-Type for POST/PUT requests
  if (['POST', 'PUT', 'PATCH'].includes(c.req.method)) {
    const contentType = c.req.header('content-type');
    
    if (!contentType) {
      logger.warn('Missing Content-Type header');
      return c.json({
        error: 'invalid_request',
        error_description: 'Content-Type header is required',
      }, 400);
    }
    
    // OAuth endpoints accept form-encoded or JSON
    const validTypes = [
      'application/x-www-form-urlencoded',
      'application/json',
    ];
    
    const hasValidType = validTypes.some(type => 
      contentType.toLowerCase().includes(type)
    );
    
    if (!hasValidType) {
      logger.warn('Invalid Content-Type', { content_type: contentType });
      return c.json({
        error: 'invalid_request',
        error_description: 'Content-Type must be application/x-www-form-urlencoded or application/json',
      }, 400);
    }
  }
  
  // Check for suspicious patterns
  const url = new URL(c.req.url);
  const suspicious = [
    '../',
    '..\\',
    '%2e%2e',
    '%252e%252e',
    'javascript:',
    'data:',
    'vbscript:',
  ];
  
  const urlString = url.toString().toLowerCase();
  for (const pattern of suspicious) {
    if (urlString.includes(pattern)) {
      logger.warn('Suspicious pattern in URL', { pattern, url: urlString });
      return c.json({
        error: 'invalid_request',
        error_description: 'Invalid URL',
      }, 400);
    }
  }
  
  await next();
}

/**
 * Token encryption at rest
 * Encrypts sensitive data before storing in KV
 */
export class TokenEncryption {
  private key: CryptoKey | null = null;
  
  constructor(private env: Env) {}
  
  /**
   * Get or generate encryption key
   */
  private async getKey(): Promise<CryptoKey> {
    if (this.key) {
      return this.key;
    }
    
    // Get key from environment or generate
    let keyData: Uint8Array;
    
    if (this.env.TOKEN_ENCRYPTION_KEY) {
      // Use provided key
      const hexKey = this.env.TOKEN_ENCRYPTION_KEY;
      keyData = new Uint8Array(hexKey.match(/.{2}/g)!.map(byte => parseInt(byte, 16)));
    } else {
      // Generate key (Note: This is per-worker instance)
      keyData = crypto.getRandomValues(new Uint8Array(32));
    }
    
    this.key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    
    return this.key;
  }
  
  /**
   * Encrypt data
   */
  async encrypt(data: string): Promise<string> {
    const key = await this.getKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(data);
    
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoded
    );
    
    // Combine IV and ciphertext
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    
    // Return base64
    return btoa(String.fromCharCode(...combined));
  }
  
  /**
   * Decrypt data
   */
  async decrypt(encryptedData: string): Promise<string> {
    const key = await this.getKey();
    const combined = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
    
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );
    
    return new TextDecoder().decode(decrypted);
  }
}