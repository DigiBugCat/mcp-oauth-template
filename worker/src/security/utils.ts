/**
 * Security Utilities
 * Common security functions for OAuth implementation
 */

/**
 * Constant-time string comparison to prevent timing attacks
 * @param a First string
 * @param b Second string
 * @returns true if strings are equal, false otherwise
 */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}

/**
 * Secure random string generation using crypto.getRandomValues
 * @param bytes Number of random bytes to generate
 * @returns Base64url encoded random string
 */
export function generateSecureRandom(bytes: number = 32): string {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return base64urlEncode(array);
}

/**
 * Base64url encode a Uint8Array
 * @param buffer Buffer to encode
 * @returns Base64url encoded string
 */
export function base64urlEncode(buffer: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...buffer));
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Base64url decode to Uint8Array
 * @param str Base64url encoded string
 * @returns Decoded buffer
 */
export function base64urlDecode(str: string): Uint8Array {
  // Add padding if necessary
  const padding = '='.repeat((4 - (str.length % 4)) % 4);
  const base64 = (str + padding)
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  
  const binary = atob(base64);
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    buffer[i] = binary.charCodeAt(i);
  }
  return buffer;
}

/**
 * SHA-256 hash
 * @param data String to hash
 * @returns Hex-encoded hash
 */
export async function sha256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * SHA-256 hash with base64url encoding
 * @param data String to hash
 * @returns Base64url encoded hash
 */
export async function sha256Base64url(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  return base64urlEncode(new Uint8Array(hashBuffer));
}

/**
 * Token binding for enhanced security
 * Binds tokens to specific client properties
 */
export interface TokenBinding {
  client_id: string;
  ip_address?: string;
  user_agent?: string;
}

/**
 * Create token binding hash
 * @param binding Token binding properties
 * @returns Binding hash
 */
export async function createTokenBinding(binding: TokenBinding): Promise<string> {
  const parts = [
    binding.client_id,
    binding.ip_address || '',
    binding.user_agent || '',
  ];
  return sha256(parts.join('|'));
}

/**
 * Validate token binding
 * @param storedBinding Stored binding hash
 * @param currentBinding Current request binding
 * @returns true if binding matches
 */
export async function validateTokenBinding(
  storedBinding: string,
  currentBinding: TokenBinding
): Promise<boolean> {
  const currentHash = await createTokenBinding(currentBinding);
  return constantTimeEqual(storedBinding, currentHash);
}

/**
 * DNS rebinding protection
 * Validates that the Host header matches expected values
 */
export function validateHost(request: { header: (name: string) => string | undefined } | Request, allowedHosts: string[]): boolean {
  const host = 'header' in request ? request.header('host') : request.headers.get('host');
  if (!host) {
    return false;
  }
  
  // Remove port if present
  const hostname = host.split(':')[0];
  
  // Allow localhost variants
  const localhostVariants = ['localhost', '127.0.0.1', '[::1]'];
  if (localhostVariants.includes(hostname)) {
    return true;
  }
  
  // Check against allowed hosts
  return allowedHosts.includes(hostname);
}

/**
 * Rate limiting key generator
 * Creates a key for rate limiting based on various factors
 */
export function getRateLimitKey(
  request: { header: (name: string) => string | undefined } | Request,
  type: 'registration' | 'token' | 'auth'
): string {
  const ip = 'header' in request 
    ? (request.header('cf-connecting-ip') || request.header('x-forwarded-for') || 'unknown')
    : (request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown');
  
  return `ratelimit:${type}:${ip}`;
}

/**
 * Simple in-memory rate limiter for Workers
 * Note: This is per-worker instance and doesn't persist
 */
export class RateLimiter {
  private counters = new Map<string, { count: number; resetAt: number }>();
  
  constructor(
    private limit: number,
    private windowMs: number
  ) {}
  
  /**
   * Check if request should be allowed
   * @param key Rate limit key
   * @returns true if allowed, false if rate limited
   */
  check(key: string): boolean {
    const now = Date.now();
    const counter = this.counters.get(key);
    
    if (!counter || now > counter.resetAt) {
      // New window
      this.counters.set(key, {
        count: 1,
        resetAt: now + this.windowMs,
      });
      return true;
    }
    
    if (counter.count >= this.limit) {
      return false;
    }
    
    counter.count++;
    return true;
  }
  
  /**
   * Clean up expired entries
   */
  cleanup(): void {
    const now = Date.now();
    for (const [key, counter] of this.counters.entries()) {
      if (now > counter.resetAt) {
        this.counters.delete(key);
      }
    }
  }
}

/**
 * CORS configuration builder
 */
export interface CORSConfig {
  allowedOrigins: string[];
  allowedMethods: string[];
  allowedHeaders: string[];
  exposedHeaders?: string[];
  credentials?: boolean;
  maxAge?: number;
}

/**
 * Build CORS headers
 * @param request Current request
 * @param config CORS configuration
 * @returns Headers object with CORS headers
 */
export function buildCORSHeaders(
  request: { header: (name: string) => string | undefined } | Request,
  config: CORSConfig
): Headers {
  const headers = new Headers();
  const origin = 'header' in request ? request.header('origin') : request.headers.get('origin');
  
  // Check if origin is allowed
  if (origin && (config.allowedOrigins.includes('*') || config.allowedOrigins.includes(origin))) {
    headers.set('Access-Control-Allow-Origin', origin);
  } else if (config.allowedOrigins.includes('*')) {
    headers.set('Access-Control-Allow-Origin', '*');
  }
  
  // Set other CORS headers
  headers.set('Access-Control-Allow-Methods', config.allowedMethods.join(', '));
  headers.set('Access-Control-Allow-Headers', config.allowedHeaders.join(', '));
  
  if (config.exposedHeaders && config.exposedHeaders.length > 0) {
    headers.set('Access-Control-Expose-Headers', config.exposedHeaders.join(', '));
  }
  
  if (config.credentials) {
    headers.set('Access-Control-Allow-Credentials', 'true');
  }
  
  if (config.maxAge) {
    headers.set('Access-Control-Max-Age', config.maxAge.toString());
  }
  
  return headers;
}

/**
 * Default CORS config for OAuth endpoints
 */
export const DEFAULT_OAUTH_CORS: CORSConfig = {
  allowedOrigins: ['*'],
  allowedMethods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
};

/**
 * Default CORS config for MCP endpoints
 */
export const DEFAULT_MCP_CORS: CORSConfig = {
  allowedOrigins: ['*'],
  allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'MCP-Protocol-Version', 'Mcp-Session-Id'],
  exposedHeaders: ['MCP-Protocol-Version', 'Mcp-Session-Id'],
  maxAge: 86400,
};