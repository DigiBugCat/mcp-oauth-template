/**
 * PKCE (Proof Key for Code Exchange) Implementation
 * RFC 7636 compliant implementation for OAuth 2.1
 * 
 * PKCE is mandatory for all OAuth 2.1 authorization code flows
 * to prevent authorization code interception attacks.
 */

/**
 * Generate a cryptographically secure code verifier
 * Must be between 43-128 characters long
 */
export function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64urlEncode(array);
}

/**
 * Generate code challenge from verifier using SHA-256
 * Only S256 method is supported (plain is deprecated)
 */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64urlEncode(new Uint8Array(hash));
}

/**
 * Validate code verifier against stored challenge
 * Uses constant-time comparison to prevent timing attacks
 */
export async function validateCodeVerifier(
  verifier: string,
  challenge: string,
  method: string = 'S256'
): Promise<boolean> {
  // Only S256 is supported
  if (method !== 'S256') {
    return false;
  }

  const computedChallenge = await generateCodeChallenge(verifier);
  return constantTimeEqual(computedChallenge, challenge);
}

/**
 * Check if the code challenge method is valid
 * Only S256 is supported in OAuth 2.1
 */
export function isValidCodeChallengeMethod(method: string): boolean {
  return method === 'S256';
}

/**
 * Validate code verifier format
 * Must be 43-128 characters, using unreserved characters only
 */
export function isValidCodeVerifier(verifier: string): boolean {
  if (!verifier || verifier.length < 43 || verifier.length > 128) {
    return false;
  }
  
  // Check for unreserved characters only: [A-Z] [a-z] [0-9] - . _ ~
  const unreservedRegex = /^[A-Za-z0-9\-._~]+$/;
  return unreservedRegex.test(verifier);
}

/**
 * Base64url encode (no padding)
 */
function base64urlEncode(buffer: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...buffer));
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Constant-time string comparison to prevent timing attacks
 */
function constantTimeEqual(a: string, b: string): boolean {
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
 * PKCE Error class for specific PKCE-related errors
 */
export class PKCEError extends Error {
  constructor(
    message: string,
    public code: 'invalid_request' | 'invalid_grant' = 'invalid_request'
  ) {
    super(message);
    this.name = 'PKCEError';
  }
}

/**
 * Validate PKCE parameters in authorization request
 */
export function validatePKCEAuthorizationParams(params: {
  code_challenge?: string;
  code_challenge_method?: string;
}): { valid: boolean; error?: string } {
  // PKCE is mandatory in OAuth 2.1
  if (!params.code_challenge) {
    return {
      valid: false,
      error: 'code_challenge is required for authorization code flow',
    };
  }

  // Default to S256 if not specified
  const method = params.code_challenge_method || 'S256';
  
  if (!isValidCodeChallengeMethod(method)) {
    return {
      valid: false,
      error: 'code_challenge_method must be S256',
    };
  }

  // Validate challenge format (base64url encoded, 43 characters for SHA256)
  if (params.code_challenge.length !== 43) {
    return {
      valid: false,
      error: 'code_challenge must be 43 characters (base64url encoded SHA256)',
    };
  }

  return { valid: true };
}

/**
 * Store PKCE challenge with authorization code
 */
export interface PKCEData {
  code_challenge: string;
  code_challenge_method: string;
}

/**
 * Extract PKCE data for storage with authorization code
 */
export function extractPKCEData(params: {
  code_challenge?: string;
  code_challenge_method?: string;
}): PKCEData | null {
  if (!params.code_challenge) {
    return null;
  }

  return {
    code_challenge: params.code_challenge,
    code_challenge_method: params.code_challenge_method || 'S256',
  };
}