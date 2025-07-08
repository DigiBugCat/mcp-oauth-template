import type { ClientRegistrationRequest } from './dynamic';

/**
 * Client Registration Validation Utilities
 * Ensures client registration requests meet OAuth 2.1 and MCP requirements
 */

/**
 * Validate redirect URIs according to OAuth 2.1 and MCP specifications
 * - Must be absolute URIs
 * - Must use HTTPS except for localhost
 * - No fragments allowed
 * - No wildcard domains
 */
export function validateRedirectUris(uris: string[]): {
  valid: boolean;
  error?: string;
} {
  if (!uris || uris.length === 0) {
    return {
      valid: false,
      error: 'At least one redirect_uri is required',
    };
  }

  for (const uri of uris) {
    try {
      const url = new URL(uri);
      
      // No fragments allowed in redirect URIs
      if (url.hash) {
        return {
          valid: false,
          error: `Redirect URI must not contain fragments: ${uri}`,
        };
      }
      
      // Check protocol - must be HTTPS except for localhost
      const isLocalhost = url.hostname === 'localhost' || 
                         url.hostname === '127.0.0.1' ||
                         url.hostname === '[::1]';
      
      if (!isLocalhost && url.protocol !== 'https:') {
        return {
          valid: false,
          error: `Redirect URI must use HTTPS for non-localhost URLs: ${uri}`,
        };
      }
      
      // Allow HTTP for localhost
      if (isLocalhost && !['http:', 'https:'].includes(url.protocol)) {
        return {
          valid: false,
          error: `Invalid protocol for localhost redirect URI: ${uri}`,
        };
      }
      
      // No wildcards in hostname
      if (url.hostname.includes('*')) {
        return {
          valid: false,
          error: `Wildcard domains are not allowed in redirect URIs: ${uri}`,
        };
      }
      
      // No credentials in URL
      if (url.username || url.password) {
        return {
          valid: false,
          error: `Redirect URI must not contain credentials: ${uri}`,
        };
      }
      
    } catch (error) {
      return {
        valid: false,
        error: `Invalid redirect URI format: ${uri}`,
      };
    }
  }
  
  // Check for duplicates
  const uniqueUris = new Set(uris);
  if (uniqueUris.size !== uris.length) {
    return {
      valid: false,
      error: 'Duplicate redirect URIs are not allowed',
    };
  }
  
  return { valid: true };
}

/**
 * Validate client metadata
 */
export function validateClientMetadata(metadata: ClientRegistrationRequest): {
  valid: boolean;
  error?: string;
} {
  // Validate client name
  if (!metadata.client_name || metadata.client_name.trim().length === 0) {
    return {
      valid: false,
      error: 'client_name must not be empty',
    };
  }
  
  if (metadata.client_name.length > 255) {
    return {
      valid: false,
      error: 'client_name must not exceed 255 characters',
    };
  }
  
  // Validate grant types
  const validGrantTypes = ['authorization_code', 'client_credentials', 'refresh_token'];
  if (metadata.grant_types) {
    for (const grantType of metadata.grant_types) {
      if (!validGrantTypes.includes(grantType)) {
        return {
          valid: false,
          error: `Invalid grant_type: ${grantType}. Supported: ${validGrantTypes.join(', ')}`,
        };
      }
    }
    
    // If authorization_code is requested, must also support refresh_token
    if (metadata.grant_types.includes('authorization_code') && 
        !metadata.grant_types.includes('refresh_token')) {
      metadata.grant_types.push('refresh_token');
    }
  }
  
  // Validate response types
  const validResponseTypes = ['code'];
  if (metadata.response_types) {
    for (const responseType of metadata.response_types) {
      if (!validResponseTypes.includes(responseType)) {
        return {
          valid: false,
          error: `Invalid response_type: ${responseType}. Supported: ${validResponseTypes.join(', ')}`,
        };
      }
    }
  }
  
  // Validate token endpoint auth method
  const validAuthMethods = ['client_secret_post', 'client_secret_basic', 'none'];
  if (metadata.token_endpoint_auth_method) {
    if (!validAuthMethods.includes(metadata.token_endpoint_auth_method)) {
      return {
        valid: false,
        error: `Invalid token_endpoint_auth_method: ${metadata.token_endpoint_auth_method}. Supported: ${validAuthMethods.join(', ')}`,
      };
    }
  }
  
  // Validate scope
  if (metadata.scope) {
    // Scope should be space-separated values
    const scopes = metadata.scope.split(' ');
    for (const scope of scopes) {
      // Basic scope validation - alphanumeric plus common chars
      if (!/^[a-zA-Z0-9:_-]+$/.test(scope)) {
        return {
          valid: false,
          error: `Invalid scope format: ${scope}`,
        };
      }
    }
  }
  
  // Validate MCP extensions
  if (metadata.mcp_transport_types) {
    const validTransports = ['sse', 'http'];
    for (const transport of metadata.mcp_transport_types) {
      if (!validTransports.includes(transport)) {
        return {
          valid: false,
          error: `Invalid mcp_transport_type: ${transport}. Supported: ${validTransports.join(', ')}`,
        };
      }
    }
  }
  
  return { valid: true };
}

/**
 * Validate a single redirect URI against registered URIs
 * Used during authorization to ensure the redirect_uri matches
 */
export function validateRedirectUri(
  requestedUri: string,
  registeredUris: string[]
): boolean {
  // Exact match required - no pattern matching
  return registeredUris.includes(requestedUri);
}

/**
 * Validate client credentials based on auth method
 */
export function validateClientCredentials(
  clientId: string,
  clientSecret: string | undefined,
  authMethod: string,
  storedSecret: string | undefined
): {
  valid: boolean;
  error?: string;
} {
  // Public clients (auth_method = none)
  if (authMethod === 'none') {
    if (clientSecret) {
      return {
        valid: false,
        error: 'Public clients must not authenticate with client_secret',
      };
    }
    return { valid: true };
  }
  
  // Confidential clients must provide secret
  if (!clientSecret) {
    return {
      valid: false,
      error: 'client_secret is required for confidential clients',
    };
  }
  
  if (!storedSecret) {
    return {
      valid: false,
      error: 'Client is not configured with a secret',
    };
  }
  
  // Constant-time comparison
  if (!constantTimeEqual(clientSecret, storedSecret)) {
    return {
      valid: false,
      error: 'Invalid client credentials',
    };
  }
  
  return { valid: true };
}

/**
 * Extract client credentials from request based on auth method
 */
export function extractClientCredentials(request: Request, body?: URLSearchParams): {
  client_id?: string;
  client_secret?: string;
  auth_method: 'basic' | 'post' | 'none';
} {
  // Try Basic authentication first
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Basic ')) {
    try {
      const credentials = atob(authHeader.substring(6));
      const [clientId, clientSecret] = credentials.split(':');
      return {
        client_id: clientId,
        client_secret: clientSecret,
        auth_method: 'basic',
      };
    } catch {
      // Invalid Basic auth
    }
  }
  
  // Try POST body
  if (body) {
    const clientId = body.get('client_id');
    const clientSecret = body.get('client_secret');
    
    if (clientId) {
      return {
        client_id: clientId,
        client_secret: clientSecret || undefined,
        auth_method: clientSecret ? 'post' : 'none',
      };
    }
  }
  
  return { auth_method: 'none' };
}

/**
 * Constant-time string comparison
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
 * Generate a secure random string for client credentials
 */
export function generateSecureRandom(bytes: number = 32): string {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return base64urlEncode(array);
}

/**
 * Base64url encode
 */
function base64urlEncode(buffer: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...buffer));
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}