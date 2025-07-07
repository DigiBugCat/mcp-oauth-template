/**
 * OAuth error response utilities
 * Provides standardized error responses for OAuth endpoints
 */

export enum OAuthErrorCode {
  // Authorization errors
  INVALID_REQUEST = 'invalid_request',
  UNAUTHORIZED_CLIENT = 'unauthorized_client',
  ACCESS_DENIED = 'access_denied',
  UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type',
  INVALID_SCOPE = 'invalid_scope',
  SERVER_ERROR = 'server_error',
  TEMPORARILY_UNAVAILABLE = 'temporarily_unavailable',
  
  // Token errors
  INVALID_GRANT = 'invalid_grant',
  INVALID_CLIENT = 'invalid_client',
  UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type',
  
  // Rate limiting
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
}

interface OAuthErrorResponse {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

export class OAuthError extends Error {
  public code: OAuthErrorCode;
  public statusCode: number;
  public description?: string;
  public uri?: string;

  constructor(
    code: OAuthErrorCode,
    description?: string,
    statusCode: number = 400,
    uri?: string
  ) {
    super(description || code);
    this.code = code;
    this.statusCode = statusCode;
    this.description = description;
    this.uri = uri;
  }

  toJSON(): OAuthErrorResponse {
    const response: OAuthErrorResponse = {
      error: this.code,
    };

    if (this.description) {
      response.error_description = this.description;
    }

    if (this.uri) {
      response.error_uri = this.uri;
    }

    return response;
  }

  toResponse(state?: string): Response {
    const body = this.toJSON();
    if (state) {
      body.state = state;
    }

    return new Response(JSON.stringify(body), {
      status: this.statusCode,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
      },
    });
  }
}

// Common OAuth errors
export const OAuthErrors = {
  // Authorization errors
  invalidRequest: (description?: string) => 
    new OAuthError(
      OAuthErrorCode.INVALID_REQUEST,
      description || 'The request is missing a required parameter, includes an invalid parameter value, or is otherwise malformed.'
    ),

  unauthorizedClient: (description?: string) => 
    new OAuthError(
      OAuthErrorCode.UNAUTHORIZED_CLIENT,
      description || 'The client is not authorized to request an authorization code using this method.'
    ),

  accessDenied: (description?: string) => 
    new OAuthError(
      OAuthErrorCode.ACCESS_DENIED,
      description || 'The resource owner or authorization server denied the request.'
    ),

  unsupportedResponseType: (description?: string) => 
    new OAuthError(
      OAuthErrorCode.UNSUPPORTED_RESPONSE_TYPE,
      description || 'The authorization server does not support obtaining an authorization code using this method.'
    ),

  invalidScope: (description?: string) => 
    new OAuthError(
      OAuthErrorCode.INVALID_SCOPE,
      description || 'The requested scope is invalid, unknown, or malformed.'
    ),

  serverError: (description?: string) => 
    new OAuthError(
      OAuthErrorCode.SERVER_ERROR,
      description || 'The authorization server encountered an unexpected condition that prevented it from fulfilling the request.',
      500
    ),

  temporarilyUnavailable: (description?: string) => 
    new OAuthError(
      OAuthErrorCode.TEMPORARILY_UNAVAILABLE,
      description || 'The authorization server is currently unable to handle the request due to a temporary overloading or maintenance.',
      503
    ),

  // Token errors
  invalidGrant: (description?: string) => 
    new OAuthError(
      OAuthErrorCode.INVALID_GRANT,
      description || 'The provided authorization grant or refresh token is invalid, expired, revoked, or does not match the redirection URI.'
    ),

  invalidClient: (description?: string) => 
    new OAuthError(
      OAuthErrorCode.INVALID_CLIENT,
      description || 'Client authentication failed.',
      401
    ),

  unsupportedGrantType: (description?: string) => 
    new OAuthError(
      OAuthErrorCode.UNSUPPORTED_GRANT_TYPE,
      description || 'The authorization grant type is not supported by the authorization server.'
    ),

  // Rate limiting
  rateLimitExceeded: (retryAfter: number) => 
    new OAuthError(
      OAuthErrorCode.RATE_LIMIT_EXCEEDED,
      `Too many requests. Please try again in ${retryAfter} seconds.`,
      429
    ),
};

/**
 * Format error for redirect response
 */
export function createErrorRedirect(
  redirectUri: string,
  error: OAuthErrorCode,
  description?: string,
  state?: string
): Response {
  const url = new URL(redirectUri);
  url.searchParams.set('error', error);
  
  if (description) {
    url.searchParams.set('error_description', description);
  }
  
  if (state) {
    url.searchParams.set('state', state);
  }

  return new Response(null, {
    status: 302,
    headers: {
      'Location': url.toString(),
    },
  });
}