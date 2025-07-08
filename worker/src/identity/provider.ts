/**
 * Identity Provider Interface
 * Abstracts authentication provider implementations (GitHub, Google, etc.)
 */

/**
 * User information returned from identity provider
 */
export interface UserInfo {
  id: string;
  email: string | null;
  email_verified?: boolean;
  login: string;
  name: string | null;
  avatar_url?: string;
  // Provider-specific data
  provider: string;
  provider_data?: Record<string, any>;
}

/**
 * Options for authorization URL generation
 */
export interface AuthOptions {
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  // Additional provider-specific parameters
  params?: Record<string, string>;
}

/**
 * Access control configuration
 */
export interface AccessConfig {
  // Allowed users by username
  allowed_users?: string[];
  // Allowed organizations
  allowed_orgs?: string[];
  // Allowed teams (format: org/team)
  allowed_teams?: string[];
  // Allowed email domains
  allowed_email_domains?: string[];
}

/**
 * OAuth token response from provider
 */
export interface ProviderTokenResponse {
  access_token: string;
  token_type: string;
  scope?: string;
  expires_in?: number;
  refresh_token?: string;
}

/**
 * Identity Provider Interface
 * All identity providers must implement this interface
 */
export interface IdentityProvider {
  /**
   * Provider name (e.g., 'github', 'google')
   */
  name: string;
  
  /**
   * Generate authorization URL for OAuth flow
   */
  getAuthorizationUrl(options: AuthOptions): string;
  
  /**
   * Exchange authorization code for access token
   */
  exchangeCode(code: string, redirectUri: string): Promise<ProviderTokenResponse>;
  
  /**
   * Get user information using access token
   */
  getUserInfo(accessToken: string): Promise<UserInfo>;
  
  /**
   * Validate user access based on configuration
   */
  validateAccess(user: UserInfo, config: AccessConfig): Promise<boolean>;
  
  /**
   * Get provider-specific scopes for authorization
   */
  getDefaultScopes(): string[];
  
  /**
   * Refresh access token if supported
   */
  refreshToken?(refreshToken: string): Promise<ProviderTokenResponse>;
}

/**
 * Base implementation with common functionality
 */
export abstract class BaseIdentityProvider implements IdentityProvider {
  abstract name: string;
  
  constructor(
    protected clientId: string,
    protected clientSecret: string,
    protected env: any
  ) {}
  
  abstract getAuthorizationUrl(options: AuthOptions): string;
  abstract exchangeCode(code: string, redirectUri: string): Promise<ProviderTokenResponse>;
  abstract getUserInfo(accessToken: string): Promise<UserInfo>;
  abstract getDefaultScopes(): string[];
  
  /**
   * Default access validation logic
   * Can be overridden by specific providers
   */
  async validateAccess(user: UserInfo, config: AccessConfig): Promise<boolean> {
    // No restrictions means allow all
    if (!config.allowed_users && 
        !config.allowed_orgs && 
        !config.allowed_teams && 
        !config.allowed_email_domains) {
      return true;
    }
    
    // Check allowed users
    if (config.allowed_users && user.login) {
      const allowedUsers = config.allowed_users.map(u => u.toLowerCase());
      if (allowedUsers.includes(user.login.toLowerCase())) {
        return true;
      }
    }
    
    // Check allowed email domains
    if (config.allowed_email_domains && user.email) {
      const emailDomain = user.email.split('@')[1]?.toLowerCase();
      if (emailDomain) {
        const allowedDomains = config.allowed_email_domains.map(d => d.toLowerCase());
        if (allowedDomains.includes(emailDomain)) {
          return true;
        }
      }
    }
    
    // Provider-specific checks (orgs, teams) must be implemented by subclass
    return false;
  }
  
  /**
   * Build URL with query parameters
   */
  protected buildUrl(baseUrl: string, params: Record<string, string>): string {
    const url = new URL(baseUrl);
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        url.searchParams.set(key, value);
      }
    });
    return url.toString();
  }
  
  /**
   * Make HTTP request with proper error handling
   */
  protected async fetchJson<T>(
    url: string,
    options: RequestInit = {}
  ): Promise<T> {
    const response = await fetch(url, {
      ...options,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'MCP-OAuth-Server/1.0',
        ...options.headers,
      },
    });
    
    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Provider API error: ${response.status} - ${error}`);
    }
    
    return response.json() as Promise<T>;
  }
}

/**
 * Provider registry for managing multiple providers
 */
export class ProviderRegistry {
  private providers = new Map<string, IdentityProvider>();
  
  register(provider: IdentityProvider): void {
    this.providers.set(provider.name, provider);
  }
  
  get(name: string): IdentityProvider | undefined {
    return this.providers.get(name);
  }
  
  list(): string[] {
    return Array.from(this.providers.keys());
  }
}

/**
 * Error class for identity provider errors
 */
export class IdentityProviderError extends Error {
  constructor(
    message: string,
    public provider: string,
    public code?: string
  ) {
    super(message);
    this.name = 'IdentityProviderError';
  }
}