export interface Env {
  // KV Namespace
  KV: KVNamespace;
  
  // GitHub OAuth Configuration
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  
  // MCP Configuration
  MCP_SERVER_URL: string;
  
  // OAuth Provider Configuration
  COOKIE_ENCRYPTION_KEY: string;
  
  // Access Control
  ALLOWED_GITHUB_USERS?: string;
  ALLOWED_GITHUB_ORGS?: string;
  ALLOWED_GITHUB_TEAMS?: string;
  ALLOWED_EMAIL_DOMAINS?: string;
  
  // Environment
  ENVIRONMENT?: string;
  PUBLIC_URL?: string;
  LOG_LEVEL?: string;
  
  // Pre-configured OAuth clients (JSON string)
  PRECONFIGURED_OAUTH_CLIENTS?: string;
  
  // Rate limiting
  RATE_LIMITER?: DurableObjectNamespace;
  DISABLE_RATE_LIMITING?: string;
  
  // Security
  TOKEN_ENCRYPTION_KEY?: string;
  ALLOWED_HOSTS?: string;
  ALLOWED_ORIGINS?: string;
  
  // GitHub Service Account (for org/team validation)
  GITHUB_ACCESS_TOKEN?: string;
}

export interface MCPClient {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  name: string;
  created_at: string;
}

export interface OAuthSession {
  session_id: string;
  client_id: string;
  redirect_uri: string;
  state?: string;
  code_challenge: string;
  code_challenge_method: string;
  scope: string;
  created_at: string;
  expires_at: string;
}

export interface AuthorizationCode {
  code: string;
  client_id: string;
  user_id: string;
  user_email: string;
  user_login: string;
  redirect_uri: string;
  scope: string;
  code_challenge: string;
  code_challenge_method: string;
  created_at: string;
  expires_at: string;
}

export interface AccessToken {
  token: string;
  refresh_token?: string;
  client_id: string;
  user_id: string;
  user_email: string;
  user_login: string;
  scope: string;
  created_at: string;
  expires_at: string;
}

export interface RefreshToken {
  token: string;
  client_id: string;
  user_id: string;
  user_email: string;
  user_login: string;
  scope: string;
  created_at: string;
  expires_at: string;
  access_token?: string;
}

export interface GitHubUser {
  id: number;
  login: string;
  email: string | null;
  name: string | null;
  avatar_url: string;
}

export interface GitHubEmail {
  email: string;
  primary: boolean;
  verified: boolean;
  visibility: string | null;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  event_type: 'auth_success' | 'auth_failure' | 'token_issued' | 'token_refreshed' | 'token_revoked' | 'token_introspected';
  client_id: string;
  user_id?: string;
  user_email?: string;
  ip_address: string;
  user_agent: string;
  details?: Record<string, any>;
  success: boolean;
  error_code?: string;
}