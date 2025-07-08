import { Octokit } from 'octokit';
import { BaseIdentityProvider, type UserInfo, type AuthOptions, type AccessConfig, type ProviderTokenResponse } from './provider';
import type { Env } from '../types';

/**
 * GitHub Identity Provider Implementation
 */

interface GitHubUser {
  id: number;
  login: string;
  name: string | null;
  email: string | null;
  avatar_url: string;
  type: string;
  site_admin: boolean;
}

interface GitHubEmail {
  email: string;
  primary: boolean;
  verified: boolean;
  visibility: string | null;
}

export class GitHubProvider extends BaseIdentityProvider {
  name = 'github';
  
  constructor(clientId: string, clientSecret: string, env: Env) {
    super(clientId, clientSecret, env);
  }
  
  getAuthorizationUrl(options: AuthOptions): string {
    return this.buildUrl('https://github.com/login/oauth/authorize', {
      client_id: this.clientId,
      redirect_uri: options.redirect_uri,
      scope: options.scope || this.getDefaultScopes().join(' '),
      state: options.state,
      ...options.params,
    });
  }
  
  async exchangeCode(code: string, redirectUri: string): Promise<ProviderTokenResponse> {
    const response = await this.fetchJson<{
      access_token: string;
      token_type: string;
      scope: string;
      error?: string;
      error_description?: string;
    }>('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: this.clientId,
        client_secret: this.clientSecret,
        code,
        redirect_uri: redirectUri,
      }),
    });
    
    if (response.error) {
      throw new Error(`GitHub OAuth error: ${response.error} - ${response.error_description}`);
    }
    
    return {
      access_token: response.access_token,
      token_type: response.token_type,
      scope: response.scope,
    };
  }
  
  async getUserInfo(accessToken: string): Promise<UserInfo> {
    const octokit = new Octokit({ auth: accessToken });
    
    // Get user profile
    const { data: user } = await octokit.rest.users.getAuthenticated();
    
    // Get user emails
    const { data: emails } = await octokit.rest.users.listEmailsForAuthenticatedUser();
    
    // Find primary verified email
    const primaryEmail = emails.find((e: GitHubEmail) => e.primary && e.verified);
    const email = primaryEmail?.email || user.email;
    
    return {
      id: user.id.toString(),
      email,
      email_verified: primaryEmail?.verified || false,
      login: user.login,
      name: user.name,
      avatar_url: user.avatar_url,
      provider: 'github',
      provider_data: {
        type: user.type,
        site_admin: user.site_admin,
      },
    };
  }
  
  async validateAccess(user: UserInfo, config: AccessConfig): Promise<boolean> {
    // Check basic access rules first
    const basicAccess = await super.validateAccess(user, config);
    if (basicAccess) {
      return true;
    }
    
    // If no GitHub-specific rules, deny
    if (!config.allowed_orgs && !config.allowed_teams) {
      return false;
    }
    
    // Need an authenticated Octokit instance for org/team checks
    // This requires the original access token, which we don't have here
    // In a real implementation, we'd need to pass the token through
    // For now, we'll need to handle this in the OAuth flow
    
    // Check organizations
    if (config.allowed_orgs && this.env.GITHUB_ACCESS_TOKEN) {
      const octokit = new Octokit({ auth: this.env.GITHUB_ACCESS_TOKEN });
      
      for (const org of config.allowed_orgs) {
        try {
          await octokit.rest.orgs.checkMembershipForUser({
            org,
            username: user.login,
          });
          return true; // User is member of allowed org
        } catch {
          // Not a member, continue checking
        }
      }
    }
    
    // Check teams
    if (config.allowed_teams && this.env.GITHUB_ACCESS_TOKEN) {
      const octokit = new Octokit({ auth: this.env.GITHUB_ACCESS_TOKEN });
      
      for (const teamStr of config.allowed_teams) {
        const [org, team_slug] = teamStr.split('/');
        if (org && team_slug) {
          try {
            await octokit.rest.teams.getMembershipForUserInOrg({
              org,
              team_slug,
              username: user.login,
            });
            return true; // User is member of allowed team
          } catch {
            // Not a member, continue checking
          }
        }
      }
    }
    
    return false;
  }
  
  getDefaultScopes(): string[] {
    return ['read:user', 'user:email'];
  }
}

/**
 * Extended GitHub provider with access token for org/team validation
 */
export class GitHubProviderWithToken extends GitHubProvider {
  constructor(
    clientId: string,
    clientSecret: string,
    env: Env,
    private userAccessToken: string
  ) {
    super(clientId, clientSecret, env);
  }
  
  async validateAccess(user: UserInfo, config: AccessConfig): Promise<boolean> {
    // Check basic access rules first
    const basicAccess = await super.validateAccess(user, config);
    if (basicAccess) {
      return true;
    }
    
    // If no GitHub-specific rules, deny
    if (!config.allowed_orgs && !config.allowed_teams) {
      return false;
    }
    
    const octokit = new Octokit({ auth: this.userAccessToken });
    
    // Check organizations
    if (config.allowed_orgs) {
      for (const org of config.allowed_orgs) {
        try {
          await octokit.rest.orgs.checkMembershipForUser({
            org,
            username: user.login,
          });
          return true;
        } catch {
          // Not a member, continue
        }
      }
    }
    
    // Check teams
    if (config.allowed_teams) {
      for (const teamStr of config.allowed_teams) {
        const [org, team_slug] = teamStr.split('/');
        if (org && team_slug) {
          try {
            await octokit.rest.teams.getMembershipForUserInOrg({
              org,
              team_slug,
              username: user.login,
            });
            return true;
          } catch {
            // Not a member, continue
          }
        }
      }
    }
    
    return false;
  }
}

/**
 * Create access config from environment variables
 */
export function createGitHubAccessConfig(env: Env): AccessConfig {
  const config: AccessConfig = {};
  
  if (env.ALLOWED_GITHUB_USERS) {
    config.allowed_users = env.ALLOWED_GITHUB_USERS.split(',').map(u => u.trim());
  }
  
  if (env.ALLOWED_GITHUB_ORGS) {
    config.allowed_orgs = env.ALLOWED_GITHUB_ORGS.split(',').map(o => o.trim());
  }
  
  if (env.ALLOWED_GITHUB_TEAMS) {
    config.allowed_teams = env.ALLOWED_GITHUB_TEAMS.split(',').map(t => t.trim());
  }
  
  if (env.ALLOWED_EMAIL_DOMAINS) {
    config.allowed_email_domains = env.ALLOWED_EMAIL_DOMAINS.split(',').map(d => d.trim());
  }
  
  return config;
}