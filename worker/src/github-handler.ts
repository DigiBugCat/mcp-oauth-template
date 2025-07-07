import { Hono } from "hono";
import { Octokit } from "octokit";
import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import type { Env } from "./types";
import {
  getGitHubAuthorizeUrl,
  exchangeGitHubCodeForToken,
  type GitHubUser,
  type GitHubEmail,
  type Props,
} from "./oauth-utils";
import { ApprovalHandler } from "./approval-handler";
import { RegistrationHandler } from "./registration";
import { RootHandler } from "./root-handler";
import { createLogger } from "./logger";
import { AuditLogger } from "./audit";
import { TokenEndpointsHandler } from "./token-endpoints";
import { ClaudeIntegrationHandler } from "./claude-integration";

const app = new Hono<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>();

// Handle CORS preflight requests
app.options('*', (c) => {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
    }
  });
});

// Handle the OAuth authorization endpoint
// The OAuth provider library expects us to handle this
app.get("/oauth/authorize", async (c) => {
  const logger = createLogger('GitHubAuth', c.env);
  const audit = new AuditLogger(c.env);
  
  logger.debug('Authorization request received');
  
  // The OAuth provider passes the validated request info via query params
  // We need to preserve all OAuth parameters when redirecting to GitHub
  const queryString = c.req.url.split('?')[1] || '';
  
  // Parse OAuth parameters to create state
  const params = new URLSearchParams(queryString);
  const oauthState = {
    client_id: params.get('client_id'),
    redirect_uri: params.get('redirect_uri'), 
    scope: params.get('scope'),
    state: params.get('state'),
    code_challenge: params.get('code_challenge'),
    code_challenge_method: params.get('code_challenge_method'),
    response_type: params.get('response_type')
  };
  
  logger.debug('OAuth parameters parsed', { client_id: oauthState.client_id });
  
  // Encode OAuth state for GitHub callback
  const state = btoa(JSON.stringify(oauthState));
  
  // Redirect to GitHub with our callback URL
  const baseUrl = c.env.PUBLIC_URL || c.req.url;
  const callbackUrl = new URL("/callback", baseUrl);
  const githubUrl = getGitHubAuthorizeUrl({
    client_id: c.env.GITHUB_CLIENT_ID,
    redirect_uri: callbackUrl.href,
    scope: "read:user user:email",
    state,
  });
  
  logger.info('Redirecting to GitHub OAuth', { client_id: oauthState.client_id });
  return c.redirect(githubUrl);
});

// GET /callback - GitHub OAuth callback
app.get("/callback", async (c) => {
  const logger = createLogger('GitHubCallback', c.env);
  const audit = new AuditLogger(c.env);
  
  logger.debug('GitHub callback received');
  
  const code = c.req.query("code");
  const state = c.req.query("state");
  const error = c.req.query("error");

  if (error) {
    logger.error('GitHub OAuth error', { error });
    return c.text(`GitHub OAuth error: ${error}`, 400);
  }

  if (!code || !state) {
    logger.error('Invalid callback', { has_code: !!code, has_state: !!state });
    return c.text("Invalid callback: missing code or state", 400);
  }

  // Decode the OAuth request info from state
  interface OAuthState {
    client_id: string;
    redirect_uri: string;
    scope?: string;
    state?: string;
    code_challenge?: string;
    code_challenge_method?: string;
    response_type?: string;
  }
  
  let oauthState: OAuthState;
  try {
    oauthState = JSON.parse(atob(state)) as OAuthState;
    logger.debug('State decoded', { client_id: oauthState.client_id });
  } catch (e) {
    logger.error('Failed to decode state', { error: e instanceof Error ? e.message : String(e) });
    return c.text("Invalid state parameter", 400);
  }

  if (!oauthState.client_id) {
    logger.error('Missing client_id in state');
    return c.text("Invalid state: missing client_id", 400);
  }
  
  // Reconstruct the OAuth request info for completeAuthorization
  const oauthReqInfo = {
    clientId: oauthState.client_id,
    redirectUri: oauthState.redirect_uri,
    scope: oauthState.scope ? oauthState.scope.split(' ') : [],
    state: oauthState.state,
    codeChallenge: oauthState.code_challenge,
    codeChallengeMethod: oauthState.code_challenge_method,
  };

  // Exchange code for GitHub access token
  logger.debug('Exchanging GitHub code for token');
  const baseUrl = c.env.PUBLIC_URL || c.req.url;
  const redirectUri = new URL("/callback", baseUrl).href;
  
  const [accessToken, errorResponse] = await exchangeGitHubCodeForToken({
    client_id: c.env.GITHUB_CLIENT_ID,
    client_secret: c.env.GITHUB_CLIENT_SECRET,
    code,
    redirect_uri: redirectUri,
  });

  if (errorResponse) {
    logger.error('GitHub token exchange failed');
    await audit.log(c.req.raw, 'auth_failure', {
      client_id: oauthState.client_id,
      success: false,
      error_code: 'github_token_exchange_failed',
    });
    return errorResponse;
  }
  
  logger.info('GitHub token obtained successfully');

  // Get user info from GitHub
  const octokit = new Octokit({ auth: accessToken });
  
  try {
    // Get user profile
    const { data: user } = await octokit.rest.users.getAuthenticated();
    
    // Get user emails
    const { data: emails } = await octokit.rest.users.listEmailsForAuthenticatedUser();
    const primaryEmail = emails.find((e: GitHubEmail) => e.primary && e.verified)?.email || user.email;

    // Validate user access
    const isAuthorized = await validateGitHubUser(
      user,
      primaryEmail,
      accessToken!,
      c.env,
      octokit
    );

    if (!isAuthorized) {
      logger.warn('User not authorized', { user: user.login, email: primaryEmail });
      await audit.log(c.req.raw, 'auth_failure', {
        client_id: oauthState.client_id,
        user_id: user.id.toString(),
        user_email: primaryEmail,
        success: false,
        error_code: 'access_denied',
        details: { github_login: user.login },
      });
      
      const redirectUrl = new URL(oauthReqInfo.redirectUri);
      redirectUrl.searchParams.set("error", "access_denied");
      redirectUrl.searchParams.set("error_description", "User not authorized");
      if (oauthReqInfo.state) {
        redirectUrl.searchParams.set("state", oauthReqInfo.state);
      }
      return c.redirect(redirectUrl.toString());
    }

    // Store session data for approval
    logger.debug('Storing session for approval');
    const sessionId = crypto.randomUUID();
    const sessionData = {
      oauthRequest: oauthReqInfo,
      user: {
        id: user.id,
        login: user.login,
        name: user.name,
        email: primaryEmail || "unknown",
      },
      createdAt: Date.now(),
    };
    
    // Store session with 5-minute expiration
    await c.env.SESSION_KV.put(
      `approval:${sessionId}`,
      JSON.stringify(sessionData),
      { expirationTtl: 300 }
    );
    
    // Redirect to approval page
    const approvalUrl = new URL("/approve", c.req.url);
    approvalUrl.searchParams.set("session", sessionId);
    
    logger.info('Redirecting to approval page', { user: user.login });
    await audit.log(c.req.raw, 'auth_success', {
      client_id: oauthState.client_id,
      user_id: user.id.toString(),
      user_email: primaryEmail,
      success: true,
      details: { github_login: user.login },
    });
    
    return c.redirect(approvalUrl.toString());
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;
    
    logger.error('GitHub API error', { error: errorMessage, stack: errorStack });
    await audit.log(c.req.raw, 'auth_failure', {
      client_id: oauthState.client_id,
      success: false,
      error_code: 'github_api_error',
      details: { error: errorMessage },
    });
    return c.text("Failed to fetch user information: " + errorMessage, 500);
  }
});

// Helper function to redirect to GitHub
function redirectToGitHub(
  request: Request,
  oauthReqInfo: AuthRequest,
  env: Env,
  headers: Record<string, string> = {},
): Response {
  const baseUrl = env.PUBLIC_URL || request.url;
  const callbackUrl = new URL("/callback", baseUrl);
  const state = btoa(JSON.stringify(oauthReqInfo));

  const githubUrl = getGitHubAuthorizeUrl({
    client_id: env.GITHUB_CLIENT_ID,
    redirect_uri: callbackUrl.href,
    scope: "read:user user:email",
    state,
  });

  return new Response(null, {
    status: 302,
    headers: {
      ...headers,
      Location: githubUrl,
    },
  });
}

// Validate user against access control rules
async function validateGitHubUser(
  user: GitHubUser,
  userEmail: string | null,
  accessToken: string,
  env: Env,
  octokit: Octokit
): Promise<boolean> {
  // Check allowed users
  if (env.ALLOWED_GITHUB_USERS) {
    const allowedUsers = env.ALLOWED_GITHUB_USERS.split(',').map(u => u.trim().toLowerCase());
    if (allowedUsers.includes(user.login.toLowerCase())) {
      return true;
    }
  }

  // Check allowed organizations
  if (env.ALLOWED_GITHUB_ORGS) {
    const allowedOrgs = env.ALLOWED_GITHUB_ORGS.split(',').map(o => o.trim());
    for (const org of allowedOrgs) {
      try {
        await octokit.rest.orgs.checkMembershipForUser({
          org,
          username: user.login,
        });
        return true;
      } catch {
        // Not a member, continue checking
      }
    }
  }

  // Check allowed teams (format: org/team)
  if (env.ALLOWED_GITHUB_TEAMS) {
    const allowedTeams = env.ALLOWED_GITHUB_TEAMS.split(',').map(t => t.trim());
    for (const teamStr of allowedTeams) {
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
          // Not a member, continue checking
        }
      }
    }
  }

  // Check allowed email domains
  if (env.ALLOWED_EMAIL_DOMAINS && userEmail) {
    const allowedDomains = env.ALLOWED_EMAIL_DOMAINS.split(',').map(d => d.trim().toLowerCase());
    const emailDomain = userEmail.split('@')[1]?.toLowerCase();
    if (emailDomain && allowedDomains.includes(emailDomain)) {
      return true;
    }
  }

  // If no restrictions are set, allow all authenticated GitHub users
  return !env.ALLOWED_GITHUB_USERS && !env.ALLOWED_GITHUB_ORGS && 
         !env.ALLOWED_GITHUB_TEAMS && !env.ALLOWED_EMAIL_DOMAINS;
}

// OAuth metadata endpoints
app.get("/.well-known/oauth-authorization-server", async (c) => {
  // Always use PUBLIC_URL if available to ensure consistent HTTPS URLs
  const baseUrl = c.env.PUBLIC_URL || new URL(c.req.url).origin.replace('http:', 'https:');
  
  return c.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    registration_endpoint: `${baseUrl}/oauth/register`,
    introspection_endpoint: `${baseUrl}/oauth/introspect`,
    revocation_endpoint: `${baseUrl}/oauth/revoke`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    scopes_supported: ["mcp"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
    introspection_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
    revocation_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
    service_documentation: "https://github.com/modelcontextprotocol/specification",
    ui_locales_supported: ["en"],
  }, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    }
  });
});

app.get("/.well-known/oauth-protected-resource", async (c) => {
  const baseUrl = c.env.PUBLIC_URL || new URL(c.req.url).origin;
  
  return c.json({
    resource: baseUrl,
    authorization_servers: [baseUrl],
    scopes_supported: ["mcp"],
    bearer_methods_supported: ["header"],
    resource_documentation: "https://github.com/modelcontextprotocol/specification",
  }, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    }
  });
});

// Mount the approval handler
app.route("/", ApprovalHandler);

// Mount the registration handler
app.route("/", RegistrationHandler);

// Mount the token endpoints handler
app.route("/", TokenEndpointsHandler);

// Mount the Claude integration handler
app.route("/", ClaudeIntegrationHandler);

// Mount the root handler for MCP endpoints
app.route("/", RootHandler);

export { app as GitHubHandler };