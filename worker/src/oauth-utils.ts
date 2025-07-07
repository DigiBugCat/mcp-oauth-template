import type { AuthRequest, ClientInfo } from "@cloudflare/workers-oauth-provider";

const COOKIE_NAME = "mcp-approved-clients";
const ONE_YEAR_IN_SECONDS = 31536000;

/**
 * Constructs an authorization URL for GitHub OAuth.
 */
export function getGitHubAuthorizeUrl(params: {
  client_id: string;
  redirect_uri: string;
  scope: string;
  state?: string;
}): string {
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", params.client_id);
  url.searchParams.set("redirect_uri", params.redirect_uri);
  url.searchParams.set("scope", params.scope);
  url.searchParams.set("response_type", "code");
  if (params.state) {
    url.searchParams.set("state", params.state);
  }
  return url.href;
}

/**
 * Exchanges GitHub authorization code for access token.
 */
export async function exchangeGitHubCodeForToken(params: {
  client_id: string;
  client_secret: string;
  code: string;
  redirect_uri: string;
}): Promise<[string, null] | [null, Response]> {
  console.log("🔍 OAUTH-UTILS DEBUG: Exchanging GitHub code for token");
  console.log("🔍 OAUTH-UTILS DEBUG: Request params:", {
    client_id: params.client_id,
    redirect_uri: params.redirect_uri,
    code: params.code ? "present" : "missing"
  });
  
  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json",
    },
    body: new URLSearchParams({
      client_id: params.client_id,
      client_secret: params.client_secret,
      code: params.code,
      redirect_uri: params.redirect_uri,
    }).toString(),
  });

  console.log("🔍 OAUTH-UTILS DEBUG: GitHub response status:", response.status);

  if (!response.ok) {
    const errorText = await response.text();
    console.error("🔍 OAUTH-UTILS DEBUG: GitHub error response:", errorText);
    return [null, new Response("Failed to exchange code for token", { status: 500 })];
  }

  const data = await response.json() as any;
  console.log("🔍 OAUTH-UTILS DEBUG: GitHub response data:", {
    has_access_token: !!data.access_token,
    has_error: !!data.error,
    error: data.error,
    error_description: data.error_description
  });
  
  if (data.error) {
    console.error("🔍 OAUTH-UTILS DEBUG: GitHub returned error:", data.error, data.error_description);
    return [null, new Response(data.error_description || data.error, { status: 400 })];
  }

  if (!data.access_token) {
    console.error("🔍 OAUTH-UTILS DEBUG: No access token in response");
    return [null, new Response("Missing access token", { status: 400 })];
  }

  console.log("🔍 OAUTH-UTILS DEBUG: Successfully got access token");
  return [data.access_token, null];
}

/**
 * Imports a secret key for HMAC-SHA256 signing.
 */
async function importKey(secret: string): Promise<CryptoKey> {
  if (!secret) {
    throw new Error("COOKIE_ENCRYPTION_KEY is required for signing cookies");
  }
  const enc = new TextEncoder();
  return crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { hash: "SHA-256", name: "HMAC" },
    false,
    ["sign", "verify"],
  );
}

/**
 * Signs data using HMAC-SHA256.
 */
async function signData(key: CryptoKey, data: string): Promise<string> {
  const enc = new TextEncoder();
  const signatureBuffer = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return Array.from(new Uint8Array(signatureBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Verifies an HMAC-SHA256 signature.
 */
async function verifySignature(
  key: CryptoKey,
  signatureHex: string,
  data: string,
): Promise<boolean> {
  const enc = new TextEncoder();
  try {
    const signatureBytes = new Uint8Array(
      signatureHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)),
    );
    return await crypto.subtle.verify("HMAC", key, signatureBytes.buffer, enc.encode(data));
  } catch {
    return false;
  }
}

/**
 * Checks if a client has already been approved via cookies.
 */
export async function clientIdAlreadyApproved(
  request: Request,
  clientId: string,
  secret: string,
): Promise<boolean> {
  const cookieHeader = request.headers.get("Cookie");
  if (!cookieHeader) return false;

  const cookies = Object.fromEntries(
    cookieHeader.split(";").map((c) => {
      const [key, ...rest] = c.trim().split("=");
      return [key, rest.join("=")];
    }),
  );

  const cookieValue = cookies[COOKIE_NAME];
  if (!cookieValue) return false;

  try {
    const [data, signature] = cookieValue.split(".");
    if (!data || !signature) return false;

    const key = await importKey(secret);
    const isValid = await verifySignature(key, signature, data);
    if (!isValid) return false;

    const approvedClients = JSON.parse(atob(data)) as string[];
    return approvedClients.includes(clientId);
  } catch {
    return false;
  }
}

/**
 * Renders an approval dialog for OAuth consent.
 */
export function renderApprovalDialog(
  request: Request,
  options: {
    client?: ClientInfo;
    server: {
      name: string;
      description: string;
      logo: string;
    };
    state: any;
  },
): Response {
  const { client, server, state } = options;
  const stateEncoded = btoa(JSON.stringify(state));

  const html = `
<!DOCTYPE html>
<html>
<head>
  <title>Authorization Request</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
      max-width: 600px;
      margin: 50px auto;
      padding: 20px;
      background-color: #f5f5f5;
    }
    .container {
      background: white;
      padding: 30px;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    h1 { color: #333; }
    .client-info {
      background: #e3f2fd;
      padding: 15px;
      border-radius: 4px;
      margin: 20px 0;
    }
    .server-info {
      margin: 20px 0;
      text-align: center;
    }
    .logo {
      width: 64px;
      height: 64px;
      border-radius: 8px;
    }
    .actions {
      margin-top: 30px;
      display: flex;
      gap: 10px;
      justify-content: center;
    }
    button {
      padding: 10px 20px;
      border: none;
      border-radius: 4px;
      font-size: 16px;
      cursor: pointer;
    }
    .approve {
      background: #4CAF50;
      color: white;
    }
    .deny {
      background: #f44336;
      color: white;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="server-info">
      <img src="${server.logo}" alt="${server.name}" class="logo">
      <h1>${server.name}</h1>
      <p>${server.description}</p>
    </div>
    
    <div class="client-info">
      <h2>${client?.clientName || "Unknown Application"} wants to access your account</h2>
      <p>Client ID: ${client?.clientId || "unknown"}</p>
    </div>
    
    <form method="post" action="/oauth/authorize">
      <input type="hidden" name="state" value="${stateEncoded}">
      
      <div class="actions">
        <button type="submit" name="action" value="approve" class="approve">
          Approve
        </button>
        <button type="submit" name="action" value="deny" class="deny">
          Deny
        </button>
      </div>
    </form>
  </div>
</body>
</html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html" },
  });
}

/**
 * Parses form submission from approval dialog.
 */
export async function parseRedirectApproval(
  request: Request,
  secret: string,
): Promise<{ state: any; headers: Record<string, string> }> {
  const formData = await request.formData();
  const action = formData.get("action");
  const stateEncoded = formData.get("state") as string;

  if (!stateEncoded) {
    throw new Error("Missing state parameter");
  }

  const state = JSON.parse(atob(stateEncoded));

  if (action !== "approve") {
    return { state, headers: {} };
  }

  // Set approval cookie
  const clientId = state.oauthReqInfo?.clientId;
  if (clientId) {
    const key = await importKey(secret);
    const approvedClients = [clientId];
    const data = btoa(JSON.stringify(approvedClients));
    const signature = await signData(key, data);
    const cookieValue = `${data}.${signature}`;

    return {
      state,
      headers: {
        "Set-Cookie": `${COOKIE_NAME}=${cookieValue}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${ONE_YEAR_IN_SECONDS}`,
      },
    };
  }

  return { state, headers: {} };
}

// Types for GitHub user info
export interface GitHubUser {
  id: number;
  login: string;
  name: string | null;
  email: string | null;
  avatar_url: string;
  html_url: string;
}

export interface GitHubEmail {
  email: string;
  primary: boolean;
  verified: boolean;
  visibility: string | null;
}

// Props that will be stored in the OAuth token
export interface Props {
  login: string;
  name: string;
  email: string;
  user_id: string;
}