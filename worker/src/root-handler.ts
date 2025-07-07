import { Hono } from "hono";
import type { Env } from "./types";
import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { mcpProxyHandler } from "./mcp-proxy";

const app = new Hono<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>();

// Handle root SSE endpoint (Claude Desktop expects this)
app.get("/", async (c) => {
  console.log("🔍 ROOT-HANDLER DEBUG: Received request to /");
  
  // Check if user is authenticated
  const authHeader = c.req.header("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.log("🔍 ROOT-HANDLER DEBUG: No auth header, returning 401");
    return c.json({ error: "invalid_token", error_description: "Missing or invalid access token" }, 401, {
      "WWW-Authenticate": 'Bearer realm="OAuth", error="invalid_token", error_description="Missing or invalid access token"'
    });
  }
  
  const token = authHeader.substring(7);
  console.log("🔍 ROOT-HANDLER DEBUG: Validating token");
  
  // Validate token using OAuth provider
  try {
    const tokenInfo = await c.env.OAUTH_PROVIDER.validateAccessToken(token);
    console.log("🔍 ROOT-HANDLER DEBUG: Token valid, user:", tokenInfo);
    
    // Create context with user props
    const ctx = {
      props: tokenInfo.props || {}
    };
    
    // Proxy to MCP server
    return mcpProxyHandler(c.req.raw, c.env, ctx);
  } catch (error) {
    console.error("🔍 ROOT-HANDLER DEBUG: Token validation failed:", error);
    return c.json({ error: "invalid_token", error_description: "Invalid access token" }, 401, {
      "WWW-Authenticate": 'Bearer realm="OAuth", error="invalid_token", error_description="Invalid access token"'
    });
  }
});

// Handle POST to root (MCP JSON-RPC)
app.post("/", async (c) => {
  console.log("🔍 ROOT-HANDLER DEBUG: Received POST to /");
  
  // Same auth logic as GET
  const authHeader = c.req.header("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.log("🔍 ROOT-HANDLER DEBUG: No auth header, returning 401");
    return c.json({ error: "invalid_token", error_description: "Missing or invalid access token" }, 401, {
      "WWW-Authenticate": 'Bearer realm="OAuth", error="invalid_token", error_description="Missing or invalid access token"'
    });
  }
  
  const token = authHeader.substring(7);
  console.log("🔍 ROOT-HANDLER DEBUG: Validating token");
  
  try {
    const tokenInfo = await c.env.OAUTH_PROVIDER.validateAccessToken(token);
    console.log("🔍 ROOT-HANDLER DEBUG: Token valid, user:", tokenInfo);
    
    const ctx = {
      props: tokenInfo.props || {}
    };
    
    return mcpProxyHandler(c.req.raw, c.env, ctx);
  } catch (error) {
    console.error("🔍 ROOT-HANDLER DEBUG: Token validation failed:", error);
    return c.json({ error: "invalid_token", error_description: "Invalid access token" }, 401, {
      "WWW-Authenticate": 'Bearer realm="OAuth", error="invalid_token", error_description="Invalid access token"'
    });
  }
});

export { app as RootHandler };