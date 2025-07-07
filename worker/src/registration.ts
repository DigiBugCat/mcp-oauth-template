import { Hono } from "hono";
import type { Env, MCPClient } from "./types";

const app = new Hono<{ Bindings: Env }>();

// Client registration request per RFC 7591
interface ClientRegistrationRequest {
  redirect_uris: string[];
  client_name: string;
  grant_types?: string[];
  response_types?: string[];
  scope?: string;
  token_endpoint_auth_method?: string;
}

// Client registration response
interface ClientRegistrationResponse {
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  client_name: string;
  grant_types: string[];
  response_types: string[];
  scope: string;
  token_endpoint_auth_method: string;
  client_id_issued_at: number;
  client_secret_expires_at: number; // 0 = no expiration
}

// POST /oauth/register - Dynamic client registration
app.post("/oauth/register", async (c) => {
  console.log("📝 CLIENT REGISTRATION: Received request");
  
  try {
    const body = await c.req.json<ClientRegistrationRequest>();
    console.log("📝 CLIENT REGISTRATION: Request body:", JSON.stringify(body));
    
    // Validate required fields
    if (!body.redirect_uris || body.redirect_uris.length === 0) {
      console.error("📝 CLIENT REGISTRATION: Missing redirect_uris");
      return c.json({ error: "invalid_request", error_description: "redirect_uris is required" }, 400, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      });
    }
    
    if (!body.client_name) {
      console.error("📝 CLIENT REGISTRATION: Missing client_name");
      return c.json({ error: "invalid_request", error_description: "client_name is required" }, 400, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      });
    }
    
    // Generate client credentials
    const clientId = `client_${generateRandomString(32)}`;
    const clientSecret = `secret_${generateRandomString(64)}`;
    
    // Create client object
    const client: MCPClient = {
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: body.redirect_uris,
      name: body.client_name,
      created_at: new Date().toISOString(),
    };
    
    // Store client in KV
    await c.env.OAUTH_KV.put(
      `client:${clientId}`,
      JSON.stringify(client),
      // No expiration for clients
    );
    
    console.log("📝 CLIENT REGISTRATION: Registered new client:", clientId);
    
    // Return registration response
    const response: ClientRegistrationResponse = {
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: body.redirect_uris,
      client_name: body.client_name,
      grant_types: body.grant_types || ["authorization_code", "refresh_token"],
      response_types: body.response_types || ["code"],
      scope: body.scope || "mcp",
      token_endpoint_auth_method: body.token_endpoint_auth_method || "client_secret_post",
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_secret_expires_at: 0, // No expiration
    };
    
    return c.json(response, 201, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
  } catch (error) {
    console.error("📝 CLIENT REGISTRATION: Error:", error);
    return c.json({ error: "server_error", error_description: "Failed to register client" }, 500, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
  }
});

// Helper function to generate random strings using Web Crypto API
function generateRandomString(length: number): string {
  const array = new Uint8Array(Math.ceil(length / 2));
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('').slice(0, length);
}

export { app as RegistrationHandler };