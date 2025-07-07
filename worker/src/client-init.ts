import type { Env } from "./types";

/**
 * Initialize pre-configured OAuth clients from environment configuration
 */
export async function initializeClients(env: Env) {
  console.log("🔍 CLIENT-INIT DEBUG: Starting client initialization");
  try {
    // Parse pre-configured clients from environment variable
    const preConfiguredClients = env.PRECONFIGURED_OAUTH_CLIENTS;
    if (!preConfiguredClients) {
      console.log("🔍 CLIENT-INIT DEBUG: No pre-configured OAuth clients found");
      return;
    }

    console.log("🔍 CLIENT-INIT DEBUG: Found pre-configured clients env var");
    const clients = JSON.parse(preConfiguredClients);
    console.log(`🔍 CLIENT-INIT DEBUG: Parsed ${clients.length} pre-configured clients`);
    
    for (const client of clients) {
      const clientKey = `client:${client.client_id}`;
      const existingClient = await env.OAUTH_KV.get(clientKey);
      
      if (!existingClient) {
        // Ensure client has all required fields for OAuth provider
        const completeClient = {
          ...client,
          grant_types: client.grant_types || ["authorization_code", "refresh_token"],
          response_types: client.response_types || ["code"],
          token_endpoint_auth_method: client.token_endpoint_auth_method || "none",
          client_id_issued_at: client.client_id_issued_at || Math.floor(Date.now() / 1000),
          registration_client_uri: client.registration_client_uri || `/oauth/register/${client.client_id}`,
          // Keep the client_secret as provided (empty string for public clients)
          client_secret: client.client_secret !== undefined ? client.client_secret : "",
        };
        
        await env.OAUTH_KV.put(clientKey, JSON.stringify(completeClient));
        console.log(`🔍 CLIENT-INIT DEBUG: Initialized client: ${client.client_name || client.client_id} (${client.client_id})`);
      } else {
        // Check if we need to update existing client with new format
        const existing = JSON.parse(existingClient);
        if (client.client_id === 'claude-desktop-client') {
          // Always update Claude Desktop to ensure it has the latest configuration
          console.log(`🔍 CLIENT-INIT DEBUG: Updating Claude Desktop client configuration`);
          const completeClient = {
            ...existing,
            ...client,
            client_secret: "",
            token_endpoint_auth_method: "none",
          };
          await env.OAUTH_KV.put(clientKey, JSON.stringify(completeClient));
          console.log(`🔍 CLIENT-INIT DEBUG: Claude Desktop client updated with empty secret`);
        } else {
          console.log(`🔍 CLIENT-INIT DEBUG: Client already exists: ${client.client_id}`);
        }
      }
    }
    console.log("🔍 CLIENT-INIT DEBUG: Client initialization complete");
  } catch (error) {
    console.error("🔍 CLIENT-INIT DEBUG: Error initializing clients:", error);
    console.error("🔍 CLIENT-INIT DEBUG: Error stack:", error.stack);
  }
}