output "tunnel_id" {
  description = "ID of the created Cloudflare Tunnel"
  value       = cloudflare_zero_trust_tunnel_cloudflared.mcp_tunnel.id
}

output "tunnel_name" {
  description = "Name of the created Cloudflare Tunnel"
  value       = cloudflare_zero_trust_tunnel_cloudflared.mcp_tunnel.name
}

output "tunnel_cname" {
  description = "CNAME value for the tunnel"
  value       = "${cloudflare_zero_trust_tunnel_cloudflared.mcp_tunnel.id}.cfargotunnel.com"
}

output "tunnel_secret" {
  description = "Base64-encoded tunnel secret for cloudflared"
  value       = random_id.tunnel_secret.b64_std
  sensitive   = true
}

output "oauth_url" {
  description = "OAuth authorization URL"
  value       = "https://${local.full_hostname}/oauth/authorize"
}

output "mcp_server_url" {
  description = "URL of the OAuth-protected MCP server"
  value       = "https://${local.full_hostname}"
}

output "oauth_metadata_url" {
  description = "OAuth metadata discovery URL"
  value       = "https://${local.full_hostname}/.well-known/oauth-authorization-server"
}

output "worker_name" {
  description = "Name of the deployed Worker"
  value       = cloudflare_workers_script.oauth_worker.script_name
}

output "github_oauth_setup" {
  description = "Instructions for GitHub OAuth App setup"
  value = <<-EOT
    GitHub OAuth App Configuration:
    
    1. Go to https://github.com/settings/developers
    2. Click "New OAuth App"
    3. Fill in:
       - Application name: ${local.base_name}
       - Homepage URL: https://${local.full_hostname}
       - Authorization callback URL: https://${local.full_hostname}/oauth/callback
    4. Save the Client ID and Client Secret
    5. Update terraform.tfvars with these values
  EOT
}

output "preconfigured_oauth_clients_json" {
  description = "JSON-encoded preconfigured OAuth clients"
  value       = jsonencode(var.preconfigured_oauth_clients)
  sensitive   = true
}

output "cookie_encryption_key" {
  description = "Cookie encryption key for the Worker"
  value       = random_password.cookie_key.result
  sensitive   = true
}

output "oauth_kv_namespace_id" {
  description = "ID of the OAuth KV namespace"
  value       = cloudflare_workers_kv_namespace.oauth_kv.id
}

output "session_kv_namespace_id" {
  description = "ID of the Session KV namespace"
  value       = cloudflare_workers_kv_namespace.session_kv.id
}

output "custom_domain_id" {
  description = "ID of the Worker custom domain"
  value       = cloudflare_workers_custom_domain.oauth_domain.id
}

output "dns_record_id" {
  description = "ID of the DNS record"
  value       = cloudflare_dns_record.oauth_dns.id
}