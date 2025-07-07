# Create Cloudflare Tunnel
resource "cloudflare_zero_trust_tunnel_cloudflared" "mcp_tunnel" {
  account_id    = var.cloudflare_account_id
  name          = local.tunnel_name
  config_src    = "cloudflare"  # Managed via Cloudflare dashboard/API
  tunnel_secret = random_id.tunnel_secret.b64_std
}

# Configure the tunnel
resource "cloudflare_zero_trust_tunnel_cloudflared_config" "mcp_config" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.mcp_tunnel.id

  config = {
    ingress = [
      {
        hostname = "${cloudflare_zero_trust_tunnel_cloudflared.mcp_tunnel.id}.cfargotunnel.com"
        service  = var.mcp_server_url
        origin_request = {
          connect_timeout    = var.origin_request_config.connect_timeout
          tcp_keep_alive     = var.origin_request_config.tcp_keep_alive
          keep_alive_timeout = var.origin_request_config.keep_alive_timeout
        }
      },
      {
        # Catch-all rule (required)
        service = "http_status:404"
      }
    ]
  }
}

# Create credentials file for Docker
resource "local_file" "tunnel_credentials" {
  filename = "${path.module}/../docker/cloudflared/credentials.json"
  content = jsonencode({
    AccountTag   = var.cloudflare_account_id
    TunnelID     = cloudflare_zero_trust_tunnel_cloudflared.mcp_tunnel.id
    TunnelSecret = random_id.tunnel_secret.b64_std
  })
  file_permission = "0600"
}

# Create config file for Docker
resource "local_file" "tunnel_config" {
  filename = "${path.module}/../docker/cloudflared/config.yml"
  content = yamlencode({
    tunnel           = cloudflare_zero_trust_tunnel_cloudflared.mcp_tunnel.id
    credentials-file = "/etc/cloudflared/credentials.json"
    ingress = [
      {
        hostname = "${cloudflare_zero_trust_tunnel_cloudflared.mcp_tunnel.id}.cfargotunnel.com"
        service  = var.mcp_server_url
        originRequest = var.origin_request_config
      },
      {
        service = "http_status:404"
      }
    ]
  })
}