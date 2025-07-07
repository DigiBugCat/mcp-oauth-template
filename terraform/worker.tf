# Deploy the Worker with modern bindings syntax
resource "cloudflare_workers_script" "oauth_worker" {
  account_id         = var.cloudflare_account_id
  script_name        = local.worker_name
  content            = file(local.worker_script_path)
  main_module        = "worker.js"
  compatibility_date = "2024-01-01"
  
  # Enable Node.js compatibility for crypto and other Node APIs
  compatibility_flags = ["nodejs_compat"]

  # All bindings use the new array syntax
  bindings = [
    # KV namespace bindings
    {
      name         = "OAUTH_KV"
      type         = "kv_namespace"
      namespace_id = cloudflare_workers_kv_namespace.oauth_kv.id
    },
    {
      name         = "SESSION_KV"
      type         = "kv_namespace"
      namespace_id = cloudflare_workers_kv_namespace.session_kv.id
    },
    
    # Secret bindings
    {
      name = "GITHUB_CLIENT_SECRET"
      type = "secret_text"
      text = var.github_client_secret
    },
    {
      name = "COOKIE_ENCRYPTION_KEY"
      type = "secret_text"
      text = random_password.cookie_key.result
    },
    
    # Plain text environment variables
    {
      name = "GITHUB_CLIENT_ID"
      type = "plain_text"
      text = var.github_client_id
    },
    {
      name = "PUBLIC_URL"
      type = "plain_text"
      text = "https://${local.full_hostname}"
    },
    {
      name = "MCP_SERVER_URL"
      type = "plain_text"
      text = "https://${cloudflare_zero_trust_tunnel_cloudflared.mcp_tunnel.id}.cfargotunnel.com"
    },
    {
      name = "ENVIRONMENT"
      type = "plain_text"
      text = var.environment
    },
    {
      name = "ALLOWED_GITHUB_USERS"
      type = "plain_text"
      text = var.allowed_github_users
    },
    {
      name = "ALLOWED_GITHUB_ORGS"
      type = "plain_text"
      text = var.allowed_github_orgs
    },
    {
      name = "ALLOWED_GITHUB_TEAMS"
      type = "plain_text"
      text = var.allowed_github_teams
    },
    {
      name = "ALLOWED_EMAIL_DOMAINS"
      type = "plain_text"
      text = var.allowed_email_domains
    },
    {
      name = "PRECONFIGURED_OAUTH_CLIENTS"
      type = "plain_text"
      text = jsonencode(var.preconfigured_oauth_clients)
    }
  ]

  # Observability settings
  observability = {
    enabled = true
    logs = {
      enabled         = true
      invocation_logs = true
    }
  }

  # Ensure Worker is deployed after DNS record
  depends_on = [
    cloudflare_dns_record.oauth_dns,
    cloudflare_workers_kv_namespace.oauth_kv,
    cloudflare_workers_kv_namespace.session_kv
  ]
}