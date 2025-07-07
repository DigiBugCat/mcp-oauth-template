variable "cloudflare_api_token" {
  description = "Cloudflare API token with permissions for Workers, KV, and DNS"
  type        = string
  sensitive   = true
}

variable "cloudflare_account_id" {
  description = "Cloudflare account ID"
  type        = string
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID for the domain"
  type        = string
}

variable "domain" {
  description = "Domain name (e.g., example.com)"
  type        = string
}

variable "subdomain" {
  description = "Subdomain for the OAuth server (e.g., mcp-oauth)"
  type        = string
}

variable "mcp_subdomain" {
  description = "Subdomain for the internal MCP server (e.g., mcp-internal)"
  type        = string
  default     = ""
}

variable "service_type" {
  description = "Type of service (e.g., mcp, api, web)"
  type        = string
  default     = "mcp"
}

variable "project_name" {
  description = "Project name (e.g., oauth-example, chatbot, analytics)"
  type        = string
}


variable "mcp_server_url" {
  description = "Internal URL of the MCP server (e.g., http://localhost:8080)"
  type        = string
  default     = "http://mcp-server:8080"
}

variable "github_client_id" {
  description = "GitHub OAuth App client ID"
  type        = string
  sensitive   = true
}

variable "github_client_secret" {
  description = "GitHub OAuth App client secret"
  type        = string
  sensitive   = true
}

variable "allowed_github_users" {
  description = "Comma-separated list of allowed GitHub usernames"
  type        = string
  default     = ""
}

variable "allowed_github_orgs" {
  description = "Comma-separated list of allowed GitHub organizations"
  type        = string
  default     = ""
}

variable "allowed_github_teams" {
  description = "Comma-separated list of allowed GitHub teams (format: org/team)"
  type        = string
  default     = ""
}

variable "allowed_email_domains" {
  description = "Comma-separated list of allowed email domains"
  type        = string
  default     = ""
}

variable "environment" {
  description = "Environment (development, staging, production)"
  type        = string
  default     = "production"
}

variable "origin_request_config" {
  description = "Advanced origin request configuration for the tunnel"
  type = object({
    connect_timeout    = number
    tcp_keep_alive     = number
    keep_alive_timeout = number
    no_tls_verify      = optional(bool)
  })
  default = {
    connect_timeout    = 30
    tcp_keep_alive     = 30
    keep_alive_timeout = 60
    no_tls_verify      = false
  }
}

variable "preconfigured_oauth_clients" {
  description = "Pre-configured OAuth clients for the server"
  type = list(object({
    client_id     = string
    client_secret = string
    redirect_uris = list(string)
    client_name   = string
  }))
  default = [
    {
      client_id     = "claude-desktop-client"
      client_secret = null
      redirect_uris = ["https://claude.ai/api/mcp/auth_callback"]
      client_name   = "Claude Desktop Example"
    },
    {
      client_id     = "test-client"
      client_secret = "test-secret"
      redirect_uris = ["http://localhost:8080/callback"]
      client_name   = "Test MCP Client"
    }
  ]
}