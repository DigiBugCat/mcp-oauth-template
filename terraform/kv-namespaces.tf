# KV namespace for OAuth state and authorization codes
resource "cloudflare_workers_kv_namespace" "oauth_kv" {
  account_id = var.cloudflare_account_id
  title      = local.oauth_kv_name
}

# KV namespace for session storage
resource "cloudflare_workers_kv_namespace" "session_kv" {
  account_id = var.cloudflare_account_id
  title      = local.session_kv_name
}