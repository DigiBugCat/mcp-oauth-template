# Custom domain for the Worker
resource "cloudflare_workers_custom_domain" "oauth_domain" {
  account_id  = var.cloudflare_account_id
  zone_id     = var.cloudflare_zone_id
  hostname    = local.full_hostname
  service     = cloudflare_workers_script.oauth_worker.script_name
  environment = "production"
  
  depends_on = [
    cloudflare_workers_script.oauth_worker,
    cloudflare_dns_record.oauth_dns
  ]
}