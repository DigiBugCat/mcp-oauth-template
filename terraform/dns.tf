# DNS record for the Worker (OAuth server)
resource "cloudflare_dns_record" "oauth_dns" {
  zone_id = var.cloudflare_zone_id
  name    = var.subdomain
  content = "192.0.2.1"  # Dummy IP - Worker will handle requests
  type    = "A"
  ttl     = 1  # Auto (proxied)
  proxied = true
  comment = "OAuth Worker endpoint for ${local.base_name}"
}