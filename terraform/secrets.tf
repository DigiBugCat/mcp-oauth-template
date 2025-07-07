# Generate a random secret for the tunnel
resource "random_id" "tunnel_secret" {
  byte_length = 32
}

# Generate a random password for cookie encryption
resource "random_password" "cookie_key" {
  length  = 32
  special = true
}