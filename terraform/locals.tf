# Local values for computed resource names
locals {
  # Base name for all resources
  base_name = "${var.service_type}-${var.project_name}-${var.environment}"
  
  # Resource-specific names
  worker_name      = "${local.base_name}-worker"
  tunnel_name      = "${local.base_name}-tunnel"
  oauth_kv_name    = "${local.base_name}-oauth-kv"
  session_kv_name  = "${local.base_name}-session-kv"
  
  # Full hostname
  full_hostname = var.subdomain != "" ? "${var.subdomain}.${var.domain}" : var.domain
  
  # Worker file path
  worker_script_path = "${path.module}/../worker/dist/worker.js"
}