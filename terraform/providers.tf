terraform {
  required_version = ">= 1.5"
  
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.6"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

provider "random" {}

provider "local" {}