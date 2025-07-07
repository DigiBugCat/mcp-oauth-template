.PHONY: help deploy destroy logs status clean test-oauth setup-local setup-prod validate

SHELL := /bin/bash

# Default target
help:
	@echo "Available commands:"
	@echo "  make deploy      - Deploy the MCP OAuth server"
	@echo "  make destroy     - Destroy all resources"
	@echo "  make logs        - View Docker logs"
	@echo "  make status      - Check deployment status"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make test-oauth  - Test OAuth flow"
	@echo "  make setup-local - Setup local development environment"
	@echo "  make setup-prod  - Validate production configuration"

# Deploy the entire stack
deploy:
	@echo "🚀 Deploying MCP OAuth Server..."
	@chmod +x scripts/deploy.sh
	@./scripts/deploy.sh

# Destroy all resources
destroy:
	@echo "🗑️ Destroying deployment..."
	@chmod +x scripts/destroy.sh
	@./scripts/destroy.sh

# View logs
logs:
	@cd docker && docker-compose logs -f

# Check status
status:
	@echo "📊 Deployment Status:"
	@echo
	@echo "🐳 Docker Services:"
	@cd docker && docker-compose ps
	@echo
	@echo "☁️ Cloudflare Resources:"
	@cd terraform && terraform show -no-color | grep -E "(cloudflare_tunnel|cloudflare_record|cloudflare_worker)" || echo "No resources deployed"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf worker/dist
	@rm -rf worker/node_modules
	@rm -rf terraform/.terraform
	@rm -f terraform/terraform.tfstate*
	@rm -f terraform/terraform.tfvars
	@echo "✅ Clean complete"

# Test OAuth flow
test-oauth:
	@echo "🧪 Testing OAuth flow..."
	@if [ -f .env ]; then \
		source .env && \
		echo "OAuth Authorization URL:" && \
		echo "https://$$SUBDOMAIN.$$DOMAIN/oauth/authorize?client_id=test-client&redirect_uri=http://localhost:8080/callback&response_type=code&code_challenge=test&code_challenge_method=S256&scope=mcp"; \
	else \
		echo "❌ Error: .env file not found"; \
	fi

# Setup local development environment
setup-local:
	@echo "🔧 Setting up local development environment..."
	@chmod +x scripts/setup-local.sh
	@./scripts/setup-local.sh

# Validate production configuration
setup-prod validate:
	@echo "🚀 Validating production configuration..."
	@chmod +x scripts/setup-prod.sh
	@./scripts/setup-prod.sh