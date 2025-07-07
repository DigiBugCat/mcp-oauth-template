#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo -e "${YELLOW}🗑️  Destroying MCP OAuth Server deployment...${NC}"

# Check if .env file exists
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    echo -e "${RED}❌ Error: .env file not found!${NC}"
    exit 1
fi

# Load environment variables
set -a
source "$PROJECT_ROOT/.env"
set +a

# Confirm destruction
echo -e "${RED}⚠️  WARNING: This will destroy all resources including:${NC}"
echo "  - Cloudflare Worker"
echo "  - KV namespaces (and all stored data)"
echo "  - Cloudflare Tunnel"
echo "  - DNS records"
echo "  - Docker containers"
echo
read -p "Are you sure you want to continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Destruction cancelled."
    exit 0
fi

# Step 1: Stop Docker services
echo -e "${YELLOW}🐳 Stopping Docker services...${NC}"
cd "$PROJECT_ROOT/docker"
docker-compose down -v || true

# Step 2: Destroy Terraform resources
echo -e "${YELLOW}🏗️  Destroying infrastructure...${NC}"
cd "$PROJECT_ROOT/terraform"

if [ -f "terraform.tfstate" ]; then
    # Ensure we have the latest state
    terraform refresh || true
    
    # Destroy all resources
    terraform destroy -auto-approve
    
    # Clean up Terraform files
    rm -f terraform.tfvars
    rm -f terraform.tfstate*
    rm -rf .terraform
else
    echo "No Terraform state found, skipping..."
fi

# Step 3: Clean up local files
echo -e "${YELLOW}🧹 Cleaning up local files...${NC}"
rm -rf "$PROJECT_ROOT/cloudflared"
rm -rf "$PROJECT_ROOT/docker/cloudflared"
rm -rf "$PROJECT_ROOT/worker/dist"
rm -rf "$PROJECT_ROOT/worker/node_modules"

echo -e "${GREEN}✅ Destruction complete!${NC}"
echo
echo -e "${YELLOW}Note:${NC} The following items were NOT deleted:"
echo "  - Your GitHub OAuth App (delete manually if needed)"
echo "  - The .env configuration file"
echo "  - The source code"