#!/bin/bash

# Setup script for local development
# This script helps set up a safe local development environment

set -euo pipefail

echo "🔧 Setting up local development environment..."

# Check if .env.local already exists
if [ -f ".env.local" ]; then
    echo "⚠️  .env.local already exists. Backing up to .env.local.backup"
    cp .env.local .env.local.backup
fi

# Copy the example file
if [ -f ".env.local.example" ]; then
    cp .env.local.example .env.local
    echo "✅ Created .env.local from .env.local.example"
else
    echo "❌ .env.local.example not found!"
    exit 1
fi

# Check if .env exists and is not a symlink
if [ -f ".env" ] && [ ! -L ".env" ]; then
    echo "⚠️  .env exists and is not a symlink. Please manually manage your .env file."
    echo "   Consider using: ln -sf .env.local .env"
else
    # Create symlink for local development
    ln -sf .env.local .env
    echo "✅ Created .env symlink pointing to .env.local"
fi

# Create terraform local vars file
if [ ! -f "terraform/terraform.local.tfvars" ]; then
    cat > terraform/terraform.local.tfvars << 'EOF'
# Local development Terraform variables
# This file is gitignored and safe for local credentials

# Add your local overrides here
# Example:
# domain = "dev.example.com"
# environment = "local"
EOF
    echo "✅ Created terraform/terraform.local.tfvars"
fi

# Create worker dev vars if needed
if [ ! -f "worker/.dev.vars" ]; then
    cat > worker/.dev.vars << 'EOF'
# Wrangler local development variables
# This file is gitignored and safe for local credentials

# Add your local worker variables here
# These override wrangler.toml vars during local development
EOF
    echo "✅ Created worker/.dev.vars"
fi

echo ""
echo "📝 Next steps:"
echo "1. Edit .env.local with your development credentials"
echo "2. Edit terraform/terraform.local.tfvars if needed"
echo "3. Edit worker/.dev.vars for worker-specific variables"
echo "4. Run 'make deploy' to deploy your local environment"
echo ""
echo "⚠️  Remember: Never commit .env.local, .env, or any file with real credentials!"