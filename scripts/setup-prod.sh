#!/bin/bash

# Setup script for production deployment
# This script validates production configuration

set -euo pipefail

echo "🚀 Validating production setup..."

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track validation status
VALIDATION_PASSED=true

# Check if .env exists
if [ ! -f ".env" ]; then
    echo -e "${RED}❌ .env file not found!${NC}"
    echo "   Copy .env.production to .env and fill in your credentials"
    VALIDATION_PASSED=false
else
    echo -e "${GREEN}✅ .env file found${NC}"
fi

# Source .env file if it exists
if [ -f ".env" ]; then
    set -a
    source .env
    set +a
fi

# Validate required environment variables
echo ""
echo "🔍 Validating required environment variables..."

check_var() {
    local var_name=$1
    local var_value=${!var_name:-}
    local is_secret=${2:-false}
    
    if [ -z "$var_value" ]; then
        echo -e "${RED}❌ $var_name is not set${NC}"
        VALIDATION_PASSED=false
    elif [[ "$var_value" == *"your-"* ]] || [[ "$var_value" == *"example"* ]]; then
        echo -e "${YELLOW}⚠️  $var_name appears to contain a placeholder value${NC}"
        VALIDATION_PASSED=false
    else
        if [ "$is_secret" = true ]; then
            echo -e "${GREEN}✅ $var_name is set (hidden)${NC}"
        else
            echo -e "${GREEN}✅ $var_name is set: $var_value${NC}"
        fi
    fi
}

# Check Cloudflare credentials
check_var "CLOUDFLARE_API_TOKEN" true
check_var "CLOUDFLARE_ACCOUNT_ID"
check_var "CLOUDFLARE_ZONE_ID"

# Check domain configuration
check_var "DOMAIN"
check_var "SUBDOMAIN"

# Check service naming
check_var "SERVICE_TYPE"
check_var "PROJECT_NAME"
check_var "ENVIRONMENT"

# Check GitHub OAuth
check_var "GITHUB_CLIENT_ID"
check_var "GITHUB_CLIENT_SECRET" true

# Check access control (at least one should be set)
echo ""
echo "🔐 Checking access control configuration..."
ACCESS_CONTROL_SET=false

if [ -n "${ALLOWED_GITHUB_USERS:-}" ]; then
    echo -e "${GREEN}✅ ALLOWED_GITHUB_USERS is configured${NC}"
    ACCESS_CONTROL_SET=true
fi

if [ -n "${ALLOWED_GITHUB_ORGS:-}" ]; then
    echo -e "${GREEN}✅ ALLOWED_GITHUB_ORGS is configured${NC}"
    ACCESS_CONTROL_SET=true
fi

if [ -n "${ALLOWED_GITHUB_TEAMS:-}" ]; then
    echo -e "${GREEN}✅ ALLOWED_GITHUB_TEAMS is configured${NC}"
    ACCESS_CONTROL_SET=true
fi

if [ -n "${ALLOWED_EMAIL_DOMAINS:-}" ]; then
    echo -e "${GREEN}✅ ALLOWED_EMAIL_DOMAINS is configured${NC}"
    ACCESS_CONTROL_SET=true
fi

if [ "$ACCESS_CONTROL_SET" = false ]; then
    echo -e "${RED}❌ No access control configured!${NC}"
    echo "   This means ANY GitHub user can authenticate."
    echo "   Configure at least one of: ALLOWED_GITHUB_USERS, ALLOWED_GITHUB_ORGS, ALLOWED_GITHUB_TEAMS, ALLOWED_EMAIL_DOMAINS"
    VALIDATION_PASSED=false
fi

# Check production-specific settings
echo ""
echo "🔧 Checking production settings..."

if [ "${ENVIRONMENT}" != "production" ]; then
    echo -e "${YELLOW}⚠️  ENVIRONMENT is not set to 'production'${NC}"
fi

if [ "${LOG_LEVEL:-info}" = "debug" ]; then
    echo -e "${YELLOW}⚠️  LOG_LEVEL is set to 'debug' - consider using 'info' or 'error' for production${NC}"
fi

# Summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$VALIDATION_PASSED" = true ]; then
    echo -e "${GREEN}✅ Production validation passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Review your configuration one more time"
    echo "2. Run 'make deploy' to deploy to production"
    echo "3. Test the OAuth flow with 'make test-oauth'"
    echo "4. Monitor logs with 'wrangler tail --env production'"
else
    echo -e "${RED}❌ Production validation failed!${NC}"
    echo ""
    echo "Please fix the issues above before deploying to production."
    exit 1
fi