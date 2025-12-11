#!/bin/bash

# Complete Deployment and Personalization Script for Colossus Card
# This script:
# 1. Builds the JavaCard applet
# 2. Deploys it to a physical JavaCard
# 3. Personalizes the card with Colossus configuration

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Parse command line arguments
JC_VERSION="${1:-3.0.5}"  # Default to 3.0.5

print_info "========================================"
print_info "Colossus Card Deployment Script"
print_info "========================================"
print_info "JavaCard Version: $JC_VERSION"
print_info "========================================"
echo ""

# Step 1: Build and Deploy
print_info "Step 1: Building applet..."
if ./gradlew deployPaymentApp -Pjc_version="$JC_VERSION"; then
    print_success "Applet deployed successfully"
else
    print_error "Deployment failed"
    exit 1
fi

echo ""
print_info "Waiting 2 seconds for card to be ready..."
sleep 2
echo ""

# Step 2: Personalize
print_info "Step 2: Personalizing card..."
if ./personalize-colossus-card.sh; then
    print_success "Card personalized successfully"
else
    print_error "Personalization failed"
    exit 1
fi

echo ""
print_success "========================================"
print_success "Deployment Complete!"
print_success "========================================"
print_info ""
print_info "Your Colossus payment card is ready!"
print_info ""
print_info "Next steps:"
print_info "  1. Test with an EMV terminal"
print_info "  2. Or use card reader tools to verify"
print_info "  3. Check COLOSSUS.md for more information"

