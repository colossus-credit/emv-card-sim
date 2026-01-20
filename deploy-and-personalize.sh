#!/bin/bash

# Complete Deployment and Personalization Script for Colossus Card
# This script:
# 1. Builds the JavaCard applet
# 2. Deploys it to a physical JavaCard (with proper instance creation)
# 3. Personalizes the card with Colossus configuration (including PAN signing)

set -e  # Exit on error

# Configuration
COLOSSUS_PKG_AID="A00000095100"
COLOSSUS_APP_AID="A0000009510001"
PSE_PKG_AID="315041592E000000000000000000"
PSE_APP_AID="315041592E5359532E4444463031"

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

# Check if applet is installed on card
check_applet_installed() {
    local aid="$1"
    java -jar gp.jar -l 2>/dev/null | grep -q "APP: $aid"
}

# Check if package is loaded on card
check_package_loaded() {
    local pkg="$1"
    java -jar gp.jar -l 2>/dev/null | grep -q "PKG: $pkg"
}

# Parse command line arguments
JC_VERSION="${1:-3.0.5}"  # Default to 3.0.5

print_info "========================================"
print_info "Colossus Card Deployment Script"
print_info "========================================"
print_info "JavaCard Version: $JC_VERSION"
print_info "Package AID: $COLOSSUS_PKG_AID"
print_info "Applet AID:  $COLOSSUS_APP_AID"
print_info "========================================"
echo ""

# Step 0: Check for gp.jar
if [ ! -f "gp.jar" ]; then
    print_info "Downloading gp.jar..."
    ./gradlew downloadGp
fi

# Step 1: Build CAP files
print_info "Step 1: Building CAP files..."
if ./gradlew cap \
    -Pjc_version="$JC_VERSION" \
    -Ppaymentapp_cap_aid="$COLOSSUS_PKG_AID" \
    -Ppaymentapp_applet_aid="$COLOSSUS_APP_AID" \
    -x test -x checkstyleMain -x checkstyleTest; then
    print_success "CAP files built successfully"
else
    print_error "Build failed"
    exit 1
fi
echo ""

# Step 2: Delete old applets if they exist (to ensure clean install)
print_info "Step 2: Cleaning old applets..."
if check_applet_installed "$COLOSSUS_APP_AID"; then
    print_info "Deleting existing Colossus applet..."
    java -jar gp.jar --delete "$COLOSSUS_APP_AID" 2>/dev/null || true
fi
if check_package_loaded "$COLOSSUS_PKG_AID"; then
    print_info "Deleting existing Colossus package..."
    java -jar gp.jar --delete "$COLOSSUS_PKG_AID" 2>/dev/null || true
fi
print_success "Cleanup complete"
echo ""

# Step 3: Install Colossus CAP with explicit instance creation
print_info "Step 3: Installing Colossus applet..."
if java -jar gp.jar --install build/paymentapp.cap \
    --create "$COLOSSUS_APP_AID" \
    --package "$COLOSSUS_PKG_AID" \
    --applet "$COLOSSUS_APP_AID"; then
    print_success "Colossus CAP installed"
else
    print_error "Failed to install Colossus CAP"
    exit 1
fi

# Verify Colossus installation
if check_applet_installed "$COLOSSUS_APP_AID"; then
    print_success "Colossus applet verified: $COLOSSUS_APP_AID"
else
    print_error "Colossus applet NOT found after install!"
    print_info "Card contents:"
    java -jar gp.jar -l | grep -E "(APP|PKG):"
    exit 1
fi
echo ""

# Step 4: Verify PSE is installed (install if not)
print_info "Step 4: Checking PSE applet..."
if check_applet_installed "$PSE_APP_AID"; then
    print_success "PSE applet already installed"
else
    print_warning "PSE applet not found, installing..."
    if [ -f "build/pse.cap" ]; then
        java -jar gp.jar --install build/pse.cap \
            --create "$PSE_APP_AID" \
            --package "$PSE_PKG_AID" \
            --applet "$PSE_APP_AID" || true
        if check_applet_installed "$PSE_APP_AID"; then
            print_success "PSE applet installed"
        else
            print_warning "PSE installation may have failed - personalization will try to configure it"
        fi
    else
        print_warning "PSE CAP not found - run './gradlew cap' to build it"
    fi
fi
echo ""

print_info "Waiting 2 seconds for card to be ready..."
sleep 2
echo ""

# Step 5: Personalize (with PAN signing)
print_info "Step 5: Personalizing card..."
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

