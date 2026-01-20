#!/bin/bash
# Script to read and verify card data using GlobalPlatformPro

GP="java -jar gp.jar"

echo "=== Reading Card Data ==="
echo ""

# Select the Colossus application
echo "Selecting Colossus AID (A000000951)..."
$GP -a "00A4040005A000000951" 2>/dev/null | grep -i "response"

# Read SFI 3 Record 1 (CAPK index, Issuer exponent, 9F4A)
echo ""
echo "Reading SFI 3 Record 1 (CAPK index, Issuer exponent)..."
$GP -a "00B2011C00" 2>/dev/null | grep -i "response"

# Read SFI 3 Record 2 (Issuer certificate)
echo ""
echo "Reading SFI 3 Record 2 (Issuer Certificate 9F90)..."
$GP -a "00B2021C00" 2>/dev/null | grep -i "response"

# Read SFI 3 Record 4 (ICC certificate)
echo ""
echo "Reading SFI 3 Record 4 (ICC Certificate 9F46)..."
$GP -a "00B2041C00" 2>/dev/null | grep -i "response"

# Get GPO to see AIP and AFL
echo ""
echo "Getting Processing Options..."
$GP -a "80A8000002830000" 2>/dev/null | grep -i "response"

# Get ICC certificate tag directly
echo ""
echo "Getting ICC Certificate (9F46) via GET DATA..."
$GP -a "80CA9F4600" 2>/dev/null | grep -i "response"

echo ""
echo "=== Done ==="
