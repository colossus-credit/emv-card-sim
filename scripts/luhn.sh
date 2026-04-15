#!/bin/bash
# Luhn algorithm utilities for PAN validation and generation

# Validate a PAN using the Luhn algorithm
# Returns 0 if valid, 1 if invalid
luhn_validate() {
    local pan="$1"
    local sum=0
    local length=${#pan}
    local parity=$((length % 2))

    for ((i=0; i<length; i++)); do
        local digit=${pan:i:1}
        if (( i % 2 == parity )); then
            digit=$((digit * 2))
            if (( digit > 9 )); then
                digit=$((digit - 9))
            fi
        fi
        sum=$((sum + digit))
    done

    if (( sum % 10 == 0 )); then
        return 0
    else
        return 1
    fi
}

# Calculate the Luhn check digit for a partial PAN (without check digit)
luhn_checkdigit() {
    local partial="$1"
    local sum=0
    local length=${#partial}

    # For check digit calculation, we process from right to left
    # The check digit position (rightmost) is even, so we double odd positions from right
    for ((i=length-1; i>=0; i--)); do
        local digit=${partial:i:1}
        local pos=$((length - 1 - i))
        if (( pos % 2 == 0 )); then
            digit=$((digit * 2))
            if (( digit > 9 )); then
                digit=$((digit - 9))
            fi
        fi
        sum=$((sum + digit))
    done

    local check_digit=$(( (10 - (sum % 10)) % 10 ))
    echo "$check_digit"
}

# Generate a valid PAN from a BIN
# Usage: generate_pan <bin> [total_length]
# Default total length is 16
generate_pan() {
    local bin="$1"
    local total_length="${2:-16}"
    local bin_length=${#bin}
    local random_length=$((total_length - bin_length - 1))  # -1 for check digit

    if (( random_length < 0 )); then
        echo "ERROR: BIN is too long for the specified PAN length" >&2
        return 1
    fi

    # Generate random digits
    local random_part=""
    for ((i=0; i<random_length; i++)); do
        random_part+=$((RANDOM % 10))
    done

    local partial="${bin}${random_part}"
    local check_digit=$(luhn_checkdigit "$partial")
    local pan="${partial}${check_digit}"

    echo "$pan"
}

# Validate that BIN matches PAN
# Returns 0 if match, 1 if conflict
validate_bin_pan() {
    local bin="$1"
    local pan="$2"
    local bin_length=${#bin}

    if [[ "${pan:0:$bin_length}" != "$bin" ]]; then
        return 1
    fi
    return 0
}

# If script is run directly, provide CLI interface
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "$1" in
        validate)
            if luhn_validate "$2"; then
                echo "VALID"
                exit 0
            else
                echo "INVALID"
                exit 1
            fi
            ;;
        generate)
            generate_pan "$2" "$3"
            ;;
        checkdigit)
            luhn_checkdigit "$2"
            ;;
        *)
            echo "Usage: $0 {validate|generate|checkdigit} <pan|bin> [length]"
            echo ""
            echo "Commands:"
            echo "  validate <pan>           - Validate a PAN using Luhn algorithm"
            echo "  generate <bin> [length]  - Generate a valid PAN from BIN (default length: 16)"
            echo "  checkdigit <partial>     - Calculate check digit for partial PAN"
            exit 1
            ;;
    esac
fi
