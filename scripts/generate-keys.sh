#!/bin/bash

# Generate RSA key pair for JWT signing

set -e

KEYS_DIR="keys"
KEY_SIZE=2048

echo "Generating RSA key pair..."

# Create keys directory
mkdir -p "$KEYS_DIR"

# Generate private key
openssl genrsa -out "$KEYS_DIR/private.pem" $KEY_SIZE

# Extract public key
openssl rsa -in "$KEYS_DIR/private.pem" -pubout -out "$KEYS_DIR/public.pem"

# Set permissions
chmod 600 "$KEYS_DIR/private.pem"
chmod 644 "$KEYS_DIR/public.pem"

echo "Keys generated successfully:"
echo "  Private key: $KEYS_DIR/private.pem"
echo "  Public key:  $KEYS_DIR/public.pem"
echo ""
echo "WARNING: Never commit these keys to version control!"
