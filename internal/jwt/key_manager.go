package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// GenerateKeyPair generates an RSA key pair with the specified bit size
func GenerateKeyPair(bitSize int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// Validate bit size (minimum 1024 for RSA)
	if bitSize < 1024 {
		return nil, nil, errors.New("bit size must be at least 1024")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return privateKey, &privateKey.PublicKey, nil
}

// SaveKeyPair saves the RSA key pair to files
func SaveKeyPair(privateKey *rsa.PrivateKey, privateKeyPath, publicKeyPath string) error {
	// Save private key
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	}

	privFile, err := os.OpenFile(privateKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privFile.Close()

	if err := pem.Encode(privFile, privPEM); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	// Save public key
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	pubFile, err := os.OpenFile(publicKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer pubFile.Close()

	if err := pem.Encode(pubFile, pubPEM); err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	return nil
}

// LoadPrivateKeyFromFile loads an RSA private key from a file
func LoadPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, errors.New("file does not exist")
	}

	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	return parsePrivateKey(keyData)
}

// LoadPublicKeyFromFile loads an RSA public key from a file
func LoadPublicKeyFromFile(path string) (*rsa.PublicKey, error) {
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, errors.New("file does not exist")
	}

	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	return parsePublicKey(keyData)
}

// LoadPrivateKeyFromEnv loads an RSA private key from an environment variable
func LoadPrivateKeyFromEnv(varName string) (*rsa.PrivateKey, error) {
	keyData := os.Getenv(varName)
	if keyData == "" {
		return nil, fmt.Errorf("environment variable %s is not set", varName)
	}

	return parsePrivateKey([]byte(keyData))
}

// LoadPublicKeyFromEnv loads an RSA public key from an environment variable
func LoadPublicKeyFromEnv(varName string) (*rsa.PublicKey, error) {
	keyData := os.Getenv(varName)
	if keyData == "" {
		return nil, fmt.Errorf("environment variable %s is not set", varName)
	}

	return parsePublicKey([]byte(keyData))
}

// parsePrivateKey parses an RSA private key from PEM-encoded data
func parsePrivateKey(keyData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("invalid PEM format")
	}

	if block.Type != "RSA PRIVATE KEY" && block.Type != "PRIVATE KEY" {
		return nil, errors.New("wrong key type")
	}

	// Try PKCS1 first
	if block.Type == "RSA PRIVATE KEY" {
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		return privateKey, nil
	}

	// Try PKCS8
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	return privateKey, nil
}

// parsePublicKey parses an RSA public key from PEM-encoded data
func parsePublicKey(keyData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("invalid PEM format")
	}

	if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" {
		return nil, errors.New("wrong key type")
	}

	// Try PKIX first (most common)
	if block.Type == "PUBLIC KEY" {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}

		publicKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("not an RSA public key")
		}
		return publicKey, nil
	}

	// Try PKCS1
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return publicKey, nil
}
