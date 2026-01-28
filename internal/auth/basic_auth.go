package auth

import (
	"encoding/base64"
	"errors"
	"strings"
)

var (
	ErrEmptyHeader        = errors.New("authorization header is empty")
	ErrInvalidScheme      = errors.New("invalid authorization scheme, expected 'Basic'")
	ErrInvalidBase64      = errors.New("invalid base64 encoding")
	ErrInvalidCredentials = errors.New("invalid credentials format")
	ErrEmptyClientID      = errors.New("client_id cannot be empty")
)

// ParseBasicAuth parses a Basic Authentication header and returns client_id and client_secret
// The header format should be: "Basic base64(client_id:client_secret)"
func ParseBasicAuth(header string) (clientID, clientSecret string, err error) {
	if header == "" {
		return "", "", ErrEmptyHeader
	}

	// Check for "Basic " prefix (case-sensitive)
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", ErrInvalidScheme
	}

	// Extract base64-encoded credentials
	encoded := strings.TrimPrefix(header, prefix)
	encoded = strings.TrimSpace(encoded)

	if encoded == "" {
		return "", "", ErrInvalidBase64
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", ErrInvalidBase64
	}

	// Split by first colon only (secret can contain colons)
	credentials := string(decoded)
	colonIndex := strings.Index(credentials, ":")
	if colonIndex == -1 {
		return "", "", ErrInvalidCredentials
	}

	clientID = credentials[:colonIndex]
	clientSecret = credentials[colonIndex+1:]

	// Validate client_id is not empty
	if clientID == "" {
		return "", "", ErrEmptyClientID
	}

	return clientID, clientSecret, nil
}
