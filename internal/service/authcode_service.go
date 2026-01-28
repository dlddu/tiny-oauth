package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
)

// AuthCodeService handles authorization code operations
type AuthCodeService struct {
}

// NewAuthCodeService creates a new AuthCodeService instance
func NewAuthCodeService() *AuthCodeService {
	return &AuthCodeService{}
}

// GenerateAuthorizationCode generates an authorization code
func (s *AuthCodeService) GenerateAuthorizationCode(ctx context.Context, clientID, userID, redirectURI string, scopes []string) (string, error) {
	// Generate random code
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	code := base64.URLEncoding.EncodeToString(b)
	return code, nil
}
