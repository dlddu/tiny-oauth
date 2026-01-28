package service

import (
	"context"
	"time"

	"github.com/dlddu/tiny-oauth/internal/jwt"
)

// TokenService handles token generation operations
type TokenService struct {
	tokenManager *jwt.TokenManager
	ttl          time.Duration
}

// NewTokenService creates a new TokenService instance
func NewTokenService(tokenManager *jwt.TokenManager, ttl time.Duration) *TokenService {
	return &TokenService{
		tokenManager: tokenManager,
		ttl:          ttl,
	}
}

// GenerateAccessToken generates an access token for the given client and scopes
func (s *TokenService) GenerateAccessToken(ctx context.Context, clientID string, scopes []string) (string, time.Duration, error) {
	claims := jwt.TokenClaims{
		Subject:  clientID,
		ClientID: clientID,
		Scopes:   scopes,
		TTL:      s.ttl,
	}

	token, err := s.tokenManager.GenerateToken(claims)
	if err != nil {
		return "", 0, err
	}

	return token, s.ttl, nil
}
