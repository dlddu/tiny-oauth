package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dlddu/tiny-oauth/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

// TokenResponse represents an OAuth 2.0 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// ClientRepository interface for client data access
type ClientRepository interface {
	GetByClientID(ctx context.Context, clientID string) (*domain.Client, error)
}

// JWTGenerator interface for JWT operations
type JWTGenerator interface {
	GenerateAccessToken(clientID string, scopes []string, expiresAt time.Time) (string, error)
}

// OAuthService handles OAuth 2.0 business logic
type OAuthService struct {
	clientRepo          ClientRepository
	jwtService          JWTGenerator
	accessTokenDuration time.Duration
}

// NewOAuthService creates a new OAuth service
func NewOAuthService(clientRepo ClientRepository, jwtService JWTGenerator, accessTokenDuration time.Duration) *OAuthService {
	return &OAuthService{
		clientRepo:          clientRepo,
		jwtService:          jwtService,
		accessTokenDuration: accessTokenDuration,
	}
}

// ClientCredentialsGrant implements the OAuth 2.0 client credentials grant type
func (s *OAuthService) ClientCredentialsGrant(ctx context.Context, clientID, clientSecret string, scopes []string) (*TokenResponse, error) {
	// 1. Validate client credentials
	client, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid_client")
	}
	if client == nil {
		return nil, fmt.Errorf("invalid_client")
	}

	// 2. Check if client is confidential (public clients not allowed for client_credentials)
	if !client.IsConfidential {
		return nil, fmt.Errorf("invalid_client")
	}

	// 3. Verify client secret
	err = bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(clientSecret))
	if err != nil {
		return nil, fmt.Errorf("invalid_client")
	}

	// 4. Check if client is authorized to use client_credentials grant type
	if !contains(client.GrantTypes, "client_credentials") {
		return nil, fmt.Errorf("unauthorized_client")
	}

	// 5. Validate requested scopes
	requestedScopes := scopes
	if len(requestedScopes) == 0 {
		// If no scopes requested, grant all available scopes
		requestedScopes = client.Scopes
	} else {
		// Check if all requested scopes are allowed for this client
		for _, scope := range requestedScopes {
			if !contains(client.Scopes, scope) {
				return nil, fmt.Errorf("invalid_scope")
			}
		}
	}

	// 6. Generate access token
	expiresAt := time.Now().Add(s.accessTokenDuration)
	accessToken, err := s.jwtService.GenerateAccessToken(clientID, requestedScopes, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("server_error: failed to generate token")
	}

	// 7. Build token response
	response := &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.accessTokenDuration.Seconds()),
		Scope:       strings.Join(requestedScopes, " "),
	}

	return response, nil
}

// contains checks if a slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
