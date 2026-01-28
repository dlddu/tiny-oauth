package service

import (
	"context"
	"testing"
	"time"

	"github.com/dlddu/tiny-oauth/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

// MockClientRepository is a mock implementation of ClientRepository for testing
type MockClientRepository struct {
	GetByClientIDFunc func(ctx context.Context, clientID string) (*domain.Client, error)
}

func (m *MockClientRepository) GetByClientID(ctx context.Context, clientID string) (*domain.Client, error) {
	if m.GetByClientIDFunc != nil {
		return m.GetByClientIDFunc(ctx, clientID)
	}
	return nil, nil
}

// MockJWTService is a mock implementation of JWTService for testing
type MockJWTService struct {
	GenerateAccessTokenFunc func(clientID string, scopes []string, expiresAt time.Time) (string, error)
}

func (m *MockJWTService) GenerateAccessToken(clientID string, scopes []string, expiresAt time.Time) (string, error) {
	if m.GenerateAccessTokenFunc != nil {
		return m.GenerateAccessTokenFunc(clientID, scopes, expiresAt)
	}
	return "", nil
}

func TestOAuthService_ClientCredentialsGrant_Success(t *testing.T) {
	// Arrange
	ctx := context.Background()
	// Generate a real bcrypt hash for "valid_client_secret"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("valid_client_secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to generate bcrypt hash: %v", err)
	}

	mockClientRepo := &MockClientRepository{
		GetByClientIDFunc: func(ctx context.Context, clientID string) (*domain.Client, error) {
			if clientID == "valid_client_id" {
				return &domain.Client{
					ID:               "1",
					ClientID:         "valid_client_id",
					ClientSecretHash: string(hashedPassword),
					ClientName:       "Test Client",
					GrantTypes:       []string{"client_credentials"},
					Scopes:           []string{"read", "write"},
					IsConfidential:   true,
				}, nil
			}
			return nil, nil
		},
	}

	mockJWTService := &MockJWTService{
		GenerateAccessTokenFunc: func(clientID string, scopes []string, expiresAt time.Time) (string, error) {
			return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token", nil
		},
	}

	service := NewOAuthService(mockClientRepo, mockJWTService, 15*time.Minute)

	// Act
	response, err := service.ClientCredentialsGrant(ctx, "valid_client_id", "valid_client_secret", []string{"read"})

	// Assert
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if response == nil {
		t.Fatal("expected response, got nil")
	}

	if response.AccessToken == "" {
		t.Error("expected access_token, got empty string")
	}

	if response.TokenType != "Bearer" {
		t.Errorf("expected token_type 'Bearer', got '%s'", response.TokenType)
	}

	if response.ExpiresIn <= 0 {
		t.Errorf("expected positive expires_in, got %d", response.ExpiresIn)
	}

	if len(response.Scope) == 0 {
		t.Error("expected scopes, got empty")
	}
}

func TestOAuthService_ClientCredentialsGrant_InvalidClientID(t *testing.T) {
	// Arrange
	ctx := context.Background()
	mockClientRepo := &MockClientRepository{
		GetByClientIDFunc: func(ctx context.Context, clientID string) (*domain.Client, error) {
			return nil, nil // Client not found
		},
	}

	mockJWTService := &MockJWTService{}

	service := NewOAuthService(mockClientRepo, mockJWTService, 15*time.Minute)

	// Act
	response, err := service.ClientCredentialsGrant(ctx, "invalid_client_id", "some_secret", []string{"read"})

	// Assert
	if err == nil {
		t.Error("expected error for invalid client_id, got nil")
	}

	if response != nil {
		t.Errorf("expected nil response, got %v", response)
	}

	// Check error message contains "invalid_client"
	if err != nil && err.Error() != "invalid_client" {
		t.Errorf("expected error message 'invalid_client', got '%s'", err.Error())
	}
}

func TestOAuthService_ClientCredentialsGrant_InvalidClientSecret(t *testing.T) {
	// Arrange
	ctx := context.Background()
	// Generate a real bcrypt hash for "valid_client_secret"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("valid_client_secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to generate bcrypt hash: %v", err)
	}

	mockClientRepo := &MockClientRepository{
		GetByClientIDFunc: func(ctx context.Context, clientID string) (*domain.Client, error) {
			return &domain.Client{
				ID:               "1",
				ClientID:         "valid_client_id",
				ClientSecretHash: string(hashedPassword),
				ClientName:       "Test Client",
				GrantTypes:       []string{"client_credentials"},
				Scopes:           []string{"read", "write"},
				IsConfidential:   true,
			}, nil
		},
	}

	mockJWTService := &MockJWTService{}

	service := NewOAuthService(mockClientRepo, mockJWTService, 15*time.Minute)

	// Act
	response, err := service.ClientCredentialsGrant(ctx, "valid_client_id", "wrong_secret", []string{"read"})

	// Assert
	if err == nil {
		t.Error("expected error for invalid client_secret, got nil")
	}

	if response != nil {
		t.Errorf("expected nil response, got %v", response)
	}

	if err != nil && err.Error() != "invalid_client" {
		t.Errorf("expected error message 'invalid_client', got '%s'", err.Error())
	}
}

func TestOAuthService_ClientCredentialsGrant_UnsupportedGrantType(t *testing.T) {
	// Arrange
	ctx := context.Background()
	// Generate a real bcrypt hash for "valid_client_secret"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("valid_client_secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to generate bcrypt hash: %v", err)
	}

	mockClientRepo := &MockClientRepository{
		GetByClientIDFunc: func(ctx context.Context, clientID string) (*domain.Client, error) {
			return &domain.Client{
				ID:               "1",
				ClientID:         "valid_client_id",
				ClientSecretHash: string(hashedPassword),
				ClientName:       "Test Client",
				GrantTypes:       []string{"authorization_code"}, // Does not include client_credentials
				Scopes:           []string{"read", "write"},
				IsConfidential:   true,
			}, nil
		},
	}

	mockJWTService := &MockJWTService{}

	service := NewOAuthService(mockClientRepo, mockJWTService, 15*time.Minute)

	// Act
	response, err := service.ClientCredentialsGrant(ctx, "valid_client_id", "valid_client_secret", []string{"read"})

	// Assert
	if err == nil {
		t.Error("expected error for unsupported grant_type, got nil")
	}

	if response != nil {
		t.Errorf("expected nil response, got %v", response)
	}

	if err != nil && err.Error() != "unauthorized_client" {
		t.Errorf("expected error message 'unauthorized_client', got '%s'", err.Error())
	}
}

func TestOAuthService_ClientCredentialsGrant_InvalidScope(t *testing.T) {
	// Arrange
	ctx := context.Background()
	// Generate a real bcrypt hash for "valid_client_secret"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("valid_client_secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to generate bcrypt hash: %v", err)
	}

	mockClientRepo := &MockClientRepository{
		GetByClientIDFunc: func(ctx context.Context, clientID string) (*domain.Client, error) {
			return &domain.Client{
				ID:               "1",
				ClientID:         "valid_client_id",
				ClientSecretHash: string(hashedPassword),
				ClientName:       "Test Client",
				GrantTypes:       []string{"client_credentials"},
				Scopes:           []string{"read"}, // Only 'read' scope allowed
				IsConfidential:   true,
			}, nil
		},
	}

	mockJWTService := &MockJWTService{}

	service := NewOAuthService(mockClientRepo, mockJWTService, 15*time.Minute)

	// Act
	response, err := service.ClientCredentialsGrant(ctx, "valid_client_id", "valid_client_secret", []string{"write", "admin"})

	// Assert
	if err == nil {
		t.Error("expected error for invalid scope, got nil")
	}

	if response != nil {
		t.Errorf("expected nil response, got %v", response)
	}

	if err != nil && err.Error() != "invalid_scope" {
		t.Errorf("expected error message 'invalid_scope', got '%s'", err.Error())
	}
}

func TestOAuthService_ClientCredentialsGrant_EmptyScope(t *testing.T) {
	// Arrange - If no scope requested, should grant all available scopes
	ctx := context.Background()
	// Generate a real bcrypt hash for "valid_client_secret"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("valid_client_secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to generate bcrypt hash: %v", err)
	}

	mockClientRepo := &MockClientRepository{
		GetByClientIDFunc: func(ctx context.Context, clientID string) (*domain.Client, error) {
			return &domain.Client{
				ID:               "1",
				ClientID:         "valid_client_id",
				ClientSecretHash: string(hashedPassword),
				ClientName:       "Test Client",
				GrantTypes:       []string{"client_credentials"},
				Scopes:           []string{"read", "write"},
				IsConfidential:   true,
			}, nil
		},
	}

	mockJWTService := &MockJWTService{
		GenerateAccessTokenFunc: func(clientID string, scopes []string, expiresAt time.Time) (string, error) {
			return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token", nil
		},
	}

	service := NewOAuthService(mockClientRepo, mockJWTService, 15*time.Minute)

	// Act - Request with empty scope
	response, err := service.ClientCredentialsGrant(ctx, "valid_client_id", "valid_client_secret", []string{})

	// Assert
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if response == nil {
		t.Fatal("expected response, got nil")
	}

	// Should grant all available scopes
	if len(response.Scope) == 0 {
		t.Error("expected scopes to be granted, got empty")
	}
}

func TestOAuthService_ClientCredentialsGrant_PublicClient(t *testing.T) {
	// Arrange - Public clients should not be allowed for client_credentials
	ctx := context.Background()
	mockClientRepo := &MockClientRepository{
		GetByClientIDFunc: func(ctx context.Context, clientID string) (*domain.Client, error) {
			return &domain.Client{
				ID:               "1",
				ClientID:         "public_client_id",
				ClientSecretHash: "",
				ClientName:       "Public Client",
				GrantTypes:       []string{"client_credentials"},
				Scopes:           []string{"read"},
				IsConfidential:   false, // Public client
			}, nil
		},
	}

	mockJWTService := &MockJWTService{}

	service := NewOAuthService(mockClientRepo, mockJWTService, 15*time.Minute)

	// Act
	response, err := service.ClientCredentialsGrant(ctx, "public_client_id", "", []string{"read"})

	// Assert
	if err == nil {
		t.Error("expected error for public client, got nil")
	}

	if response != nil {
		t.Errorf("expected nil response, got %v", response)
	}

	if err != nil && err.Error() != "invalid_client" {
		t.Errorf("expected error message 'invalid_client', got '%s'", err.Error())
	}
}
