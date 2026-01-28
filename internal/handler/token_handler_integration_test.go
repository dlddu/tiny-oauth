package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dlddu/tiny-oauth/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

// Integration test with real service and JWT implementation
func TestTokenEndpoint_ClientCredentials_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Arrange - Setup real components
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Hash a test client secret
	secretHash, err := bcrypt.GenerateFromPassword([]byte("test_secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	// Mock repository with real client data
	mockClientRepo := &MockClientRepository{
		GetByClientIDFunc: func(ctx context.Context, clientID string) (*domain.Client, error) {
			if clientID == "test_client" {
				return &domain.Client{
					ID:               "1",
					ClientID:         "test_client",
					ClientSecretHash: string(secretHash),
					ClientName:       "Test Client",
					GrantTypes:       []string{"client_credentials"},
					Scopes:           []string{"read", "write", "admin"},
					IsConfidential:   true,
				}, nil
			}
			return nil, nil
		},
	}

	// Create real JWT service
	jwtService := NewJWTService(privateKey, &privateKey.PublicKey, "http://localhost:8080")

	// Create real OAuth service
	oauthService := NewOAuthService(mockClientRepo, jwtService, 15*time.Minute)

	// Create handler
	handler := NewTokenHandler(oauthService)

	// Prepare request
	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("scope", "read write")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Basic Auth
	auth := base64.StdEncoding.EncodeToString([]byte("test_client:test_secret"))
	req.Header.Set("Authorization", "Basic "+auth)

	w := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(w, req)

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
		t.Logf("Response body: %s", w.Body.String())
	}

	body := w.Body.String()
	if !strings.Contains(body, "access_token") {
		t.Error("expected access_token in response")
	}

	if !strings.Contains(body, "Bearer") {
		t.Error("expected token_type Bearer")
	}

	if !strings.Contains(body, "expires_in") {
		t.Error("expected expires_in in response")
	}

	// Verify Cache-Control headers
	cacheControl := w.Header().Get("Cache-Control")
	if !strings.Contains(cacheControl, "no-store") {
		t.Errorf("expected Cache-Control no-store, got '%s'", cacheControl)
	}
}

func TestTokenEndpoint_ClientCredentials_WrongPassword_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	secretHash, err := bcrypt.GenerateFromPassword([]byte("correct_secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	mockClientRepo := &MockClientRepository{
		GetByClientIDFunc: func(ctx context.Context, clientID string) (*domain.Client, error) {
			return &domain.Client{
				ID:               "1",
				ClientID:         "test_client",
				ClientSecretHash: string(secretHash),
				ClientName:       "Test Client",
				GrantTypes:       []string{"client_credentials"},
				Scopes:           []string{"read"},
				IsConfidential:   true,
			}, nil
		},
	}

	jwtService := NewJWTService(privateKey, &privateKey.PublicKey, "http://localhost:8080")
	oauthService := NewOAuthService(mockClientRepo, jwtService, 15*time.Minute)
	handler := NewTokenHandler(oauthService)

	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("scope", "read")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Wrong password
	auth := base64.StdEncoding.EncodeToString([]byte("test_client:wrong_secret"))
	req.Header.Set("Authorization", "Basic "+auth)

	w := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(w, req)

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "invalid_client") {
		t.Error("expected error 'invalid_client'")
	}
}

func TestTokenEndpoint_ClientCredentials_ExceedingScope_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	secretHash, err := bcrypt.GenerateFromPassword([]byte("test_secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	mockClientRepo := &MockClientRepository{
		GetByClientIDFunc: func(ctx context.Context, clientID string) (*domain.Client, error) {
			return &domain.Client{
				ID:               "1",
				ClientID:         "test_client",
				ClientSecretHash: string(secretHash),
				ClientName:       "Test Client",
				GrantTypes:       []string{"client_credentials"},
				Scopes:           []string{"read"}, // Only 'read' allowed
				IsConfidential:   true,
			}, nil
		},
	}

	jwtService := NewJWTService(privateKey, &privateKey.PublicKey, "http://localhost:8080")
	oauthService := NewOAuthService(mockClientRepo, jwtService, 15*time.Minute)
	handler := NewTokenHandler(oauthService)

	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("scope", "read write admin") // Requesting more than allowed

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	auth := base64.StdEncoding.EncodeToString([]byte("test_client:test_secret"))
	req.Header.Set("Authorization", "Basic "+auth)

	w := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(w, req)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "invalid_scope") {
		t.Error("expected error 'invalid_scope'")
	}
}

// MockClientRepository for integration tests
type MockClientRepository struct {
	GetByClientIDFunc func(ctx context.Context, clientID string) (*domain.Client, error)
}

func (m *MockClientRepository) GetByClientID(ctx context.Context, clientID string) (*domain.Client, error) {
	if m.GetByClientIDFunc != nil {
		return m.GetByClientIDFunc(ctx, clientID)
	}
	return nil, nil
}
