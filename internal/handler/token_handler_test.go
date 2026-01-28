package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dlddu/tiny-oauth/internal/domain"
)

// MockClientService is a mock for client authentication operations
type MockClientService struct {
	client *domain.Client
	err    error
}

func (m *MockClientService) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (*domain.Client, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.client, nil
}

func (m *MockClientService) GetClientByID(ctx context.Context, clientID string) (*domain.Client, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.client, nil
}

// MockTokenService is a mock for token generation operations
type MockTokenService struct {
	token string
	err   error
}

func (m *MockTokenService) GenerateAccessToken(ctx context.Context, clientID string, scopes []string) (string, time.Duration, error) {
	if m.err != nil {
		return "", 0, m.err
	}
	return m.token, 15 * time.Minute, nil
}

func TestTokenHandler_ClientCredentialsGrant_BasicAuth(t *testing.T) {
	tests := []struct {
		name               string
		authHeader         string
		formData           url.Values
		setupMocks         func(*MockClientService, *MockTokenService)
		wantStatus         int
		wantAccessToken    bool
		wantError          string
		wantErrorDesc      string
	}{
		{
			name:       "should issue token with valid Basic Auth credentials",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("test-client:test-secret")),
			formData: url.Values{
				"grant_type": {"client_credentials"},
			},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {
				cs.client = &domain.Client{
					ID:               "id-123",
					ClientID:         "test-client",
					ClientSecretHash: "$2a$10$test-hash",
					ClientName:       "Test Client",
					GrantTypes:       []string{"client_credentials"},
					Scopes:           []string{"read", "write"},
					IsConfidential:   true,
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
				ts.token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token"
			},
			wantStatus:      http.StatusOK,
			wantAccessToken: true,
		},
		{
			name:       "should issue token with requested scope",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("test-client:test-secret")),
			formData: url.Values{
				"grant_type": {"client_credentials"},
				"scope":      {"read"},
			},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {
				cs.client = &domain.Client{
					ID:               "id-123",
					ClientID:         "test-client",
					ClientSecretHash: "$2a$10$test-hash",
					ClientName:       "Test Client",
					GrantTypes:       []string{"client_credentials"},
					Scopes:           []string{"read", "write"},
					IsConfidential:   true,
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
				ts.token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token"
			},
			wantStatus:      http.StatusOK,
			wantAccessToken: true,
		},
		{
			name:       "should issue token with multiple scopes",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("test-client:test-secret")),
			formData: url.Values{
				"grant_type": {"client_credentials"},
				"scope":      {"read write"},
			},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {
				cs.client = &domain.Client{
					ID:               "id-123",
					ClientID:         "test-client",
					ClientSecretHash: "$2a$10$test-hash",
					ClientName:       "Test Client",
					GrantTypes:       []string{"client_credentials"},
					Scopes:           []string{"read", "write"},
					IsConfidential:   true,
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
				ts.token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token"
			},
			wantStatus:      http.StatusOK,
			wantAccessToken: true,
		},
		{
			name:       "should fail with invalid client_id",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("invalid-client:test-secret")),
			formData: url.Values{
				"grant_type": {"client_credentials"},
			},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {
				cs.err = errors.New("invalid client credentials")
			},
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_client",
			wantErrorDesc: "Client authentication failed",
		},
		{
			name:       "should fail with invalid client_secret",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("test-client:wrong-secret")),
			formData: url.Values{
				"grant_type": {"client_credentials"},
			},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {
				cs.err = errors.New("invalid client credentials")
			},
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_client",
			wantErrorDesc: "Client authentication failed",
		},
		{
			name:       "should fail with missing grant_type",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("test-client:test-secret")),
			formData:   url.Values{},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {
				cs.client = &domain.Client{
					ID:               "id-123",
					ClientID:         "test-client",
					ClientSecretHash: "$2a$10$test-hash",
					ClientName:       "Test Client",
					GrantTypes:       []string{"client_credentials"},
					Scopes:           []string{"read"},
					IsConfidential:   true,
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
			},
			wantStatus:    http.StatusBadRequest,
			wantError:     "invalid_request",
			wantErrorDesc: "grant_type parameter is required",
		},
		{
			name:       "should fail with unsupported grant_type",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("test-client:test-secret")),
			formData: url.Values{
				"grant_type": {"authorization_code"},
			},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {
				cs.client = &domain.Client{
					ID:               "id-123",
					ClientID:         "test-client",
					ClientSecretHash: "$2a$10$test-hash",
					ClientName:       "Test Client",
					GrantTypes:       []string{"client_credentials"},
					Scopes:           []string{"read"},
					IsConfidential:   true,
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
			},
			wantStatus:    http.StatusBadRequest,
			wantError:     "unsupported_grant_type",
			wantErrorDesc: "grant_type must be client_credentials",
		},
		{
			name:       "should fail when client does not support client_credentials grant",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("test-client:test-secret")),
			formData: url.Values{
				"grant_type": {"client_credentials"},
			},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {
				cs.client = &domain.Client{
					ID:               "id-123",
					ClientID:         "test-client",
					ClientSecretHash: "$2a$10$test-hash",
					ClientName:       "Test Client",
					GrantTypes:       []string{"authorization_code"},
					Scopes:           []string{"read"},
					IsConfidential:   true,
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
			},
			wantStatus:    http.StatusBadRequest,
			wantError:     "unauthorized_client",
			wantErrorDesc: "Client is not authorized to use this grant type",
		},
		{
			name:       "should fail with missing Authorization header",
			authHeader: "",
			formData: url.Values{
				"grant_type": {"client_credentials"},
			},
			setupMocks:    func(cs *MockClientService, ts *MockTokenService) {},
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_client",
			wantErrorDesc: "Client authentication failed",
		},
		{
			name:       "should fail with malformed Authorization header",
			authHeader: "Bearer some-token",
			formData: url.Values{
				"grant_type": {"client_credentials"},
			},
			setupMocks:    func(cs *MockClientService, ts *MockTokenService) {},
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_client",
			wantErrorDesc: "Client authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			clientService := &MockClientService{}
			tokenService := &MockTokenService{}
			if tt.setupMocks != nil {
				tt.setupMocks(clientService, tokenService)
			}

			// Create handler
			handler := NewTokenHandler(clientService, tokenService)

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tt.formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			// Check response body
			if tt.wantAccessToken {
				var tokenResp TokenResponse
				if err := json.NewDecoder(rr.Body).Decode(&tokenResp); err != nil {
					t.Errorf("failed to decode token response: %v", err)
					return
				}

				if tokenResp.AccessToken == "" {
					t.Error("access_token is empty")
				}

				if tokenResp.TokenType != "Bearer" {
					t.Errorf("expected token_type 'Bearer', got %s", tokenResp.TokenType)
				}

				if tokenResp.ExpiresIn <= 0 {
					t.Errorf("expected positive expires_in, got %d", tokenResp.ExpiresIn)
				}
			} else if tt.wantError != "" {
				var errResp ErrorResponse
				if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
					t.Errorf("failed to decode error response: %v", err)
					return
				}

				if errResp.Error != tt.wantError {
					t.Errorf("expected error %s, got %s", tt.wantError, errResp.Error)
				}

				if tt.wantErrorDesc != "" && errResp.ErrorDescription != tt.wantErrorDesc {
					t.Errorf("expected error_description %s, got %s", tt.wantErrorDesc, errResp.ErrorDescription)
				}
			}

			// Verify Content-Type header
			contentType := rr.Header().Get("Content-Type")
			if !strings.Contains(contentType, "application/json") {
				t.Errorf("expected Content-Type to contain 'application/json', got %s", contentType)
			}
		})
	}
}

func TestTokenHandler_ClientCredentialsGrant_PostBody(t *testing.T) {
	tests := []struct {
		name            string
		formData        url.Values
		setupMocks      func(*MockClientService, *MockTokenService)
		wantStatus      int
		wantAccessToken bool
		wantError       string
	}{
		{
			name: "should issue token with client credentials in POST body",
			formData: url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {"test-client"},
				"client_secret": {"test-secret"},
			},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {
				cs.client = &domain.Client{
					ID:               "id-123",
					ClientID:         "test-client",
					ClientSecretHash: "$2a$10$test-hash",
					ClientName:       "Test Client",
					GrantTypes:       []string{"client_credentials"},
					Scopes:           []string{"read"},
					IsConfidential:   true,
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
				ts.token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token"
			},
			wantStatus:      http.StatusOK,
			wantAccessToken: true,
		},
		{
			name: "should issue token with scope in POST body",
			formData: url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {"test-client"},
				"client_secret": {"test-secret"},
				"scope":         {"read write"},
			},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {
				cs.client = &domain.Client{
					ID:               "id-123",
					ClientID:         "test-client",
					ClientSecretHash: "$2a$10$test-hash",
					ClientName:       "Test Client",
					GrantTypes:       []string{"client_credentials"},
					Scopes:           []string{"read", "write"},
					IsConfidential:   true,
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
				ts.token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token"
			},
			wantStatus:      http.StatusOK,
			wantAccessToken: true,
		},
		{
			name: "should fail with invalid client_id in POST body",
			formData: url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {"invalid-client"},
				"client_secret": {"test-secret"},
			},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {
				cs.err = errors.New("invalid client credentials")
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_client",
		},
		{
			name: "should fail with invalid client_secret in POST body",
			formData: url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {"test-client"},
				"client_secret": {"wrong-secret"},
			},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {
				cs.err = errors.New("invalid client credentials")
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_client",
		},
		{
			name: "should fail with missing client_id in POST body",
			formData: url.Values{
				"grant_type":    {"client_credentials"},
				"client_secret": {"test-secret"},
			},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_client",
		},
		{
			name: "should fail with missing client_secret in POST body",
			formData: url.Values{
				"grant_type": {"client_credentials"},
				"client_id":  {"test-client"},
			},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			clientService := &MockClientService{}
			tokenService := &MockTokenService{}
			if tt.setupMocks != nil {
				tt.setupMocks(clientService, tokenService)
			}

			// Create handler
			handler := NewTokenHandler(clientService, tokenService)

			// Create request without Authorization header
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tt.formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			// Create response recorder
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			// Check response
			if tt.wantAccessToken {
				var tokenResp TokenResponse
				if err := json.NewDecoder(rr.Body).Decode(&tokenResp); err != nil {
					t.Errorf("failed to decode token response: %v", err)
					return
				}

				if tokenResp.AccessToken == "" {
					t.Error("access_token is empty")
				}

				if tokenResp.TokenType != "Bearer" {
					t.Errorf("expected token_type 'Bearer', got %s", tokenResp.TokenType)
				}
			} else if tt.wantError != "" {
				var errResp ErrorResponse
				if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
					t.Errorf("failed to decode error response: %v", err)
					return
				}

				if errResp.Error != tt.wantError {
					t.Errorf("expected error %s, got %s", tt.wantError, errResp.Error)
				}
			}
		})
	}
}

func TestTokenHandler_MethodNotAllowed(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		wantStatus int
	}{
		{
			name:       "should reject GET requests",
			method:     http.MethodGet,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "should reject PUT requests",
			method:     http.MethodPut,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "should reject DELETE requests",
			method:     http.MethodDelete,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "should accept POST requests",
			method:     http.MethodPost,
			wantStatus: http.StatusBadRequest, // Will fail due to missing grant_type, but method is accepted
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientService := &MockClientService{}
			tokenService := &MockTokenService{}
			handler := NewTokenHandler(clientService, tokenService)

			req := httptest.NewRequest(tt.method, "/oauth/token", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestTokenHandler_ContentTypeValidation(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		wantStatus  int
	}{
		{
			name:        "should accept application/x-www-form-urlencoded",
			contentType: "application/x-www-form-urlencoded",
			wantStatus:  http.StatusBadRequest, // Will fail due to missing grant_type
		},
		{
			name:        "should accept application/x-www-form-urlencoded with charset",
			contentType: "application/x-www-form-urlencoded; charset=utf-8",
			wantStatus:  http.StatusBadRequest, // Will fail due to missing grant_type
		},
		{
			name:        "should reject application/json",
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "should reject text/plain",
			contentType: "text/plain",
			wantStatus:  http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientService := &MockClientService{}
			tokenService := &MockTokenService{}
			handler := NewTokenHandler(clientService, tokenService)

			req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
			req.Header.Set("Content-Type", tt.contentType)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestTokenHandler_ScopeValidation(t *testing.T) {
	tests := []struct {
		name          string
		requestedScope string
		allowedScopes  []string
		setupMocks     func(*MockClientService, *MockTokenService)
		wantStatus     int
		wantError      string
	}{
		{
			name:          "should accept requested scope within allowed scopes",
			requestedScope: "read",
			allowedScopes:  []string{"read", "write"},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					GrantTypes: []string{"client_credentials"},
					Scopes:     []string{"read", "write"},
				}
				ts.token = "test.token"
			},
			wantStatus: http.StatusOK,
		},
		{
			name:          "should fail with scope not allowed for client",
			requestedScope: "admin",
			allowedScopes:  []string{"read"},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					GrantTypes: []string{"client_credentials"},
					Scopes:     []string{"read"},
				}
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_scope",
		},
		{
			name:          "should use default scopes when no scope requested",
			requestedScope: "",
			allowedScopes:  []string{"read", "write"},
			setupMocks: func(cs *MockClientService, ts *MockTokenService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					GrantTypes: []string{"client_credentials"},
					Scopes:     []string{"read", "write"},
				}
				ts.token = "test.token"
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientService := &MockClientService{}
			tokenService := &MockTokenService{}
			if tt.setupMocks != nil {
				tt.setupMocks(clientService, tokenService)
			}

			handler := NewTokenHandler(clientService, tokenService)

			formData := url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {"test-client"},
				"client_secret": {"test-secret"},
			}
			if tt.requestedScope != "" {
				formData.Set("scope", tt.requestedScope)
			}

			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			if tt.wantError != "" {
				var errResp ErrorResponse
				if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
					t.Errorf("failed to decode error response: %v", err)
					return
				}

				if errResp.Error != tt.wantError {
					t.Errorf("expected error %s, got %s", tt.wantError, errResp.Error)
				}
			}
		})
	}
}

func TestTokenHandler_CacheControlHeaders(t *testing.T) {
	clientService := &MockClientService{
		client: &domain.Client{
			ClientID:   "test-client",
			GrantTypes: []string{"client_credentials"},
			Scopes:     []string{"read"},
		},
	}
	tokenService := &MockTokenService{
		token: "test.token",
	}

	handler := NewTokenHandler(clientService, tokenService)

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	t.Run("should set Cache-Control to no-store", func(t *testing.T) {
		cacheControl := rr.Header().Get("Cache-Control")
		if !strings.Contains(cacheControl, "no-store") {
			t.Errorf("expected Cache-Control to contain 'no-store', got %s", cacheControl)
		}
	})

	t.Run("should set Pragma to no-cache", func(t *testing.T) {
		pragma := rr.Header().Get("Pragma")
		if pragma != "no-cache" {
			t.Errorf("expected Pragma 'no-cache', got %s", pragma)
		}
	})
}
