package handler

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// MockOAuthService is a mock implementation of OAuthService for testing
type MockOAuthService struct {
	ClientCredentialsGrantFunc func(clientID, clientSecret string, scopes []string) (*TokenResponse, error)
}

func (m *MockOAuthService) ClientCredentialsGrant(clientID, clientSecret string, scopes []string) (*TokenResponse, error) {
	if m.ClientCredentialsGrantFunc != nil {
		return m.ClientCredentialsGrantFunc(clientID, clientSecret, scopes)
	}
	return nil, nil
}

func TestTokenHandler_ClientCredentials_BasicAuth_Success(t *testing.T) {
	// Arrange
	mockService := &MockOAuthService{
		ClientCredentialsGrantFunc: func(clientID, clientSecret string, scopes []string) (*TokenResponse, error) {
			return &TokenResponse{
				AccessToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token",
				TokenType:   "Bearer",
				ExpiresIn:   900,
				Scope:       "read write",
			}, nil
		},
	}

	handler := NewTokenHandler(mockService)

	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("scope", "read write")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Basic Auth: client_id:client_secret
	auth := base64.StdEncoding.EncodeToString([]byte("test_client:test_secret"))
	req.Header.Set("Authorization", "Basic "+auth)

	w := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(w, req)

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("expected Content-Type to contain 'application/json', got '%s'", contentType)
	}

	body := w.Body.String()
	if !strings.Contains(body, "access_token") {
		t.Error("expected response to contain 'access_token'")
	}

	if !strings.Contains(body, "token_type") {
		t.Error("expected response to contain 'token_type'")
	}

	if !strings.Contains(body, "expires_in") {
		t.Error("expected response to contain 'expires_in'")
	}

	if !strings.Contains(body, "Bearer") {
		t.Error("expected token_type to be 'Bearer'")
	}
}

func TestTokenHandler_ClientCredentials_BodyAuth_Success(t *testing.T) {
	// Arrange - Client credentials in POST body
	mockService := &MockOAuthService{
		ClientCredentialsGrantFunc: func(clientID, clientSecret string, scopes []string) (*TokenResponse, error) {
			if clientID == "test_client" && clientSecret == "test_secret" {
				return &TokenResponse{
					AccessToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token",
					TokenType:   "Bearer",
					ExpiresIn:   900,
					Scope:       "read",
				}, nil
			}
			return nil, &OAuthError{ErrorCode: "invalid_client"}
		},
	}

	handler := NewTokenHandler(mockService)

	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_id", "test_client")
	formData.Set("client_secret", "test_secret")
	formData.Set("scope", "read")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(w, req)

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "access_token") {
		t.Error("expected response to contain 'access_token'")
	}
}

func TestTokenHandler_ClientCredentials_MissingGrantType(t *testing.T) {
	// Arrange
	mockService := &MockOAuthService{}
	handler := NewTokenHandler(mockService)

	formData := url.Values{}
	// Missing grant_type parameter

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(w, req)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "invalid_request") {
		t.Error("expected error 'invalid_request'")
	}
}

func TestTokenHandler_ClientCredentials_UnsupportedGrantType(t *testing.T) {
	// Arrange
	mockService := &MockOAuthService{}
	handler := NewTokenHandler(mockService)

	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(w, req)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "unsupported_grant_type") {
		t.Error("expected error 'unsupported_grant_type'")
	}
}

func TestTokenHandler_ClientCredentials_InvalidClient(t *testing.T) {
	// Arrange
	mockService := &MockOAuthService{
		ClientCredentialsGrantFunc: func(clientID, clientSecret string, scopes []string) (*TokenResponse, error) {
			return nil, &OAuthError{
				ErrorCode:        "invalid_client",
				ErrorDescription: "Client authentication failed",
			}
		},
	}

	handler := NewTokenHandler(mockService)

	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_id", "invalid_client")
	formData.Set("client_secret", "wrong_secret")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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

func TestTokenHandler_ClientCredentials_InvalidScope(t *testing.T) {
	// Arrange
	mockService := &MockOAuthService{
		ClientCredentialsGrantFunc: func(clientID, clientSecret string, scopes []string) (*TokenResponse, error) {
			return nil, &OAuthError{
				ErrorCode:        "invalid_scope",
				ErrorDescription: "Requested scope is invalid or exceeds allowed scopes",
			}
		},
	}

	handler := NewTokenHandler(mockService)

	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_id", "test_client")
	formData.Set("client_secret", "test_secret")
	formData.Set("scope", "admin superuser")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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

func TestTokenHandler_ClientCredentials_UnauthorizedClient(t *testing.T) {
	// Arrange
	mockService := &MockOAuthService{
		ClientCredentialsGrantFunc: func(clientID, clientSecret string, scopes []string) (*TokenResponse, error) {
			return nil, &OAuthError{
				ErrorCode:        "unauthorized_client",
				ErrorDescription: "Client is not authorized to use this grant type",
			}
		},
	}

	handler := NewTokenHandler(mockService)

	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_id", "public_client")
	formData.Set("client_secret", "secret")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(w, req)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "unauthorized_client") {
		t.Error("expected error 'unauthorized_client'")
	}
}

func TestTokenHandler_ClientCredentials_MethodNotAllowed(t *testing.T) {
	// Arrange - Only POST is allowed
	mockService := &MockOAuthService{}
	handler := NewTokenHandler(mockService)

	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	w := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(w, req)

	// Assert
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestTokenHandler_ClientCredentials_MissingClientCredentials(t *testing.T) {
	// Arrange - No Basic Auth and no client credentials in body
	mockService := &MockOAuthService{}
	handler := NewTokenHandler(mockService)

	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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

func TestTokenHandler_ClientCredentials_CacheControlHeader(t *testing.T) {
	// Arrange - Token responses should include Cache-Control: no-store
	mockService := &MockOAuthService{
		ClientCredentialsGrantFunc: func(clientID, clientSecret string, scopes []string) (*TokenResponse, error) {
			return &TokenResponse{
				AccessToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token",
				TokenType:   "Bearer",
				ExpiresIn:   900,
				Scope:       "read",
			}, nil
		},
	}

	handler := NewTokenHandler(mockService)

	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_id", "test_client")
	formData.Set("client_secret", "test_secret")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(w, req)

	// Assert
	cacheControl := w.Header().Get("Cache-Control")
	if !strings.Contains(cacheControl, "no-store") {
		t.Errorf("expected Cache-Control to contain 'no-store', got '%s'", cacheControl)
	}

	pragma := w.Header().Get("Pragma")
	if pragma != "no-cache" {
		t.Errorf("expected Pragma 'no-cache', got '%s'", pragma)
	}
}
