package handler

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/dlddu/tiny-oauth/internal/domain"
	"github.com/dlddu/tiny-oauth/internal/service"
)

// TokenResponse represents an OAuth 2.0 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// OAuthError represents an OAuth 2.0 error response
type OAuthError struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// Error implements the error interface
func (e *OAuthError) Error() string {
	return e.ErrorCode
}

// OAuthService interface for OAuth operations (without context for simpler mocking)
type OAuthService interface {
	ClientCredentialsGrant(clientID, clientSecret string, scopes []string) (*TokenResponse, error)
}

// ClientRepository interface for integration tests
type ClientRepository interface {
	GetByClientID(ctx context.Context, clientID string) (*domain.Client, error)
}

// Integration test constructors - wrappers for service package
func NewJWTService(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, issuer string) *service.JWTService {
	return service.NewJWTService(privateKey, publicKey, issuer)
}

func NewOAuthService(clientRepo ClientRepository, jwtService *service.JWTService, duration time.Duration) OAuthService {
	// Create an adapter to wrap the service with context handling
	return &oauthServiceAdapter{
		service: service.NewOAuthService(clientRepo, jwtService, duration),
	}
}

// oauthServiceAdapter adapts the service.OAuthService to the handler interface
type oauthServiceAdapter struct {
	service *service.OAuthService
}

func (a *oauthServiceAdapter) ClientCredentialsGrant(clientID, clientSecret string, scopes []string) (*TokenResponse, error) {
	// Use background context for the service call
	ctx := context.Background()
	resp, err := a.service.ClientCredentialsGrant(ctx, clientID, clientSecret, scopes)
	if err != nil {
		return nil, err
	}
	return &TokenResponse{
		AccessToken:  resp.AccessToken,
		TokenType:    resp.TokenType,
		ExpiresIn:    resp.ExpiresIn,
		RefreshToken: resp.RefreshToken,
		Scope:        resp.Scope,
	}, nil
}

// TokenHandler handles OAuth 2.0 token endpoint requests
type TokenHandler struct {
	oauthService OAuthService
}

// NewTokenHandler creates a new token handler
func NewTokenHandler(oauthService OAuthService) *TokenHandler {
	return &TokenHandler{
		oauthService: oauthService,
	}
}

// ServeHTTP implements the http.Handler interface
func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set security headers
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Only allow POST method
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "Failed to parse form data")
		return
	}

	// Get grant_type parameter
	grantType := r.FormValue("grant_type")
	if grantType == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "Missing grant_type parameter")
		return
	}

	// Only support client_credentials for now
	if grantType != "client_credentials" {
		h.writeError(w, http.StatusBadRequest, "unsupported_grant_type", "Only client_credentials grant type is supported")
		return
	}

	// Extract client credentials (from Basic Auth or request body)
	clientID, clientSecret, err := h.extractClientCredentials(r)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
		return
	}

	// Parse scopes
	scopeParam := r.FormValue("scope")
	var scopes []string
	if scopeParam != "" {
		scopes = strings.Split(scopeParam, " ")
	}

	// Call OAuth service
	response, err := h.oauthService.ClientCredentialsGrant(clientID, clientSecret, scopes)
	if err != nil {
		h.handleOAuthError(w, err)
		return
	}

	// Write success response
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		// Log error but don't return since headers are already written
		return
	}
}

// extractClientCredentials extracts client_id and client_secret from request
func (h *TokenHandler) extractClientCredentials(r *http.Request) (string, string, error) {
	// Try to get from Authorization header (Basic Auth)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Basic ") {
		encoded := strings.TrimPrefix(authHeader, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", "", err
		}

		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return "", "", http.ErrNoCookie
		}

		return parts[0], parts[1], nil
	}

	// Try to get from request body
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if clientID == "" || clientSecret == "" {
		return "", "", http.ErrNoCookie
	}

	return clientID, clientSecret, nil
}

// handleOAuthError handles OAuth service errors
func (h *TokenHandler) handleOAuthError(w http.ResponseWriter, err error) {
	errorCode := err.Error()

	// Map error codes to HTTP status codes
	var statusCode int

	switch errorCode {
	case "invalid_client":
		statusCode = http.StatusUnauthorized
	case "invalid_scope", "unauthorized_client", "unsupported_grant_type", "invalid_request":
		statusCode = http.StatusBadRequest
	default:
		statusCode = http.StatusInternalServerError
		errorCode = "server_error"
	}

	h.writeError(w, statusCode, errorCode, "")
}

// writeError writes an OAuth error response
func (h *TokenHandler) writeError(w http.ResponseWriter, statusCode int, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)

	errResp := &OAuthError{
		ErrorCode:        errorCode,
		ErrorDescription: description,
	}

	if err := json.NewEncoder(w).Encode(errResp); err != nil {
		// Log error but don't return since headers are already written
		return
	}
}
