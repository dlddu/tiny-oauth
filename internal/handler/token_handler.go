package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/dlddu/tiny-oauth/internal/auth"
	"github.com/dlddu/tiny-oauth/internal/domain"
)

// ClientServiceInterface defines the interface for client operations
type ClientServiceInterface interface {
	AuthenticateClient(ctx context.Context, clientID, clientSecret string) (*domain.Client, error)
	GetClientByID(ctx context.Context, clientID string) (*domain.Client, error)
}

// TokenServiceInterface defines the interface for token operations
type TokenServiceInterface interface {
	GenerateAccessToken(ctx context.Context, clientID string, scopes []string) (string, time.Duration, error)
}

// TokenHandler handles OAuth 2.0 token endpoint requests
type TokenHandler struct {
	clientService ClientServiceInterface
	tokenService  TokenServiceInterface
}

// NewTokenHandler creates a new TokenHandler instance
func NewTokenHandler(clientService ClientServiceInterface, tokenService TokenServiceInterface) *TokenHandler {
	return &TokenHandler{
		clientService: clientService,
		tokenService:  tokenService,
	}
}

// TokenResponse represents the OAuth 2.0 token endpoint response
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// ErrorResponse represents the OAuth 2.0 error response
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// ServeHTTP implements http.Handler interface
func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set security headers
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")

	// Only accept POST method
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Method not allowed",
		})
		return
	}

	// Validate Content-Type
	contentType := r.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Content-Type must be application/x-www-form-urlencoded",
		})
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Failed to parse form data",
		})
		return
	}

	// Extract grant_type
	grantType := r.FormValue("grant_type")
	if grantType == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "grant_type parameter is required",
		})
		return
	}

	// Only support client_credentials grant type
	if grantType != "client_credentials" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "unsupported_grant_type",
			ErrorDescription: "grant_type must be client_credentials",
		})
		return
	}

	// Authenticate client
	client, err := h.authenticateClient(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "Client authentication failed",
		})
		return
	}

	// Check if client supports client_credentials grant
	if !h.supportsGrantType(client, "client_credentials") {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "unauthorized_client",
			ErrorDescription: "Client is not authorized to use this grant type",
		})
		return
	}

	// Extract and validate scopes
	requestedScope := r.FormValue("scope")
	scopes := h.parseScopes(requestedScope)

	// If no scope requested, use all client scopes
	if len(scopes) == 0 {
		scopes = client.Scopes
	} else {
		// Validate requested scopes
		if !h.validateScopes(scopes, client.Scopes) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error:            "invalid_scope",
				ErrorDescription: "Requested scope is not allowed for this client",
			})
			return
		}
	}

	// Generate access token
	ctx := r.Context()
	accessToken, expiresIn, err := h.tokenService.GenerateAccessToken(ctx, client.ClientID, scopes)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to generate access token",
		})
		return
	}

	// Build response
	response := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(expiresIn.Seconds()),
		Scope:       strings.Join(scopes, " "),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// authenticateClient authenticates the client using Basic Auth or POST body
func (h *TokenHandler) authenticateClient(r *http.Request) (*domain.Client, error) {
	var clientID, clientSecret string

	// Try Basic Auth first
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		var err error
		clientID, clientSecret, err = auth.ParseBasicAuth(authHeader)
		if err != nil {
			return nil, err
		}
	} else {
		// Try POST body
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")

		if clientID == "" || clientSecret == "" {
			return nil, auth.ErrInvalidCredentials
		}
	}

	// Authenticate client
	ctx := r.Context()
	return h.clientService.AuthenticateClient(ctx, clientID, clientSecret)
}

// supportsGrantType checks if the client supports the given grant type
func (h *TokenHandler) supportsGrantType(client *domain.Client, grantType string) bool {
	for _, gt := range client.GrantTypes {
		if gt == grantType {
			return true
		}
	}
	return false
}

// parseScopes parses space-separated scopes
func (h *TokenHandler) parseScopes(scope string) []string {
	if scope == "" {
		return []string{}
	}
	return strings.Fields(scope)
}

// validateScopes checks if all requested scopes are allowed
func (h *TokenHandler) validateScopes(requested []string, allowed []string) bool {
	allowedMap := make(map[string]bool)
	for _, s := range allowed {
		allowedMap[s] = true
	}

	for _, s := range requested {
		if !allowedMap[s] {
			return false
		}
	}

	return true
}
