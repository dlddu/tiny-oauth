package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/dlddu/tiny-oauth/internal/domain"
)

// UserServiceInterface defines the interface for user operations
type UserServiceInterface interface {
	Authenticate(ctx context.Context, username, password string) (*domain.User, error)
}

// AuthCodeServiceInterface defines the interface for authorization code operations
type AuthCodeServiceInterface interface {
	GenerateAuthorizationCode(ctx context.Context, clientID, userID, redirectURI string, scopes []string) (string, error)
}

// SessionStore defines the interface for session management
type SessionStore interface {
	Set(sessionID string, key string, value interface{}) error
	Get(sessionID string, key string) (interface{}, error)
	Delete(sessionID string) error
}

// AuthHandler handles authentication and consent pages
type AuthHandler struct {
	userService     UserServiceInterface
	clientService   ClientServiceInterface
	authCodeService AuthCodeServiceInterface
	sessionStore    SessionStore
	loginTemplate   *template.Template
	consentTemplate *template.Template
}

// NewAuthHandler creates a new AuthHandler instance
func NewAuthHandler(
	userService UserServiceInterface,
	clientService ClientServiceInterface,
	authCodeService AuthCodeServiceInterface,
	sessionStore SessionStore,
) *AuthHandler {
	// Parse templates
	loginTpl := template.Must(template.New("login").Parse(loginTemplateHTML))
	consentTpl := template.Must(template.New("consent").Parse(consentTemplateHTML))

	return &AuthHandler{
		userService:     userService,
		clientService:   clientService,
		authCodeService: authCodeService,
		sessionStore:    sessionStore,
		loginTemplate:   loginTpl,
		consentTemplate: consentTpl,
	}
}

// ServeHTTP implements http.Handler interface
func (h *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set security headers
	h.setSecurityHeaders(w)

	// Route based on path and method
	switch r.URL.Path {
	case "/login":
		switch r.Method {
		case http.MethodGet:
			h.ShowLoginForm(w, r)
		case http.MethodPost:
			h.HandleLoginSubmit(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	case "/consent":
		switch r.Method {
		case http.MethodGet:
			h.ShowConsentForm(w, r)
		case http.MethodPost:
			h.HandleConsentSubmit(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		http.NotFound(w, r)
	}
}

// ShowLoginForm displays the login form
func (h *AuthHandler) ShowLoginForm(w http.ResponseWriter, r *http.Request) {
	// Generate CSRF token
	csrfToken := h.generateCSRFToken()

	// Get session ID from cookie or create new one
	sessionID := h.getOrCreateSession(r, w)

	// Store CSRF token in session
	_ = h.sessionStore.Set(sessionID, "csrf_token", csrfToken)

	// Prepare template data
	data := map[string]interface{}{
		"CSRFToken":   csrfToken,
		"ClientID":    r.URL.Query().Get("client_id"),
		"RedirectURI": r.URL.Query().Get("redirect_uri"),
		"Scope":       r.URL.Query().Get("scope"),
		"State":       r.URL.Query().Get("state"),
		"ResponseType": r.URL.Query().Get("response_type"),
		"CodeChallenge": r.URL.Query().Get("code_challenge"),
		"CodeChallengeMethod": r.URL.Query().Get("code_challenge_method"),
	}

	// Render template
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = h.loginTemplate.Execute(w, data)
}

// HandleLoginSubmit processes login form submission
func (h *AuthHandler) HandleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	// Get session ID from cookie
	sessionID := h.getSessionID(r)
	if sessionID == "" {
		http.Error(w, "Session not found", http.StatusBadRequest)
		return
	}

	// Validate CSRF token
	submittedToken := r.FormValue("csrf_token")
	storedTokenVal, _ := h.sessionStore.Get(sessionID, "csrf_token")
	storedToken, _ := storedTokenVal.(string)

	if submittedToken != "" && submittedToken != storedToken {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Invalid CSRF token")
		return
	}

	// Extract credentials
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Validate inputs
	if username == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "username is required")
		return
	}

	if password == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "password is required")
		return
	}

	// Authenticate user
	ctx := r.Context()
	user, err := h.userService.Authenticate(ctx, username, password)
	if err != nil {
		// Check if user is inactive
		if strings.Contains(err.Error(), "inactive") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Account is inactive")
			return
		}
		// Generic authentication error
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Invalid username or password")
		return
	}

	// Store user ID in session
	_ = h.sessionStore.Set(sessionID, "user_id", user.ID)

	// Check if this is part of OAuth flow
	clientID := r.FormValue("client_id")
	if clientID != "" {
		// Redirect to consent page with query parameters
		redirectURI := r.FormValue("redirect_uri")
		scope := r.FormValue("scope")
		state := r.FormValue("state")
		responseType := r.FormValue("response_type")
		codeChallenge := r.FormValue("code_challenge")
		codeChallengeMethod := r.FormValue("code_challenge_method")

		consentURL := "/consent?client_id=" + clientID
		if redirectURI != "" {
			consentURL += "&redirect_uri=" + redirectURI
		}
		if scope != "" {
			consentURL += "&scope=" + scope
		}
		if state != "" {
			consentURL += "&state=" + state
		}
		if responseType != "" {
			consentURL += "&response_type=" + responseType
		}
		if codeChallenge != "" {
			consentURL += "&code_challenge=" + codeChallenge
		}
		if codeChallengeMethod != "" {
			consentURL += "&code_challenge_method=" + codeChallengeMethod
		}

		http.Redirect(w, r, consentURL, http.StatusFound)
		return
	}

	// Redirect to home or original URL
	http.Redirect(w, r, "/", http.StatusFound)
}

// ShowConsentForm displays the consent form
func (h *AuthHandler) ShowConsentForm(w http.ResponseWriter, r *http.Request) {
	// Get session ID from cookie
	sessionID := h.getSessionID(r)
	if sessionID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Check if user is authenticated
	userIDVal, err := h.sessionStore.Get(sessionID, "user_id")
	if err != nil || userIDVal == nil {
		// Redirect to login with query parameters preserved
		loginURL := "/login?" + r.URL.RawQuery
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Extract query parameters
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "client_id is required")
		return
	}

	// Get client information
	ctx := r.Context()
	client, err := h.clientService.GetClientByID(ctx, clientID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Invalid client")
		return
	}

	// Parse requested scopes
	scopeStr := r.URL.Query().Get("scope")
	var scopes []string
	if scopeStr != "" {
		scopes = strings.Fields(scopeStr)
	}

	// Prepare template data
	data := map[string]interface{}{
		"ClientName":  client.ClientName,
		"ClientID":    clientID,
		"RedirectURI": r.URL.Query().Get("redirect_uri"),
		"Scope":       scopeStr,
		"Scopes":      scopes,
		"State":       r.URL.Query().Get("state"),
		"ResponseType": r.URL.Query().Get("response_type"),
		"CodeChallenge": r.URL.Query().Get("code_challenge"),
		"CodeChallengeMethod": r.URL.Query().Get("code_challenge_method"),
	}

	// Render template
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = h.consentTemplate.Execute(w, data)
}

// HandleConsentSubmit processes consent form submission
func (h *AuthHandler) HandleConsentSubmit(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	// Get session ID from cookie
	sessionID := h.getSessionID(r)
	if sessionID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Check if user is authenticated
	userIDVal, err := h.sessionStore.Get(sessionID, "user_id")
	if err != nil || userIDVal == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	userID, _ := userIDVal.(string)

	// Extract form data
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	scopeStr := r.FormValue("scope")
	state := r.FormValue("state")
	action := r.FormValue("action")

	// Validate required fields
	if clientID == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "client_id is required")
		return
	}

	if redirectURI == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "redirect_uri is required")
		return
	}

	// Get client information
	ctx := r.Context()
	client, err := h.clientService.GetClientByID(ctx, clientID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Invalid client")
		return
	}

	// Validate redirect URI
	if !h.isValidRedirectURI(redirectURI, client.RedirectURIs) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Invalid redirect_uri")
		return
	}

	// Parse scopes
	var scopes []string
	if scopeStr != "" {
		scopes = strings.Fields(scopeStr)
	}

	// Check if user denied
	if action == "deny" {
		// Redirect with error
		redirectURL := redirectURI + "?error=access_denied&error_description=User+denied+the+request"
		if state != "" {
			redirectURL += "&state=" + state
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Validate scopes
	if len(scopes) > 0 && !h.validateScopes(scopes, client.Scopes) {
		// Redirect with error
		redirectURL := redirectURI + "?error=invalid_scope&error_description=Requested+scope+is+invalid"
		if state != "" {
			redirectURL += "&state=" + state
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Generate authorization code
	authCode, err := h.authCodeService.GenerateAuthorizationCode(ctx, clientID, userID, redirectURI, scopes)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Failed to generate authorization code")
		return
	}

	// Redirect with authorization code
	redirectURL := redirectURI + "?code=" + authCode
	if state != "" {
		redirectURL += "&state=" + state
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// Helper methods

func (h *AuthHandler) setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
}

func (h *AuthHandler) generateCSRFToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (h *AuthHandler) getOrCreateSession(r *http.Request, w http.ResponseWriter) string {
	cookie, err := r.Cookie("session_id")
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}

	// Generate new session ID
	sessionID := h.generateSessionID()

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   3600,
	})

	return sessionID
}

func (h *AuthHandler) getSessionID(r *http.Request) string {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (h *AuthHandler) generateSessionID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (h *AuthHandler) isValidRedirectURI(redirectURI string, allowedURIs []string) bool {
	for _, allowed := range allowedURIs {
		if redirectURI == allowed {
			return true
		}
	}
	return false
}

func (h *AuthHandler) validateScopes(requested []string, allowed []string) bool {
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

// HTML Templates

const loginTemplateHTML = `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Login</title>
	<style>
		body {
			font-family: Arial, sans-serif;
			max-width: 400px;
			margin: 50px auto;
			padding: 20px;
		}
		form {
			border: 1px solid #ccc;
			padding: 20px;
			border-radius: 5px;
		}
		input {
			width: 100%;
			padding: 10px;
			margin: 10px 0;
			box-sizing: border-box;
		}
		button {
			width: 100%;
			padding: 10px;
			background-color: #007bff;
			color: white;
			border: none;
			border-radius: 5px;
			cursor: pointer;
		}
		button:hover {
			background-color: #0056b3;
		}
	</style>
</head>
<body>
	<h1>Login</h1>
	<form method="POST" action="/login">
		<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
		<input type="hidden" name="client_id" value="{{.ClientID}}">
		<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
		<input type="hidden" name="scope" value="{{.Scope}}">
		<input type="hidden" name="state" value="{{.State}}">
		<input type="hidden" name="response_type" value="{{.ResponseType}}">
		<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
		<input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">

		<label for="username">Username:</label>
		<input type="text" id="username" name="username" required>

		<label for="password">Password:</label>
		<input type="password" id="password" name="password" required>

		<button type="submit">Login</button>
	</form>
</body>
</html>`

const consentTemplateHTML = `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Authorization Required</title>
	<style>
		body {
			font-family: Arial, sans-serif;
			max-width: 500px;
			margin: 50px auto;
			padding: 20px;
		}
		.consent-box {
			border: 1px solid #ccc;
			padding: 20px;
			border-radius: 5px;
		}
		.scopes {
			margin: 20px 0;
			padding: 10px;
			background-color: #f5f5f5;
			border-radius: 5px;
		}
		.scope-item {
			margin: 5px 0;
		}
		.buttons {
			display: flex;
			gap: 10px;
			margin-top: 20px;
		}
		button {
			flex: 1;
			padding: 10px;
			border: none;
			border-radius: 5px;
			cursor: pointer;
		}
		.allow {
			background-color: #28a745;
			color: white;
		}
		.allow:hover {
			background-color: #218838;
		}
		.deny {
			background-color: #dc3545;
			color: white;
		}
		.deny:hover {
			background-color: #c82333;
		}
	</style>
</head>
<body>
	<div class="consent-box">
		<h1>Authorization Required</h1>
		<p><strong>{{.ClientName}}</strong> is requesting access to your account.</p>

		{{if .Scopes}}
		<div class="scopes">
			<p><strong>Requested permissions:</strong></p>
			<ul>
				{{range .Scopes}}
				<li class="scope-item">{{.}}</li>
				{{end}}
			</ul>
		</div>
		{{end}}

		<form method="POST" action="/consent">
			<input type="hidden" name="client_id" value="{{.ClientID}}">
			<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
			<input type="hidden" name="scope" value="{{.Scope}}">
			<input type="hidden" name="state" value="{{.State}}">
			<input type="hidden" name="response_type" value="{{.ResponseType}}">
			<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
			<input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">

			<div class="buttons">
				<button type="submit" name="action" value="allow" class="allow">Allow</button>
				<button type="submit" name="action" value="deny" class="deny">Deny</button>
			</div>
		</form>
	</div>
</body>
</html>`
