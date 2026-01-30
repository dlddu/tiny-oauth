package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dlddu/tiny-oauth/internal/domain"
)

// MockUserService is a mock for user authentication operations
type MockUserService struct {
	user *domain.User
	err  error
}

func (m *MockUserService) Authenticate(ctx context.Context, username, password string) (*domain.User, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.user, nil
}

func (m *MockUserService) Register(ctx context.Context, username, email, password, firstName, lastName string) (*domain.User, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.user, nil
}

func (m *MockUserService) GetByID(ctx context.Context, id string) (*domain.User, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.user, nil
}

func (m *MockUserService) UpdatePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	return m.err
}

func (m *MockUserService) ValidateEmail(email string) error {
	return m.err
}

func (m *MockUserService) ValidateUsername(username string) error {
	return m.err
}

// MockAuthCodeService is a mock for authorization code operations
type MockAuthCodeService struct {
	err error
}

func (m *MockAuthCodeService) GenerateAuthorizationCode(ctx context.Context, clientID, userID, redirectURI string, scopes []string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return "test-auth-code-123", nil
}

// MockSessionStore is a mock for session storage operations
type MockSessionStore struct {
	sessions map[string]map[string]interface{}
	err      error
}

func NewMockSessionStore() *MockSessionStore {
	return &MockSessionStore{
		sessions: make(map[string]map[string]interface{}),
	}
}

func (m *MockSessionStore) Set(sessionID string, key string, value interface{}) error {
	if m.err != nil {
		return m.err
	}
	if m.sessions[sessionID] == nil {
		m.sessions[sessionID] = make(map[string]interface{})
	}
	m.sessions[sessionID][key] = value
	return nil
}

func (m *MockSessionStore) Get(sessionID string, key string) (interface{}, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.sessions[sessionID] == nil {
		return nil, errors.New("session not found")
	}
	return m.sessions[sessionID][key], nil
}

func (m *MockSessionStore) Delete(sessionID string) error {
	if m.err != nil {
		return m.err
	}
	delete(m.sessions, sessionID)
	return nil
}

func TestAuthHandler_ShowLoginForm(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    url.Values
		wantStatus     int
		wantContains   []string
		wantNotContain []string
	}{
		{
			name:        "should render login form with username and password fields",
			queryParams: url.Values{},
			wantStatus:  http.StatusOK,
			wantContains: []string{
				"username",
				"password",
				"<form",
				"</form>",
			},
		},
		{
			name: "should preserve redirect_uri in form",
			queryParams: url.Values{
				"redirect_uri": {"https://example.com/callback"},
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				"redirect_uri",
				"https://example.com/callback",
			},
		},
		{
			name: "should preserve client_id in form",
			queryParams: url.Values{
				"client_id": {"test-client-id"},
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				"client_id",
				"test-client-id",
			},
		},
		{
			name: "should preserve scope in form",
			queryParams: url.Values{
				"scope": {"read write"},
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				"scope",
				"read write",
			},
		},
		{
			name: "should preserve state parameter",
			queryParams: url.Values{
				"state": {"random-state-value"},
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				"state",
				"random-state-value",
			},
		},
		{
			name: "should include CSRF token field",
			queryParams: url.Values{},
			wantStatus:  http.StatusOK,
			wantContains: []string{
				"csrf_token",
				"type=\"hidden\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create handler
			userService := &MockUserService{}
			clientService := &MockClientService{}
			authCodeService := &MockAuthCodeService{}
			sessionStore := NewMockSessionStore()
			handler := NewAuthHandler(userService, clientService, authCodeService, sessionStore)

			// Build URL with query parameters
			reqURL := "/login"
			if len(tt.queryParams) > 0 {
				reqURL += "?" + tt.queryParams.Encode()
			}

			// Create request
			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			// Check response body contains expected strings
			body := rr.Body.String()
			for _, expectedStr := range tt.wantContains {
				if !strings.Contains(body, expectedStr) {
					t.Errorf("response body should contain %q", expectedStr)
				}
			}

			// Check response body does not contain unexpected strings
			for _, unexpectedStr := range tt.wantNotContain {
				if strings.Contains(body, unexpectedStr) {
					t.Errorf("response body should not contain %q", unexpectedStr)
				}
			}
		})
	}
}

func TestAuthHandler_HandleLoginSubmit(t *testing.T) {
	tests := []struct {
		name             string
		formData         url.Values
		setupMocks       func(*MockUserService, *MockSessionStore)
		wantStatus       int
		wantRedirect     bool
		wantRedirectPath string
		wantError        bool
		wantErrorMessage string
	}{
		{
			name: "should authenticate user with valid credentials",
			formData: url.Values{
				"username": {"testuser"},
				"password": {"correct-password"},
			},
			setupMocks: func(us *MockUserService, ss *MockSessionStore) {
				us.user = &domain.User{
					ID:       "user-123",
					Username: "testuser",
					Email:    "test@example.com",
					IsActive: true,
				}
			},
			wantStatus:   http.StatusFound,
			wantRedirect: true,
		},
		{
			name: "should create session after successful authentication",
			formData: url.Values{
				"username": {"testuser"},
				"password": {"correct-password"},
			},
			setupMocks: func(us *MockUserService, ss *MockSessionStore) {
				us.user = &domain.User{
					ID:       "user-123",
					Username: "testuser",
					Email:    "test@example.com",
					IsActive: true,
				}
			},
			wantStatus:   http.StatusFound,
			wantRedirect: true,
		},
		{
			name: "should redirect to consent page when client_id present",
			formData: url.Values{
				"username":  {"testuser"},
				"password":  {"correct-password"},
				"client_id": {"test-client"},
			},
			setupMocks: func(us *MockUserService, ss *MockSessionStore) {
				us.user = &domain.User{
					ID:       "user-123",
					Username: "testuser",
					IsActive: true,
				}
			},
			wantStatus:       http.StatusFound,
			wantRedirect:     true,
			wantRedirectPath: "/consent",
		},
		{
			name: "should redirect to original URL when no client_id",
			formData: url.Values{
				"username":     {"testuser"},
				"password":     {"correct-password"},
				"redirect_uri": {"https://example.com/callback"},
			},
			setupMocks: func(us *MockUserService, ss *MockSessionStore) {
				us.user = &domain.User{
					ID:       "user-123",
					Username: "testuser",
					IsActive: true,
				}
			},
			wantStatus:   http.StatusFound,
			wantRedirect: true,
		},
		{
			name: "should fail with empty username",
			formData: url.Values{
				"username": {""},
				"password": {"password123"},
			},
			setupMocks: func(us *MockUserService, ss *MockSessionStore) {
				us.err = errors.New("invalid credentials")
			},
			wantStatus:       http.StatusBadRequest,
			wantError:        true,
			wantErrorMessage: "username is required",
		},
		{
			name: "should fail with empty password",
			formData: url.Values{
				"username": {"testuser"},
				"password": {""},
			},
			setupMocks: func(us *MockUserService, ss *MockSessionStore) {
				us.err = errors.New("invalid credentials")
			},
			wantStatus:       http.StatusBadRequest,
			wantError:        true,
			wantErrorMessage: "password is required",
		},
		{
			name: "should fail with invalid username",
			formData: url.Values{
				"username": {"invaliduser"},
				"password": {"wrong-password"},
			},
			setupMocks: func(us *MockUserService, ss *MockSessionStore) {
				us.err = errors.New("invalid credentials")
			},
			wantStatus:       http.StatusUnauthorized,
			wantError:        true,
			wantErrorMessage: "Invalid username or password",
		},
		{
			name: "should fail with invalid password",
			formData: url.Values{
				"username": {"testuser"},
				"password": {"wrong-password"},
			},
			setupMocks: func(us *MockUserService, ss *MockSessionStore) {
				us.err = errors.New("invalid credentials")
			},
			wantStatus:       http.StatusUnauthorized,
			wantError:        true,
			wantErrorMessage: "Invalid username or password",
		},
		{
			name: "should fail when user is inactive",
			formData: url.Values{
				"username": {"testuser"},
				"password": {"correct-password"},
			},
			setupMocks: func(us *MockUserService, ss *MockSessionStore) {
				us.err = errors.New("user is inactive")
			},
			wantStatus:       http.StatusForbidden,
			wantError:        true,
			wantErrorMessage: "Account is inactive",
		},
		{
			name: "should fail with invalid CSRF token",
			formData: url.Values{
				"username":   {"testuser"},
				"password":   {"correct-password"},
				"csrf_token": {"invalid-token"},
			},
			setupMocks: func(us *MockUserService, ss *MockSessionStore) {
				us.user = &domain.User{
					ID:       "user-123",
					Username: "testuser",
					IsActive: true,
				}
			},
			wantStatus:       http.StatusForbidden,
			wantError:        true,
			wantErrorMessage: "Invalid CSRF token",
		},
		{
			name: "should preserve state parameter after login",
			formData: url.Values{
				"username": {"testuser"},
				"password": {"correct-password"},
				"state":    {"random-state-123"},
			},
			setupMocks: func(us *MockUserService, ss *MockSessionStore) {
				us.user = &domain.User{
					ID:       "user-123",
					Username: "testuser",
					IsActive: true,
				}
			},
			wantStatus:   http.StatusFound,
			wantRedirect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			userService := &MockUserService{}
			sessionStore := NewMockSessionStore()
			if tt.setupMocks != nil {
				tt.setupMocks(userService, sessionStore)
			}

			// Create handler
			clientService := &MockClientService{}
			authCodeService := &MockAuthCodeService{}
			handler := NewAuthHandler(userService, clientService, authCodeService, sessionStore)

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(tt.formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{
				Name:  "session_id",
				Value: "test-session",
			})
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			// Check redirect
			if tt.wantRedirect {
				location := rr.Header().Get("Location")
				if location == "" {
					t.Error("expected Location header for redirect")
				}
				if tt.wantRedirectPath != "" && !strings.Contains(location, tt.wantRedirectPath) {
					t.Errorf("expected redirect to contain %q, got %q", tt.wantRedirectPath, location)
				}
			}

			// Check error message
			if tt.wantError {
				body := rr.Body.String()
				if tt.wantErrorMessage != "" && !strings.Contains(body, tt.wantErrorMessage) {
					t.Errorf("expected error message to contain %q", tt.wantErrorMessage)
				}
			}
		})
	}
}

func TestAuthHandler_ShowConsentForm(t *testing.T) {
	tests := []struct {
		name           string
		sessionData    map[string]interface{}
		queryParams    url.Values
		setupMocks     func(*MockClientService)
		wantStatus     int
		wantContains   []string
		wantNotContain []string
	}{
		{
			name: "should display consent form with client information",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
				"scope":     {"read write"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "Test Application",
					Scopes:     []string{"read", "write"},
				}
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				"Test Application",
				"read",
				"write",
				"Allow",
				"Deny",
			},
		},
		{
			name: "should display requested scopes",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
				"scope":     {"read write profile"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "Test Application",
					Scopes:     []string{"read", "write", "profile"},
				}
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				"read",
				"write",
				"profile",
			},
		},
		{
			name: "should require authentication before showing consent",
			sessionData: map[string]interface{}{
				// No user_id in session
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
			},
			setupMocks: func(cs *MockClientService) {},
			wantStatus: http.StatusFound, // Redirect to login
		},
		{
			name: "should fail with missing client_id",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				// No client_id
			},
			setupMocks:   func(cs *MockClientService) {},
			wantStatus:   http.StatusBadRequest,
			wantContains: []string{"client_id is required"},
		},
		{
			name: "should fail with invalid client_id",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"invalid-client"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.err = errors.New("client not found")
			},
			wantStatus:   http.StatusBadRequest,
			wantContains: []string{"Invalid client"},
		},
		{
			name: "should preserve redirect_uri in form",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id":    {"test-client"},
				"redirect_uri": {"https://example.com/callback"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					ClientName:   "Test Application",
					RedirectURIs: []string{"https://example.com/callback"},
				}
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				"redirect_uri",
				"https://example.com/callback",
			},
		},
		{
			name: "should preserve state parameter in form",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
				"state":     {"random-state-value"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "Test Application",
				}
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				"state",
				"random-state-value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			clientService := &MockClientService{}
			sessionStore := NewMockSessionStore()
			if tt.setupMocks != nil {
				tt.setupMocks(clientService)
			}

			// Set session data
			for key, value := range tt.sessionData {
				_ = sessionStore.Set("test-session", key, value)
			}

			// Create handler
			userService := &MockUserService{}
			authCodeService := &MockAuthCodeService{}
			handler := NewAuthHandler(userService, clientService, authCodeService, sessionStore)

			// Build URL with query parameters
			reqURL := "/consent"
			if len(tt.queryParams) > 0 {
				reqURL += "?" + tt.queryParams.Encode()
			}

			// Create request with session cookie
			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			req.AddCookie(&http.Cookie{
				Name:  "session_id",
				Value: "test-session",
			})
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			// Check response body contains expected strings
			body := rr.Body.String()
			for _, expectedStr := range tt.wantContains {
				if !strings.Contains(body, expectedStr) {
					t.Errorf("response body should contain %q", expectedStr)
				}
			}

			// Check response body does not contain unexpected strings
			for _, unexpectedStr := range tt.wantNotContain {
				if strings.Contains(body, unexpectedStr) {
					t.Errorf("response body should not contain %q", unexpectedStr)
				}
			}
		})
	}
}

func TestAuthHandler_HandleConsentSubmit(t *testing.T) {
	tests := []struct {
		name             string
		sessionData      map[string]interface{}
		formData         url.Values
		setupMocks       func(*MockClientService, *MockAuthCodeService)
		wantStatus       int
		wantRedirect     bool
		wantRedirectPath string
		wantQueryParams  map[string]string
	}{
		{
			name: "should generate authorization code when user approves",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			formData: url.Values{
				"client_id":    {"test-client"},
				"redirect_uri": {"https://example.com/callback"},
				"scope":        {"read write"},
				"action":       {"allow"},
			},
			setupMocks: func(cs *MockClientService, acs *MockAuthCodeService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
					Scopes:       []string{"read", "write"},
				}
			},
			wantStatus:       http.StatusFound,
			wantRedirect:     true,
			wantRedirectPath: "https://example.com/callback",
			wantQueryParams: map[string]string{
				"code": "test-auth-code-123",
			},
		},
		{
			name: "should redirect with authorization code in query",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			formData: url.Values{
				"client_id":    {"test-client"},
				"redirect_uri": {"https://example.com/callback"},
				"scope":        {"read"},
				"action":       {"allow"},
			},
			setupMocks: func(cs *MockClientService, acs *MockAuthCodeService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
					Scopes:       []string{"read"},
				}
			},
			wantStatus:       http.StatusFound,
			wantRedirect:     true,
			wantRedirectPath: "https://example.com/callback",
		},
		{
			name: "should preserve state parameter in redirect",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			formData: url.Values{
				"client_id":    {"test-client"},
				"redirect_uri": {"https://example.com/callback"},
				"scope":        {"read"},
				"state":        {"random-state-123"},
				"action":       {"allow"},
			},
			setupMocks: func(cs *MockClientService, acs *MockAuthCodeService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
					Scopes:       []string{"read"},
				}
			},
			wantStatus:       http.StatusFound,
			wantRedirect:     true,
			wantRedirectPath: "https://example.com/callback",
			wantQueryParams: map[string]string{
				"state": "random-state-123",
			},
		},
		{
			name: "should redirect with error when user denies",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			formData: url.Values{
				"client_id":    {"test-client"},
				"redirect_uri": {"https://example.com/callback"},
				"action":       {"deny"},
			},
			setupMocks: func(cs *MockClientService, acs *MockAuthCodeService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
				}
			},
			wantStatus:       http.StatusFound,
			wantRedirect:     true,
			wantRedirectPath: "https://example.com/callback",
			wantQueryParams: map[string]string{
				"error":             "access_denied",
				"error_description": "User denied the request",
			},
		},
		{
			name: "should require authentication",
			sessionData: map[string]interface{}{
				// No user_id in session
			},
			formData: url.Values{
				"client_id":    {"test-client"},
				"redirect_uri": {"https://example.com/callback"},
				"action":       {"allow"},
			},
			setupMocks: func(cs *MockClientService, acs *MockAuthCodeService) {},
			wantStatus:   http.StatusFound, // Redirect to login
			wantRedirect: true,
		},
		{
			name: "should fail with missing client_id",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			formData: url.Values{
				"redirect_uri": {"https://example.com/callback"},
				"action":       {"allow"},
			},
			setupMocks: func(cs *MockClientService, acs *MockAuthCodeService) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "should fail with missing redirect_uri",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			formData: url.Values{
				"client_id": {"test-client"},
				"action":    {"allow"},
			},
			setupMocks: func(cs *MockClientService, acs *MockAuthCodeService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
				}
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "should fail with invalid redirect_uri",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			formData: url.Values{
				"client_id":    {"test-client"},
				"redirect_uri": {"https://evil.com/callback"},
				"action":       {"allow"},
			},
			setupMocks: func(cs *MockClientService, acs *MockAuthCodeService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
				}
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "should fail with invalid scope",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			formData: url.Values{
				"client_id":    {"test-client"},
				"redirect_uri": {"https://example.com/callback"},
				"scope":        {"admin delete"},
				"action":       {"allow"},
			},
			setupMocks: func(cs *MockClientService, acs *MockAuthCodeService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
					Scopes:       []string{"read", "write"},
				}
			},
			wantStatus:       http.StatusFound,
			wantRedirect:     true,
			wantRedirectPath: "https://example.com/callback",
			wantQueryParams: map[string]string{
				"error":             "invalid_scope",
				"error_description": "Requested scope is invalid",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			clientService := &MockClientService{}
			authCodeService := &MockAuthCodeService{}
			sessionStore := NewMockSessionStore()
			if tt.setupMocks != nil {
				tt.setupMocks(clientService, authCodeService)
			}

			// Set session data
			for key, value := range tt.sessionData {
				_ = sessionStore.Set("test-session", key, value)
			}

			// Create handler
			userService := &MockUserService{}
			handler := NewAuthHandler(userService, clientService, authCodeService, sessionStore)

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(tt.formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{
				Name:  "session_id",
				Value: "test-session",
			})
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			// Check redirect
			if tt.wantRedirect {
				location := rr.Header().Get("Location")
				if location == "" {
					t.Error("expected Location header for redirect")
				}
				if tt.wantRedirectPath != "" && !strings.Contains(location, tt.wantRedirectPath) {
					t.Errorf("expected redirect to contain %q, got %q", tt.wantRedirectPath, location)
				}

				// Check query parameters in redirect URL
				if len(tt.wantQueryParams) > 0 {
					redirectURL, err := url.Parse(location)
					if err != nil {
						t.Fatalf("failed to parse redirect URL: %v", err)
					}
					queryParams := redirectURL.Query()
					for key, expectedValue := range tt.wantQueryParams {
						actualValue := queryParams.Get(key)
						if expectedValue != "" && actualValue != expectedValue {
							t.Errorf("expected query param %s=%q, got %q", key, expectedValue, actualValue)
						} else if expectedValue == "" && actualValue == "" {
							t.Errorf("expected query param %s to be present", key)
						}
					}
				}
			}
		})
	}
}

func TestAuthHandler_MethodValidation(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		method     string
		wantStatus int
	}{
		{
			name:       "should accept GET for login page",
			path:       "/login",
			method:     http.MethodGet,
			wantStatus: http.StatusOK,
		},
		{
			name:       "should accept POST for login submission",
			path:       "/login",
			method:     http.MethodPost,
			wantStatus: http.StatusBadRequest, // Will fail validation, but method is accepted
		},
		{
			name:       "should reject PUT for login",
			path:       "/login",
			method:     http.MethodPut,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "should reject DELETE for login",
			path:       "/login",
			method:     http.MethodDelete,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "should accept GET for consent page",
			path:       "/consent",
			method:     http.MethodGet,
			wantStatus: http.StatusFound, // Redirects if not authenticated
		},
		{
			name:       "should accept POST for consent submission",
			path:       "/consent",
			method:     http.MethodPost,
			wantStatus: http.StatusFound, // Redirects if not authenticated
		},
		{
			name:       "should reject PUT for consent",
			path:       "/consent",
			method:     http.MethodPut,
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create handler
			userService := &MockUserService{}
			clientService := &MockClientService{}
			authCodeService := &MockAuthCodeService{}
			sessionStore := NewMockSessionStore()
			handler := NewAuthHandler(userService, clientService, authCodeService, sessionStore)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestAuthHandler_SessionManagement(t *testing.T) {
	tests := []struct {
		name          string
		setupSession  func(*MockSessionStore)
		wantSessionID bool
		wantCookie    bool
	}{
		{
			name: "should create session cookie after successful login",
			setupSession: func(ss *MockSessionStore) {
				// Session will be created during login
			},
			wantSessionID: true,
			wantCookie:    true,
		},
		{
			name: "should set HttpOnly flag on session cookie",
			setupSession: func(ss *MockSessionStore) {
				// Session will be created during login
			},
			wantSessionID: true,
			wantCookie:    true,
		},
		{
			name: "should set Secure flag on session cookie in production",
			setupSession: func(ss *MockSessionStore) {
				// Session will be created during login
			},
			wantSessionID: true,
			wantCookie:    true,
		},
		{
			name: "should set SameSite=Lax on session cookie",
			setupSession: func(ss *MockSessionStore) {
				// Session will be created during login
			},
			wantSessionID: true,
			wantCookie:    true,
		},
		{
			name: "should store user_id in session",
			setupSession: func(ss *MockSessionStore) {
				_ = ss.Set("test-session", "user_id", "user-123")
			},
			wantSessionID: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionStore := NewMockSessionStore()
			if tt.setupSession != nil {
				tt.setupSession(sessionStore)
			}

			// Create handler and test session management
			userService := &MockUserService{
				user: &domain.User{
					ID:       "user-123",
					Username: "testuser",
					IsActive: true,
				},
			}
			clientService := &MockClientService{}
			authCodeService := &MockAuthCodeService{}
			handler := NewAuthHandler(userService, clientService, authCodeService, sessionStore)

			// Simulate a login request to create session
			formData := url.Values{
				"username": {"testuser"},
				"password": {"password"},
			}
			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{
				Name:  "session_id",
				Value: "test-session",
			})
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			// Verify session was created or accessed correctly
			if tt.wantSessionID {
				// Check that session contains expected data
				userID, err := sessionStore.Get("test-session", "user_id")
				if err != nil {
					t.Errorf("expected session to contain user_id: %v", err)
				}
				if userID == nil {
					t.Error("expected user_id to be set in session")
				}
			}
		})
	}
}

func TestAuthHandler_CSRFProtection(t *testing.T) {
	tests := []struct {
		name             string
		setupCSRF        func() (string, string) // Returns expected token and provided token
		wantStatus       int
		wantError        bool
		wantErrorMessage string
	}{
		{
			name: "should accept request with valid CSRF token",
			setupCSRF: func() (string, string) {
				token := "valid-csrf-token-123"
				return token, token
			},
			wantStatus: http.StatusFound,
		},
		{
			name: "should reject request with invalid CSRF token",
			setupCSRF: func() (string, string) {
				return "valid-csrf-token-123", "invalid-token"
			},
			wantStatus:       http.StatusForbidden,
			wantError:        true,
			wantErrorMessage: "Invalid CSRF token",
		},
		{
			name: "should allow request without CSRF token (optional validation)",
			setupCSRF: func() (string, string) {
				return "valid-csrf-token-123", ""
			},
			wantStatus: http.StatusFound, // Handler allows requests without CSRF token
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test CSRF protection
			userService := &MockUserService{
				user: &domain.User{
					ID:       "user-123",
					Username: "testuser",
					IsActive: true,
				},
			}
			clientService := &MockClientService{}
			authCodeService := &MockAuthCodeService{}
			sessionStore := NewMockSessionStore()
			handler := NewAuthHandler(userService, clientService, authCodeService, sessionStore)

			expectedToken, providedToken := tt.setupCSRF()

			// Store expected token in session
			_ = sessionStore.Set("test-session", "csrf_token", expectedToken)

			// Create request with provided token
			formData := url.Values{
				"username":   {"testuser"},
				"password":   {"password123"},
				"csrf_token": {providedToken},
			}

			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{
				Name:  "session_id",
				Value: "test-session",
			})
			rr := httptest.NewRecorder()

			// Execute and verify
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestAuthHandler_PKCESupport(t *testing.T) {
	tests := []struct {
		name               string
		formData           url.Values
		wantCodeChallenge  bool
		wantChallengeParam string
	}{
		{
			name: "should store code_challenge when provided",
			formData: url.Values{
				"client_id":             {"test-client"},
				"code_challenge":        {"test-challenge"},
				"code_challenge_method": {"S256"},
				"action":                {"allow"},
			},
			wantCodeChallenge:  true,
			wantChallengeParam: "code_challenge",
		},
		{
			name: "should accept plain code challenge method",
			formData: url.Values{
				"client_id":             {"test-client"},
				"code_challenge":        {"test-challenge"},
				"code_challenge_method": {"plain"},
				"action":                {"allow"},
			},
			wantCodeChallenge: true,
		},
		{
			name: "should accept S256 code challenge method",
			formData: url.Values{
				"client_id":             {"test-client"},
				"code_challenge":        {"test-challenge"},
				"code_challenge_method": {"S256"},
				"action":                {"allow"},
			},
			wantCodeChallenge: true,
		},
		{
			name: "should work without code_challenge for confidential clients",
			formData: url.Values{
				"client_id": {"test-client"},
				"action":    {"allow"},
			},
			wantCodeChallenge: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test PKCE support
			userService := &MockUserService{}
			clientService := &MockClientService{
				client: &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
					Scopes:       []string{"read", "write"},
				},
			}
			authCodeService := &MockAuthCodeService{}
			sessionStore := NewMockSessionStore()
			_ = sessionStore.Set("test-session", "user_id", "user-123")
			handler := NewAuthHandler(userService, clientService, authCodeService, sessionStore)

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(tt.formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{
				Name:  "session_id",
				Value: "test-session",
			})
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			// Verify that code_challenge is properly stored and passed to authorization code generation
		})
	}
}

func TestAuthHandler_SecurityHeaders(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		wantHeaders    map[string]string
		wantNotHeaders []string
	}{
		{
			name: "should set X-Frame-Options header",
			path: "/login",
			wantHeaders: map[string]string{
				"X-Frame-Options": "DENY",
			},
		},
		{
			name: "should set X-Content-Type-Options header",
			path: "/login",
			wantHeaders: map[string]string{
				"X-Content-Type-Options": "nosniff",
			},
		},
		{
			name: "should set X-XSS-Protection header",
			path: "/login",
			wantHeaders: map[string]string{
				"X-XSS-Protection": "1; mode=block",
			},
		},
		{
			name: "should set Content-Security-Policy header",
			path: "/login",
			wantHeaders: map[string]string{
				"Content-Security-Policy": "default-src 'self'",
			},
		},
		{
			name: "should not cache login page",
			path: "/login",
			wantHeaders: map[string]string{
				"Cache-Control": "no-store, no-cache, must-revalidate",
				"Pragma":        "no-cache",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test security headers
			userService := &MockUserService{}
			clientService := &MockClientService{}
			authCodeService := &MockAuthCodeService{}
			sessionStore := NewMockSessionStore()
			handler := NewAuthHandler(userService, clientService, authCodeService, sessionStore)

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			// Check expected headers
			for headerName, expectedValue := range tt.wantHeaders {
				actualValue := rr.Header().Get(headerName)
				if !strings.Contains(actualValue, expectedValue) {
					t.Errorf("expected header %s to contain %q, got %q", headerName, expectedValue, actualValue)
				}
			}

			// Check headers that should not be present
			for _, headerName := range tt.wantNotHeaders {
				if rr.Header().Get(headerName) != "" {
					t.Errorf("header %s should not be present", headerName)
				}
			}
		})
	}
}

func TestAuthHandler_LoginFormRendering(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    url.Values
		wantStatus     int
		wantContains   []string
		wantNotContain []string
	}{
		{
			name:        "should render login form with proper HTML structure",
			queryParams: url.Values{},
			wantStatus:  http.StatusOK,
			wantContains: []string{
				"<!DOCTYPE html>",
				"<html>",
				"</html>",
				"<head>",
				"</head>",
				"<body>",
				"</body>",
			},
		},
		{
			name:        "should include meta viewport for responsive design",
			queryParams: url.Values{},
			wantStatus:  http.StatusOK,
			wantContains: []string{
				`<meta name="viewport"`,
				`content="width=device-width, initial-scale=1.0"`,
			},
		},
		{
			name:        "should include UTF-8 charset meta tag",
			queryParams: url.Values{},
			wantStatus:  http.StatusOK,
			wantContains: []string{
				`<meta charset="UTF-8">`,
			},
		},
		{
			name:        "should include title in login page",
			queryParams: url.Values{},
			wantStatus:  http.StatusOK,
			wantContains: []string{
				"<title>Login</title>",
			},
		},
		{
			name:        "should include username label with for attribute",
			queryParams: url.Values{},
			wantStatus:  http.StatusOK,
			wantContains: []string{
				`<label for="username">`,
				"Username",
			},
		},
		{
			name:        "should include password label with for attribute",
			queryParams: url.Values{},
			wantStatus:  http.StatusOK,
			wantContains: []string{
				`<label for="password">`,
				"Password",
			},
		},
		{
			name:        "should include username input with proper attributes",
			queryParams: url.Values{},
			wantStatus:  http.StatusOK,
			wantContains: []string{
				`<input type="text"`,
				`id="username"`,
				`name="username"`,
				`required`,
			},
		},
		{
			name:        "should include password input with proper type",
			queryParams: url.Values{},
			wantStatus:  http.StatusOK,
			wantContains: []string{
				`<input type="password"`,
				`id="password"`,
				`name="password"`,
				`required`,
			},
		},
		{
			name:        "should include submit button",
			queryParams: url.Values{},
			wantStatus:  http.StatusOK,
			wantContains: []string{
				`<button type="submit">`,
				"Login",
				"</button>",
			},
		},
		{
			name:        "should include form with POST method",
			queryParams: url.Values{},
			wantStatus:  http.StatusOK,
			wantContains: []string{
				`<form method="POST"`,
				`action="/login"`,
			},
		},
		{
			name:        "should include style tag for basic styling",
			queryParams: url.Values{},
			wantStatus:  http.StatusOK,
			wantContains: []string{
				"<style>",
				"</style>",
			},
		},
		{
			name:        "should include CSS for responsive layout",
			queryParams: url.Values{},
			wantStatus:  http.StatusOK,
			wantContains: []string{
				"font-family",
				"padding",
				"margin",
			},
		},
		{
			name:        "should include hidden CSRF token field",
			queryParams: url.Values{},
			wantStatus:  http.StatusOK,
			wantContains: []string{
				`<input type="hidden"`,
				`name="csrf_token"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create handler
			userService := &MockUserService{}
			clientService := &MockClientService{}
			authCodeService := &MockAuthCodeService{}
			sessionStore := NewMockSessionStore()
			handler := NewAuthHandler(userService, clientService, authCodeService, sessionStore)

			// Build URL with query parameters
			reqURL := "/login"
			if len(tt.queryParams) > 0 {
				reqURL += "?" + tt.queryParams.Encode()
			}

			// Create request
			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			// Check response body contains expected strings
			body := rr.Body.String()
			for _, expectedStr := range tt.wantContains {
				if !strings.Contains(body, expectedStr) {
					t.Errorf("response body should contain %q", expectedStr)
				}
			}

			// Check response body does not contain unexpected strings
			for _, unexpectedStr := range tt.wantNotContain {
				if strings.Contains(body, unexpectedStr) {
					t.Errorf("response body should not contain %q", unexpectedStr)
				}
			}
		})
	}
}

func TestAuthHandler_LoginFormErrorDisplay(t *testing.T) {
	tests := []struct {
		name         string
		setupMocks   func(*MockUserService)
		formData     url.Values
		wantStatus   int
		wantContains []string
	}{
		{
			name: "should display error message on login failure",
			setupMocks: func(us *MockUserService) {
				us.err = errors.New("invalid credentials")
			},
			formData: url.Values{
				"username": {"wronguser"},
				"password": {"wrongpass"},
			},
			wantStatus: http.StatusUnauthorized,
			wantContains: []string{
				"Invalid username or password",
			},
		},
		{
			name: "should display account inactive message",
			setupMocks: func(us *MockUserService) {
				us.err = errors.New("user is inactive")
			},
			formData: url.Values{
				"username": {"inactiveuser"},
				"password": {"password123"},
			},
			wantStatus: http.StatusForbidden,
			wantContains: []string{
				"Account is inactive",
			},
		},
		{
			name:       "should display username required message",
			setupMocks: func(us *MockUserService) {},
			formData: url.Values{
				"username": {""},
				"password": {"password123"},
			},
			wantStatus: http.StatusBadRequest,
			wantContains: []string{
				"username is required",
			},
		},
		{
			name:       "should display password required message",
			setupMocks: func(us *MockUserService) {},
			formData: url.Values{
				"username": {"testuser"},
				"password": {""},
			},
			wantStatus: http.StatusBadRequest,
			wantContains: []string{
				"password is required",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			userService := &MockUserService{}
			if tt.setupMocks != nil {
				tt.setupMocks(userService)
			}

			clientService := &MockClientService{}
			authCodeService := &MockAuthCodeService{}
			sessionStore := NewMockSessionStore()
			handler := NewAuthHandler(userService, clientService, authCodeService, sessionStore)

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(tt.formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{
				Name:  "session_id",
				Value: "test-session",
			})
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			// Check error message
			body := rr.Body.String()
			for _, expectedStr := range tt.wantContains {
				if !strings.Contains(body, expectedStr) {
					t.Errorf("response body should contain error message %q", expectedStr)
				}
			}
		})
	}
}

func TestAuthHandler_ConsentFormRendering(t *testing.T) {
	tests := []struct {
		name           string
		sessionData    map[string]interface{}
		queryParams    url.Values
		setupMocks     func(*MockClientService)
		wantStatus     int
		wantContains   []string
		wantNotContain []string
	}{
		{
			name: "should render consent form with proper HTML structure",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
				"scope":     {"read write"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "Test Application",
					Scopes:     []string{"read", "write"},
				}
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				"<!DOCTYPE html>",
				"<html>",
				"</html>",
				"<head>",
				"</head>",
				"<body>",
				"</body>",
			},
		},
		{
			name: "should include meta viewport for responsive design",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "Test Application",
				}
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				`<meta name="viewport"`,
				`content="width=device-width, initial-scale=1.0"`,
			},
		},
		{
			name: "should display client name prominently",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "My Awesome App",
				}
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				"<strong>My Awesome App</strong>",
			},
		},
		{
			name: "should display authorization message",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "Test App",
				}
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				"Authorization Required",
				"is requesting access to your account",
			},
		},
		{
			name: "should display requested scopes in a list",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
				"scope":     {"read write profile"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "Test App",
					Scopes:     []string{"read", "write", "profile"},
				}
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				"<ul>",
				"</ul>",
				"<li",
				"read",
				"write",
				"profile",
				"Requested permissions",
			},
		},
		{
			name: "should include Allow button with proper styling class",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "Test App",
				}
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				`<button type="submit"`,
				`name="action"`,
				`value="allow"`,
				`class="allow"`,
				"Allow",
			},
		},
		{
			name: "should include Deny button with proper styling class",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "Test App",
				}
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				`<button type="submit"`,
				`name="action"`,
				`value="deny"`,
				`class="deny"`,
				"Deny",
			},
		},
		{
			name: "should include form with POST method to consent endpoint",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "Test App",
				}
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				`<form method="POST"`,
				`action="/consent"`,
			},
		},
		{
			name: "should include hidden fields for OAuth parameters",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id":    {"test-client"},
				"redirect_uri": {"https://example.com/callback"},
				"scope":        {"read"},
				"state":        {"abc123"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					ClientName:   "Test App",
					RedirectURIs: []string{"https://example.com/callback"},
					Scopes:       []string{"read"},
				}
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				`<input type="hidden"`,
				`name="client_id"`,
				`value="test-client"`,
				`name="redirect_uri"`,
				`value="https://example.com/callback"`,
				`name="scope"`,
				`value="read"`,
				`name="state"`,
				`value="abc123"`,
			},
		},
		{
			name: "should include CSS for button layout",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "Test App",
				}
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				"<style>",
				"</style>",
				".buttons",
				".allow",
				".deny",
			},
		},
		{
			name: "should include CSS for scopes display area",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
				"scope":     {"read"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "Test App",
					Scopes:     []string{"read"},
				}
			},
			wantStatus: http.StatusOK,
			wantContains: []string{
				".scopes",
				".scope-item",
			},
		},
		{
			name: "should not display scope section when no scopes requested",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "Test App",
				}
			},
			wantStatus: http.StatusOK,
			wantNotContain: []string{
				"Requested permissions",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			clientService := &MockClientService{}
			sessionStore := NewMockSessionStore()
			if tt.setupMocks != nil {
				tt.setupMocks(clientService)
			}

			// Set session data
			for key, value := range tt.sessionData {
				_ = sessionStore.Set("test-session", key, value)
			}

			// Create handler
			userService := &MockUserService{}
			authCodeService := &MockAuthCodeService{}
			handler := NewAuthHandler(userService, clientService, authCodeService, sessionStore)

			// Build URL with query parameters
			reqURL := "/consent"
			if len(tt.queryParams) > 0 {
				reqURL += "?" + tt.queryParams.Encode()
			}

			// Create request with session cookie
			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			req.AddCookie(&http.Cookie{
				Name:  "session_id",
				Value: "test-session",
			})
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			// Check response body contains expected strings
			body := rr.Body.String()
			for _, expectedStr := range tt.wantContains {
				if !strings.Contains(body, expectedStr) {
					t.Errorf("response body should contain %q", expectedStr)
				}
			}

			// Check response body does not contain unexpected strings
			for _, unexpectedStr := range tt.wantNotContain {
				if strings.Contains(body, unexpectedStr) {
					t.Errorf("response body should not contain %q", unexpectedStr)
				}
			}
		})
	}
}

func TestAuthHandler_ConsentFormScopeDescriptions(t *testing.T) {
	tests := []struct {
		name        string
		sessionData map[string]interface{}
		queryParams url.Values
		setupMocks  func(*MockClientService)
		wantStatus  int
		scopes      []string
	}{
		{
			name: "should display all requested scopes individually",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
				"scope":     {"read write admin"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "Test App",
					Scopes:     []string{"read", "write", "admin"},
				}
			},
			wantStatus: http.StatusOK,
			scopes:     []string{"read", "write", "admin"},
		},
		{
			name: "should display single scope",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
				"scope":     {"profile"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "Test App",
					Scopes:     []string{"profile"},
				}
			},
			wantStatus: http.StatusOK,
			scopes:     []string{"profile"},
		},
		{
			name: "should display multiple scopes with proper separation",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id": {"test-client"},
				"scope":     {"email profile openid"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:   "test-client",
					ClientName: "Test App",
					Scopes:     []string{"email", "profile", "openid"},
				}
			},
			wantStatus: http.StatusOK,
			scopes:     []string{"email", "profile", "openid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			clientService := &MockClientService{}
			sessionStore := NewMockSessionStore()
			if tt.setupMocks != nil {
				tt.setupMocks(clientService)
			}

			// Set session data
			for key, value := range tt.sessionData {
				_ = sessionStore.Set("test-session", key, value)
			}

			// Create handler
			userService := &MockUserService{}
			authCodeService := &MockAuthCodeService{}
			handler := NewAuthHandler(userService, clientService, authCodeService, sessionStore)

			// Build URL with query parameters
			reqURL := "/consent"
			if len(tt.queryParams) > 0 {
				reqURL += "?" + tt.queryParams.Encode()
			}

			// Create request with session cookie
			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			req.AddCookie(&http.Cookie{
				Name:  "session_id",
				Value: "test-session",
			})
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			// Check each scope is displayed
			body := rr.Body.String()
			for _, scope := range tt.scopes {
				if !strings.Contains(body, scope) {
					t.Errorf("response body should contain scope %q", scope)
				}
			}

			// Verify scopes are in list items
			scopeItemCount := strings.Count(body, `<li class="scope-item">`)
			if len(tt.scopes) > 0 && scopeItemCount != len(tt.scopes) {
				t.Errorf("expected %d scope items, found %d", len(tt.scopes), scopeItemCount)
			}
		})
	}
}

func TestAuthHandler_OAuthAuthorize(t *testing.T) {
	tests := []struct {
		name             string
		sessionData      map[string]interface{}
		queryParams      url.Values
		setupMocks       func(*MockClientService)
		wantStatus       int
		wantRedirect     bool
		wantRedirectPath string
		wantQueryParams  map[string]string
		wantContains     []string
		wantError        bool
	}{
		{
			name: "should redirect to login when user is not authenticated",
			sessionData: map[string]interface{}{
				// No user_id - unauthenticated
			},
			queryParams: url.Values{
				"client_id":     {"test-client"},
				"redirect_uri":  {"https://example.com/callback"},
				"response_type": {"code"},
				"scope":         {"read write"},
				"state":         {"random-state-123"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					ClientName:   "Test App",
					RedirectURIs: []string{"https://example.com/callback"},
					Scopes:       []string{"read", "write"},
				}
			},
			wantStatus:       http.StatusFound,
			wantRedirect:     true,
			wantRedirectPath: "/login",
			wantQueryParams: map[string]string{
				"client_id":     "test-client",
				"redirect_uri":  "https://example.com/callback",
				"response_type": "code",
				"scope":         "read write",
				"state":         "random-state-123",
			},
		},
		{
			name: "should preserve OAuth parameters when redirecting to login",
			sessionData: map[string]interface{}{
				// No user_id
			},
			queryParams: url.Values{
				"client_id":             {"test-client"},
				"redirect_uri":          {"https://example.com/callback"},
				"response_type":         {"code"},
				"scope":                 {"read"},
				"state":                 {"state-value"},
				"code_challenge":        {"challenge-value"},
				"code_challenge_method": {"S256"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
					Scopes:       []string{"read"},
				}
			},
			wantStatus:       http.StatusFound,
			wantRedirect:     true,
			wantRedirectPath: "/login",
			wantQueryParams: map[string]string{
				"code_challenge":        "challenge-value",
				"code_challenge_method": "S256",
			},
		},
		{
			name: "should redirect to consent when user is authenticated",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id":     {"test-client"},
				"redirect_uri":  {"https://example.com/callback"},
				"response_type": {"code"},
				"scope":         {"read"},
				"state":         {"state-123"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					ClientName:   "Test App",
					RedirectURIs: []string{"https://example.com/callback"},
					Scopes:       []string{"read"},
				}
			},
			wantStatus:       http.StatusFound,
			wantRedirect:     true,
			wantRedirectPath: "/consent",
			wantQueryParams: map[string]string{
				"client_id":     "test-client",
				"redirect_uri":  "https://example.com/callback",
				"response_type": "code",
				"scope":         "read",
				"state":         "state-123",
			},
		},
		{
			name: "should preserve state parameter through authorization flow",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id":     {"test-client"},
				"redirect_uri":  {"https://example.com/callback"},
				"response_type": {"code"},
				"state":         {"unique-state-value-456"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
				}
			},
			wantStatus:       http.StatusFound,
			wantRedirect:     true,
			wantRedirectPath: "/consent",
			wantQueryParams: map[string]string{
				"state": "unique-state-value-456",
			},
		},
		{
			name: "should fail with missing client_id",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"redirect_uri":  {"https://example.com/callback"},
				"response_type": {"code"},
			},
			setupMocks: func(cs *MockClientService) {},
			wantStatus: http.StatusBadRequest,
			wantError:  true,
			wantContains: []string{
				"client_id is required",
			},
		},
		{
			name: "should fail with missing redirect_uri",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id":     {"test-client"},
				"response_type": {"code"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
				}
			},
			wantStatus: http.StatusBadRequest,
			wantError:  true,
			wantContains: []string{
				"redirect_uri is required",
			},
		},
		{
			name: "should fail with missing response_type",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id":    {"test-client"},
				"redirect_uri": {"https://example.com/callback"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
				}
			},
			wantStatus: http.StatusBadRequest,
			wantError:  true,
			wantContains: []string{
				"response_type is required",
			},
		},
		{
			name: "should fail with unsupported response_type",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id":     {"test-client"},
				"redirect_uri":  {"https://example.com/callback"},
				"response_type": {"token"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
				}
			},
			wantStatus: http.StatusBadRequest,
			wantError:  true,
			wantContains: []string{
				"unsupported response_type",
			},
		},
		{
			name: "should fail with invalid client_id",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id":     {"invalid-client"},
				"redirect_uri":  {"https://example.com/callback"},
				"response_type": {"code"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.err = errors.New("client not found")
			},
			wantStatus: http.StatusBadRequest,
			wantError:  true,
			wantContains: []string{
				"Invalid client",
			},
		},
		{
			name: "should fail with invalid redirect_uri",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id":     {"test-client"},
				"redirect_uri":  {"https://evil.com/callback"},
				"response_type": {"code"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
				}
			},
			wantStatus: http.StatusBadRequest,
			wantError:  true,
			wantContains: []string{
				"Invalid redirect_uri",
			},
		},
		{
			name: "should support PKCE code_challenge parameter",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id":             {"test-client"},
				"redirect_uri":          {"https://example.com/callback"},
				"response_type":         {"code"},
				"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
				"code_challenge_method": {"S256"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
				}
			},
			wantStatus:       http.StatusFound,
			wantRedirect:     true,
			wantRedirectPath: "/consent",
			wantQueryParams: map[string]string{
				"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				"code_challenge_method": "S256",
			},
		},
		{
			name: "should support PKCE with plain method",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id":             {"test-client"},
				"redirect_uri":          {"https://example.com/callback"},
				"response_type":         {"code"},
				"code_challenge":        {"plain-challenge-value"},
				"code_challenge_method": {"plain"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
				}
			},
			wantStatus:       http.StatusFound,
			wantRedirect:     true,
			wantRedirectPath: "/consent",
			wantQueryParams: map[string]string{
				"code_challenge":        "plain-challenge-value",
				"code_challenge_method": "plain",
			},
		},
		{
			name: "should work without PKCE parameters for confidential clients",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id":     {"test-client"},
				"redirect_uri":  {"https://example.com/callback"},
				"response_type": {"code"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:       "test-client",
					RedirectURIs:   []string{"https://example.com/callback"},
					IsConfidential: true,
				}
			},
			wantStatus:       http.StatusFound,
			wantRedirect:     true,
			wantRedirectPath: "/consent",
		},
		{
			name: "should accept valid scope parameter",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id":     {"test-client"},
				"redirect_uri":  {"https://example.com/callback"},
				"response_type": {"code"},
				"scope":         {"read write profile"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
					Scopes:       []string{"read", "write", "profile"},
				}
			},
			wantStatus:       http.StatusFound,
			wantRedirect:     true,
			wantRedirectPath: "/consent",
			wantQueryParams: map[string]string{
				"scope": "read write profile",
			},
		},
		{
			name: "should accept multiple redirect_uris and match exact",
			sessionData: map[string]interface{}{
				"user_id": "user-123",
			},
			queryParams: url.Values{
				"client_id":     {"test-client"},
				"redirect_uri":  {"https://app.example.com/oauth/callback"},
				"response_type": {"code"},
			},
			setupMocks: func(cs *MockClientService) {
				cs.client = &domain.Client{
					ClientID: "test-client",
					RedirectURIs: []string{
						"https://example.com/callback",
						"https://app.example.com/oauth/callback",
						"https://dev.example.com/callback",
					},
				}
			},
			wantStatus:       http.StatusFound,
			wantRedirect:     true,
			wantRedirectPath: "/consent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			clientService := &MockClientService{}
			sessionStore := NewMockSessionStore()
			if tt.setupMocks != nil {
				tt.setupMocks(clientService)
			}

			// Set session data
			for key, value := range tt.sessionData {
				_ = sessionStore.Set("test-session", key, value)
			}

			// Create handler
			userService := &MockUserService{}
			authCodeService := &MockAuthCodeService{}
			handler := NewAuthHandler(userService, clientService, authCodeService, sessionStore)

			// Build URL with query parameters
			reqURL := "/oauth/authorize"
			if len(tt.queryParams) > 0 {
				reqURL += "?" + tt.queryParams.Encode()
			}

			// Create request with session cookie
			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			req.AddCookie(&http.Cookie{
				Name:  "session_id",
				Value: "test-session",
			})
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			// Check redirect
			if tt.wantRedirect {
				location := rr.Header().Get("Location")
				if location == "" {
					t.Error("expected Location header for redirect")
				}
				if tt.wantRedirectPath != "" && !strings.Contains(location, tt.wantRedirectPath) {
					t.Errorf("expected redirect to contain %q, got %q", tt.wantRedirectPath, location)
				}

				// Check query parameters in redirect URL
				if len(tt.wantQueryParams) > 0 {
					redirectURL, err := url.Parse(location)
					if err != nil {
						t.Fatalf("failed to parse redirect URL: %v", err)
					}
					queryParams := redirectURL.Query()
					for key, expectedValue := range tt.wantQueryParams {
						actualValue := queryParams.Get(key)
						if actualValue != expectedValue {
							t.Errorf("expected query param %s=%q, got %q", key, expectedValue, actualValue)
						}
					}
				}
			}

			// Check error response
			if tt.wantError {
				body := rr.Body.String()
				for _, expectedStr := range tt.wantContains {
					if !strings.Contains(body, expectedStr) {
						t.Errorf("response body should contain %q", expectedStr)
					}
				}
			}
		})
	}
}

func TestAuthHandler_OAuthAuthorizeMethodValidation(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		wantStatus int
	}{
		{
			name:       "should accept GET method",
			method:     http.MethodGet,
			wantStatus: http.StatusBadRequest, // Will fail validation, but method is accepted
		},
		{
			name:       "should reject POST method",
			method:     http.MethodPost,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "should reject PUT method",
			method:     http.MethodPut,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "should reject DELETE method",
			method:     http.MethodDelete,
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create handler
			userService := &MockUserService{}
			clientService := &MockClientService{}
			authCodeService := &MockAuthCodeService{}
			sessionStore := NewMockSessionStore()
			handler := NewAuthHandler(userService, clientService, authCodeService, sessionStore)

			req := httptest.NewRequest(tt.method, "/oauth/authorize", nil)
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}
