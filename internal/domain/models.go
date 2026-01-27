package domain

import (
	"time"
)

// Client represents an OAuth 2.0 client application
type Client struct {
	ID               string    `json:"id"`
	ClientID         string    `json:"client_id"`
	ClientSecretHash string    `json:"-"`
	ClientName       string    `json:"client_name"`
	RedirectURIs     []string  `json:"redirect_uris"`
	GrantTypes       []string  `json:"grant_types"`
	Scopes           []string  `json:"scopes"`
	IsConfidential   bool      `json:"is_confidential"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// User represents a resource owner
type User struct {
	ID            string    `json:"id"`
	Username      string    `json:"username"`
	Email         string    `json:"email"`
	PasswordHash  string    `json:"-"`
	FirstName     string    `json:"first_name,omitempty"`
	LastName      string    `json:"last_name,omitempty"`
	IsActive      bool      `json:"is_active"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// AuthorizationCode represents an OAuth 2.0 authorization code
type AuthorizationCode struct {
	ID                  string    `json:"id"`
	CodeHash            string    `json:"-"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scopes              []string  `json:"scopes"`
	CodeChallenge       string    `json:"-"`
	CodeChallengeMethod string    `json:"-"`
	ExpiresAt           time.Time `json:"expires_at"`
	CreatedAt           time.Time `json:"created_at"`
	UsedAt              *time.Time `json:"used_at,omitempty"`
}

// RefreshToken represents an OAuth 2.0 refresh token
type RefreshToken struct {
	ID            string     `json:"id"`
	TokenHash     string     `json:"-"`
	ClientID      string     `json:"client_id"`
	UserID        string     `json:"user_id"`
	Scopes        []string   `json:"scopes"`
	ExpiresAt     time.Time  `json:"expires_at"`
	CreatedAt     time.Time  `json:"created_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedReason string     `json:"revoked_reason,omitempty"`
	ParentTokenID *string    `json:"parent_token_id,omitempty"`
}

// TokenBlacklist represents a revoked JWT access token
type TokenBlacklist struct {
	ID        string    `json:"id"`
	JTI       string    `json:"jti"`
	UserID    *string   `json:"user_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason,omitempty"`
}
