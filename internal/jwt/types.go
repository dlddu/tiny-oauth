package jwt

import (
	"errors"
	"time"
)

// TokenClaims represents the claims used to generate a JWT token
type TokenClaims struct {
	Subject  string        `json:"sub"`
	Audience []string      `json:"aud,omitempty"`
	Scopes   []string      `json:"scopes,omitempty"`
	ClientID string        `json:"client_id,omitempty"`
	TTL      time.Duration `json:"-"`
}

// Validate validates the token claims
func (tc TokenClaims) Validate() error {
	if tc.Subject == "" {
		return errors.New("subject is required")
	}
	if tc.TTL <= 0 {
		return errors.New("TTL must be positive")
	}
	return nil
}

// TokenInfo represents the parsed and validated token information
type TokenInfo struct {
	Subject   string    `json:"sub"`
	Issuer    string    `json:"iss"`
	Audience  []string  `json:"aud,omitempty"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
	JTI       string    `json:"jti"`
	Scopes    []string  `json:"scopes,omitempty"`
	ClientID  string    `json:"client_id,omitempty"`
}
