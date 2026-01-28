package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewTokenManager(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	tests := []struct {
		name       string
		privateKey *rsa.PrivateKey
		publicKey  *rsa.PublicKey
		issuer     string
		wantErr    bool
	}{
		{
			name:       "should create token manager with valid keys",
			privateKey: privateKey,
			publicKey:  publicKey,
			issuer:     "http://localhost:8080",
			wantErr:    false,
		},
		{
			name:       "should fail with nil private key",
			privateKey: nil,
			publicKey:  publicKey,
			issuer:     "http://localhost:8080",
			wantErr:    true,
		},
		{
			name:       "should fail with nil public key",
			privateKey: privateKey,
			publicKey:  nil,
			issuer:     "http://localhost:8080",
			wantErr:    true,
		},
		{
			name:       "should fail with empty issuer",
			privateKey: privateKey,
			publicKey:  publicKey,
			issuer:     "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tm, err := NewTokenManager(tt.privateKey, tt.publicKey, tt.issuer)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tm == nil {
				t.Error("token manager is nil")
			}
		})
	}
}

func TestGenerateToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	tm, err := NewTokenManager(privateKey, publicKey, "http://localhost:8080")
	if err != nil {
		t.Fatalf("failed to create token manager: %v", err)
	}

	tests := []struct {
		name      string
		claims    TokenClaims
		wantErr   bool
		errReason string
	}{
		{
			name: "should generate valid token with all claims",
			claims: TokenClaims{
				Subject:  "user-123",
				Audience: []string{"api.example.com"},
				Scopes:   []string{"read", "write"},
				ClientID: "client-456",
				TTL:      15 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "should generate token with minimal claims",
			claims: TokenClaims{
				Subject: "user-123",
				TTL:     15 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "should fail with empty subject",
			claims: TokenClaims{
				Subject: "",
				TTL:     15 * time.Minute,
			},
			wantErr:   true,
			errReason: "subject is required",
		},
		{
			name: "should fail with zero TTL",
			claims: TokenClaims{
				Subject: "user-123",
				TTL:     0,
			},
			wantErr:   true,
			errReason: "TTL must be positive",
		},
		{
			name: "should fail with negative TTL",
			claims: TokenClaims{
				Subject: "user-123",
				TTL:     -1 * time.Minute,
			},
			wantErr:   true,
			errReason: "TTL must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString, err := tm.GenerateToken(tt.claims)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tokenString == "" {
				t.Error("token string is empty")
			}

			// Verify token can be parsed
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				return publicKey, nil
			})

			if err != nil {
				t.Errorf("failed to parse generated token: %v", err)
				return
			}

			if !token.Valid {
				t.Error("generated token is invalid")
			}

			// Verify algorithm
			if token.Method.Alg() != "RS256" {
				t.Errorf("expected algorithm RS256, got %s", token.Method.Alg())
			}

			// Verify claims
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				t.Error("failed to extract claims from token")
				return
			}

			if claims["sub"] != tt.claims.Subject {
				t.Errorf("expected subject %s, got %v", tt.claims.Subject, claims["sub"])
			}

			if claims["iss"] != "http://localhost:8080" {
				t.Errorf("expected issuer http://localhost:8080, got %v", claims["iss"])
			}

			// Verify JTI exists
			if _, ok := claims["jti"].(string); !ok {
				t.Error("JTI claim is missing or not a string")
			}

			// Verify timestamps
			if _, ok := claims["iat"].(float64); !ok {
				t.Error("iat claim is missing or not a number")
			}
			if _, ok := claims["exp"].(float64); !ok {
				t.Error("exp claim is missing or not a number")
			}

			// Verify optional claims
			if tt.claims.ClientID != "" {
				if claims["client_id"] != tt.claims.ClientID {
					t.Errorf("expected client_id %s, got %v", tt.claims.ClientID, claims["client_id"])
				}
			}

			if len(tt.claims.Scopes) > 0 {
				if claims["scope"] == nil {
					t.Error("scope claim is missing")
				}
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	tm, err := NewTokenManager(privateKey, publicKey, "http://localhost:8080")
	if err != nil {
		t.Fatalf("failed to create token manager: %v", err)
	}

	// Generate a valid token for testing
	validToken, err := tm.GenerateToken(TokenClaims{
		Subject:  "user-123",
		Audience: []string{"api.example.com"},
		Scopes:   []string{"read"},
		ClientID: "client-456",
		TTL:      15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to generate valid token: %v", err)
	}

	// Generate an expired token
	expiredToken, err := tm.GenerateToken(TokenClaims{
		Subject: "user-123",
		TTL:     -1 * time.Hour, // Already expired
	})
	if err != nil {
		t.Fatalf("failed to generate expired token: %v", err)
	}

	// Generate token with wrong key
	wrongPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate wrong key: %v", err)
	}
	wrongPublicKey := &wrongPrivateKey.PublicKey
	wrongTM, err := NewTokenManager(wrongPrivateKey, wrongPublicKey, "http://localhost:8080")
	if err != nil {
		t.Fatalf("failed to create wrong token manager: %v", err)
	}
	wrongKeyToken, err := wrongTM.GenerateToken(TokenClaims{
		Subject: "user-123",
		TTL:     15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to generate token with wrong key: %v", err)
	}

	tests := []struct {
		name        string
		tokenString string
		wantErr     bool
		errReason   string
	}{
		{
			name:        "should validate correct token",
			tokenString: validToken,
			wantErr:     false,
		},
		{
			name:        "should fail with expired token",
			tokenString: expiredToken,
			wantErr:     true,
			errReason:   "token is expired",
		},
		{
			name:        "should fail with token signed by wrong key",
			tokenString: wrongKeyToken,
			wantErr:     true,
			errReason:   "signature verification failed",
		},
		{
			name:        "should fail with malformed token",
			tokenString: "not.a.valid.jwt",
			wantErr:     true,
			errReason:   "malformed token",
		},
		{
			name:        "should fail with empty token",
			tokenString: "",
			wantErr:     true,
			errReason:   "empty token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := tm.ValidateToken(tt.tokenString)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if claims == nil {
				t.Error("claims are nil")
				return
			}

			// Verify claims structure
			if claims.Subject == "" {
				t.Error("subject claim is empty")
			}
			if claims.Issuer == "" {
				t.Error("issuer claim is empty")
			}
			if claims.JTI == "" {
				t.Error("JTI claim is empty")
			}
			if claims.IssuedAt.IsZero() {
				t.Error("issued at time is zero")
			}
			if claims.ExpiresAt.IsZero() {
				t.Error("expires at time is zero")
			}
		})
	}
}

func TestTokenWithKID(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	tm, err := NewTokenManager(privateKey, publicKey, "http://localhost:8080")
	if err != nil {
		t.Fatalf("failed to create token manager: %v", err)
	}

	tests := []struct {
		name   string
		kid    string
		claims TokenClaims
	}{
		{
			name: "should generate token with KID",
			kid:  "key-2024-01",
			claims: TokenClaims{
				Subject: "user-123",
				TTL:     15 * time.Minute,
			},
		},
		{
			name: "should generate token without KID",
			kid:  "",
			claims: TokenClaims{
				Subject: "user-123",
				TTL:     15 * time.Minute,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set KID if provided
			if tt.kid != "" {
				err := tm.SetKID(tt.kid)
				if err != nil {
					t.Fatalf("failed to set KID: %v", err)
				}
			}

			tokenString, err := tm.GenerateToken(tt.claims)
			if err != nil {
				t.Fatalf("failed to generate token: %v", err)
			}

			// Parse token to check KID
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				return publicKey, nil
			})
			if err != nil {
				t.Fatalf("failed to parse token: %v", err)
			}

			if tt.kid != "" {
				// KID should be present in header
				if token.Header["kid"] != tt.kid {
					t.Errorf("expected KID %s, got %v", tt.kid, token.Header["kid"])
				}
			}
		})
	}
}

func TestTokenClaims_Validate(t *testing.T) {
	tests := []struct {
		name    string
		claims  TokenClaims
		wantErr bool
	}{
		{
			name: "should pass with valid claims",
			claims: TokenClaims{
				Subject: "user-123",
				TTL:     15 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "should fail with empty subject",
			claims: TokenClaims{
				Subject: "",
				TTL:     15 * time.Minute,
			},
			wantErr: true,
		},
		{
			name: "should fail with zero TTL",
			claims: TokenClaims{
				Subject: "user-123",
				TTL:     0,
			},
			wantErr: true,
		},
		{
			name: "should fail with negative TTL",
			claims: TokenClaims{
				Subject: "user-123",
				TTL:     -1 * time.Minute,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.claims.Validate()

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestTokenRotation(t *testing.T) {
	// Test key rotation scenario
	oldPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate old key: %v", err)
	}
	oldPublicKey := &oldPrivateKey.PublicKey

	newPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate new key: %v", err)
	}
	newPublicKey := &newPrivateKey.PublicKey

	// Create token with old key
	oldTM, err := NewTokenManager(oldPrivateKey, oldPublicKey, "http://localhost:8080")
	if err != nil {
		t.Fatalf("failed to create old token manager: %v", err)
	}
	err = oldTM.SetKID("key-old")
	if err != nil {
		t.Fatalf("failed to set old KID: %v", err)
	}

	oldToken, err := oldTM.GenerateToken(TokenClaims{
		Subject: "user-123",
		TTL:     15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to generate old token: %v", err)
	}

	// Create token with new key
	newTM, err := NewTokenManager(newPrivateKey, newPublicKey, "http://localhost:8080")
	if err != nil {
		t.Fatalf("failed to create new token manager: %v", err)
	}
	err = newTM.SetKID("key-new")
	if err != nil {
		t.Fatalf("failed to set new KID: %v", err)
	}

	newToken, err := newTM.GenerateToken(TokenClaims{
		Subject: "user-123",
		TTL:     15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to generate new token: %v", err)
	}

	t.Run("should validate token with new key", func(t *testing.T) {
		claims, err := newTM.ValidateToken(newToken)
		if err != nil {
			t.Errorf("failed to validate new token: %v", err)
		}
		if claims == nil {
			t.Error("claims are nil")
		}
	})

	t.Run("should fail to validate old token with new key", func(t *testing.T) {
		_, err := newTM.ValidateToken(oldToken)
		if err == nil {
			t.Error("expected error when validating old token with new key")
		}
	})

	t.Run("should validate old token with old key", func(t *testing.T) {
		claims, err := oldTM.ValidateToken(oldToken)
		if err != nil {
			t.Errorf("failed to validate old token: %v", err)
		}
		if claims == nil {
			t.Error("claims are nil")
		}
	})
}
