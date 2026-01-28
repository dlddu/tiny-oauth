package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenManager manages JWT token generation and validation
type TokenManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	kid        string
}

// NewTokenManager creates a new TokenManager
func NewTokenManager(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, issuer string) (*TokenManager, error) {
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}
	if publicKey == nil {
		return nil, errors.New("public key is required")
	}
	if issuer == "" {
		return nil, errors.New("issuer is required")
	}

	return &TokenManager{
		privateKey: privateKey,
		publicKey:  publicKey,
		issuer:     issuer,
	}, nil
}

// SetKID sets the Key ID (kid) for the token header
func (tm *TokenManager) SetKID(kid string) error {
	tm.kid = kid
	return nil
}

// GenerateToken generates a JWT token with the specified claims
func (tm *TokenManager) GenerateToken(claims TokenClaims) (string, error) {
	// Validate claims
	if err := claims.Validate(); err != nil {
		return "", err
	}

	now := time.Now()
	expiresAt := now.Add(claims.TTL)

	// Create JWT claims
	jwtClaims := jwt.MapClaims{
		"iss": tm.issuer,
		"sub": claims.Subject,
		"iat": now.Unix(),
		"exp": expiresAt.Unix(),
		"jti": uuid.New().String(),
	}

	// Add optional claims
	if len(claims.Audience) > 0 {
		jwtClaims["aud"] = claims.Audience
	}

	if len(claims.Scopes) > 0 {
		jwtClaims["scope"] = strings.Join(claims.Scopes, " ")
	}

	if claims.ClientID != "" {
		jwtClaims["client_id"] = claims.ClientID
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)

	// Set KID in header if available
	if tm.kid != "" {
		token.Header["kid"] = tm.kid
	}

	// Sign token
	tokenString, err := token.SignedString(tm.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates a JWT token and returns the token information
func (tm *TokenManager) ValidateToken(tokenString string) (*TokenInfo, error) {
	if tokenString == "" {
		return nil, errors.New("empty token")
	}

	// Parse and validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tm.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("token is invalid")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims format")
	}

	// Parse token info
	tokenInfo := &TokenInfo{}

	// Required claims
	if sub, ok := claims["sub"].(string); ok {
		tokenInfo.Subject = sub
	} else {
		return nil, errors.New("missing subject claim")
	}

	if iss, ok := claims["iss"].(string); ok {
		tokenInfo.Issuer = iss
	}

	if jti, ok := claims["jti"].(string); ok {
		tokenInfo.JTI = jti
	}

	// Timestamps
	if iat, ok := claims["iat"].(float64); ok {
		tokenInfo.IssuedAt = time.Unix(int64(iat), 0)
	}

	if exp, ok := claims["exp"].(float64); ok {
		tokenInfo.ExpiresAt = time.Unix(int64(exp), 0)
	}

	// Optional claims
	if aud, ok := claims["aud"].([]interface{}); ok {
		tokenInfo.Audience = make([]string, len(aud))
		for i, a := range aud {
			if audStr, ok := a.(string); ok {
				tokenInfo.Audience[i] = audStr
			}
		}
	} else if audStr, ok := claims["aud"].(string); ok {
		tokenInfo.Audience = []string{audStr}
	}

	if scope, ok := claims["scope"].(string); ok {
		if scope != "" {
			tokenInfo.Scopes = strings.Split(scope, " ")
		}
	}

	if clientID, ok := claims["client_id"].(string); ok {
		tokenInfo.ClientID = clientID
	}

	return tokenInfo, nil
}
