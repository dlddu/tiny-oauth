package service

import (
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTService handles JWT token generation and verification
type JWTService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
}

// NewJWTService creates a new JWT service
func NewJWTService(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, issuer string) *JWTService {
	return &JWTService{
		privateKey: privateKey,
		publicKey:  publicKey,
		issuer:     issuer,
	}
}

// GenerateAccessToken generates a JWT access token with RS256
func (s *JWTService) GenerateAccessToken(clientID string, scopes []string, expiresAt time.Time) (string, error) {
	now := time.Now()

	// Create JWT claims
	claims := jwt.MapClaims{
		"iss": s.issuer,
		"sub": clientID,
		"aud": s.issuer,
		"exp": expiresAt.Unix(),
		"iat": now.Unix(),
		"jti": uuid.New().String(),
	}

	// Add scope claim if scopes are provided
	if len(scopes) > 0 {
		claims["scope"] = strings.Join(scopes, " ")
	} else {
		claims["scope"] = ""
	}

	// Create token with RS256 algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Sign token with private key
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// VerifyAccessToken verifies a JWT access token and returns its claims
func (s *JWTService) VerifyAccessToken(tokenString string) (jwt.MapClaims, error) {
	// Parse and verify token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to extract claims")
	}

	return claims, nil
}
