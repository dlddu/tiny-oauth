package service

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTService_GenerateAccessToken_ClientCredentials(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	service := NewJWTService(privateKey, &privateKey.PublicKey, "http://localhost:8080")

	clientID := "test_client_id"
	scopes := []string{"read", "write"}
	expiresAt := time.Now().Add(15 * time.Minute)

	// Act
	tokenString, err := service.GenerateAccessToken(clientID, scopes, expiresAt)

	// Assert
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if tokenString == "" {
		t.Error("expected token string, got empty")
	}

	// Parse and validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			t.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &privateKey.PublicKey, nil
	})

	if err != nil {
		t.Errorf("failed to parse token: %v", err)
	}

	if !token.Valid {
		t.Error("token is not valid")
	}

	// Verify claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("failed to get claims")
	}

	// Check client_id (sub)
	if sub, ok := claims["sub"].(string); !ok || sub != clientID {
		t.Errorf("expected sub '%s', got '%v'", clientID, claims["sub"])
	}

	// Check issuer
	if iss, ok := claims["iss"].(string); !ok || iss != "http://localhost:8080" {
		t.Errorf("expected iss 'http://localhost:8080', got '%v'", claims["iss"])
	}

	// Check scopes
	if scope, ok := claims["scope"].(string); !ok || scope != "read write" {
		t.Errorf("expected scope 'read write', got '%v'", claims["scope"])
	}

	// Check exp
	if exp, ok := claims["exp"].(float64); !ok {
		t.Error("expected exp claim")
	} else {
		expTime := time.Unix(int64(exp), 0)
		if expTime.Before(time.Now()) {
			t.Error("token is already expired")
		}
	}

	// Check iat (issued at)
	if iat, ok := claims["iat"].(float64); !ok {
		t.Error("expected iat claim")
	} else {
		iatTime := time.Unix(int64(iat), 0)
		if iatTime.After(time.Now()) {
			t.Error("iat is in the future")
		}
	}

	// Check jti (JWT ID) exists and is unique
	if jti, ok := claims["jti"].(string); !ok || jti == "" {
		t.Error("expected jti claim")
	}
}

func TestJWTService_GenerateAccessToken_EmptyScopes(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	service := NewJWTService(privateKey, &privateKey.PublicKey, "http://localhost:8080")

	clientID := "test_client_id"
	scopes := []string{} // Empty scopes
	expiresAt := time.Now().Add(15 * time.Minute)

	// Act
	tokenString, err := service.GenerateAccessToken(clientID, scopes, expiresAt)

	// Assert
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})

	if err != nil {
		t.Errorf("failed to parse token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("failed to get claims")
	}

	// Check scope claim - should be empty string or not present
	if scope, ok := claims["scope"].(string); ok && scope != "" {
		t.Errorf("expected empty scope, got '%s'", scope)
	}
}

func TestJWTService_GenerateAccessToken_UniqueJTI(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	service := NewJWTService(privateKey, &privateKey.PublicKey, "http://localhost:8080")

	clientID := "test_client_id"
	scopes := []string{"read"}
	expiresAt := time.Now().Add(15 * time.Minute)

	// Act - Generate two tokens
	token1, err := service.GenerateAccessToken(clientID, scopes, expiresAt)
	if err != nil {
		t.Fatalf("failed to generate first token: %v", err)
	}

	token2, err := service.GenerateAccessToken(clientID, scopes, expiresAt)
	if err != nil {
		t.Fatalf("failed to generate second token: %v", err)
	}

	// Parse tokens
	parsed1, _ := jwt.Parse(token1, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	parsed2, _ := jwt.Parse(token2, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})

	claims1 := parsed1.Claims.(jwt.MapClaims)
	claims2 := parsed2.Claims.(jwt.MapClaims)

	jti1 := claims1["jti"].(string)
	jti2 := claims2["jti"].(string)

	// Assert - JTI should be unique
	if jti1 == jti2 {
		t.Error("expected unique jti for each token")
	}
}

func TestJWTService_GenerateAccessToken_RS256Algorithm(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	service := NewJWTService(privateKey, &privateKey.PublicKey, "http://localhost:8080")

	clientID := "test_client_id"
	scopes := []string{"read"}
	expiresAt := time.Now().Add(15 * time.Minute)

	// Act
	tokenString, err := service.GenerateAccessToken(clientID, scopes, expiresAt)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Parse token without validation to check header
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	// Assert - Algorithm should be RS256
	if alg, ok := token.Header["alg"].(string); !ok || alg != "RS256" {
		t.Errorf("expected algorithm 'RS256', got '%v'", token.Header["alg"])
	}

	if typ, ok := token.Header["typ"].(string); !ok || typ != "JWT" {
		t.Errorf("expected type 'JWT', got '%v'", token.Header["typ"])
	}
}

func TestJWTService_VerifyAccessToken_Valid(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	service := NewJWTService(privateKey, &privateKey.PublicKey, "http://localhost:8080")

	clientID := "test_client_id"
	scopes := []string{"read"}
	expiresAt := time.Now().Add(15 * time.Minute)

	tokenString, err := service.GenerateAccessToken(clientID, scopes, expiresAt)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Act
	claims, err := service.VerifyAccessToken(tokenString)

	// Assert
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if claims == nil {
		t.Fatal("expected claims, got nil")
	}

	if sub, ok := claims["sub"].(string); !ok || sub != clientID {
		t.Errorf("expected sub '%s', got '%v'", clientID, claims["sub"])
	}
}

func TestJWTService_VerifyAccessToken_Expired(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	service := NewJWTService(privateKey, &privateKey.PublicKey, "http://localhost:8080")

	clientID := "test_client_id"
	scopes := []string{"read"}
	expiresAt := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago

	tokenString, err := service.GenerateAccessToken(clientID, scopes, expiresAt)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Act
	claims, err := service.VerifyAccessToken(tokenString)

	// Assert
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}

	if claims != nil {
		t.Errorf("expected nil claims, got %v", claims)
	}
}

func TestJWTService_VerifyAccessToken_InvalidSignature(t *testing.T) {
	// Arrange
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key 1: %v", err)
	}

	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key 2: %v", err)
	}

	// Generate token with one key
	service1 := NewJWTService(privateKey1, &privateKey1.PublicKey, "http://localhost:8080")
	tokenString, err := service1.GenerateAccessToken("test_client", []string{"read"}, time.Now().Add(15*time.Minute))
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Try to verify with different key
	service2 := NewJWTService(privateKey2, &privateKey2.PublicKey, "http://localhost:8080")

	// Act
	claims, err := service2.VerifyAccessToken(tokenString)

	// Assert
	if err == nil {
		t.Error("expected error for invalid signature, got nil")
	}

	if claims != nil {
		t.Errorf("expected nil claims, got %v", claims)
	}
}
