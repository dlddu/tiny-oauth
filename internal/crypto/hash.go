package crypto

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrEmptyPassword = errors.New("password cannot be empty")
	ErrEmptyHash     = errors.New("hash cannot be empty")
)

// HashPassword hashes a password using bcrypt with default cost
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", ErrEmptyPassword
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// VerifyPassword verifies a password against a bcrypt hash using constant-time comparison
func VerifyPassword(hash, password string) error {
	if hash == "" {
		return ErrEmptyHash
	}
	if password == "" {
		return ErrEmptyPassword
	}

	// bcrypt.CompareHashAndPassword uses constant-time comparison internally
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
