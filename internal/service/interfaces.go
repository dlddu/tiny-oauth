package service

import (
	"context"
	"errors"

	"github.com/dlddu/tiny-oauth/internal/domain"
)

var (
	ErrEmptyClientID      = errors.New("client_id cannot be empty")
	ErrEmptyClientName    = errors.New("client_name cannot be empty")
	ErrEmptySecret        = errors.New("client_secret is required for confidential clients")
	ErrEmptyRedirectURIs  = errors.New("redirect_uris cannot be empty")
	ErrEmptyGrantTypes    = errors.New("grant_types cannot be empty")
	ErrInvalidGrantType   = errors.New("invalid grant type")
	ErrInvalidCredentials = errors.New("invalid client credentials")
)

// Hasher defines the interface for password hashing operations
type Hasher interface {
	HashPassword(password string) (string, error)
	VerifyPassword(hash, password string) error
}

// ClientRepository defines the interface for client data access
type ClientRepository interface {
	Create(ctx context.Context, client *domain.Client) error
	GetByClientID(ctx context.Context, clientID string) (*domain.Client, error)
	Delete(ctx context.Context, clientID string) error
}
