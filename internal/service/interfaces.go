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
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrUserInactive       = errors.New("user is inactive")
	ErrInvalidEmail       = errors.New("invalid email format")
	ErrInvalidUsername    = errors.New("invalid username format")
	ErrSamePassword       = errors.New("new password must be different from old password")
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

// UserRepository defines the interface for user data access
type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByUsername(ctx context.Context, username string) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByID(ctx context.Context, id string) (*domain.User, error)
	Update(ctx context.Context, user *domain.User) error
	Delete(ctx context.Context, id string) error
}

// UserService defines the interface for user business logic
type UserService interface {
	Register(ctx context.Context, username, email, password, firstName, lastName string) (*domain.User, error)
	Authenticate(ctx context.Context, username, password string) (*domain.User, error)
	GetByID(ctx context.Context, id string) (*domain.User, error)
	UpdatePassword(ctx context.Context, userID, oldPassword, newPassword string) error
	ValidateEmail(email string) error
	ValidateUsername(username string) error
}
