package repository

import (
	"context"
	"errors"

	"github.com/dlddu/tiny-oauth/internal/domain"
)

var (
	ErrClientNotFound = errors.New("client not found")
	ErrUserNotFound   = errors.New("user not found")
)

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
