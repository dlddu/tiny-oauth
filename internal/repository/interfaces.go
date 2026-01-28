package repository

import (
	"context"
	"errors"

	"github.com/dlddu/tiny-oauth/internal/domain"
)

var (
	ErrClientNotFound = errors.New("client not found")
)

// ClientRepository defines the interface for client data access
type ClientRepository interface {
	Create(ctx context.Context, client *domain.Client) error
	GetByClientID(ctx context.Context, clientID string) (*domain.Client, error)
	Delete(ctx context.Context, clientID string) error
}
