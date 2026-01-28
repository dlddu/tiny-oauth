package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/dlddu/tiny-oauth/internal/domain"
	"github.com/lib/pq"
)

type pgClientRepository struct {
	db *sql.DB
}

// NewClientRepository creates a new PostgreSQL-based ClientRepository
func NewClientRepository(db *sql.DB) ClientRepository {
	return &pgClientRepository{db: db}
}

// Create creates a new client in the database
func (r *pgClientRepository) Create(ctx context.Context, client *domain.Client) error {
	query := `
		INSERT INTO clients (
			id, client_id, client_secret_hash, client_name,
			redirect_uris, grant_types, scopes, is_confidential,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		client.ID,
		client.ClientID,
		client.ClientSecretHash,
		client.ClientName,
		pq.Array(client.RedirectURIs),
		pq.Array(client.GrantTypes),
		pq.Array(client.Scopes),
		client.IsConfidential,
		client.CreatedAt,
		client.UpdatedAt,
	)

	return err
}

// GetByClientID retrieves a client by its client_id
func (r *pgClientRepository) GetByClientID(ctx context.Context, clientID string) (*domain.Client, error) {
	if clientID == "" {
		return nil, errors.New("client_id cannot be empty")
	}

	query := `
		SELECT
			id, client_id, client_secret_hash, client_name,
			redirect_uris, grant_types, scopes, is_confidential,
			created_at, updated_at
		FROM clients
		WHERE client_id = $1
	`

	client := &domain.Client{}
	err := r.db.QueryRowContext(ctx, query, clientID).Scan(
		&client.ID,
		&client.ClientID,
		&client.ClientSecretHash,
		&client.ClientName,
		pq.Array(&client.RedirectURIs),
		pq.Array(&client.GrantTypes),
		pq.Array(&client.Scopes),
		&client.IsConfidential,
		&client.CreatedAt,
		&client.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}

	return client, nil
}

// Delete removes a client from the database
func (r *pgClientRepository) Delete(ctx context.Context, clientID string) error {
	query := `DELETE FROM clients WHERE client_id = $1`

	_, err := r.db.ExecContext(ctx, query, clientID)
	return err
}
