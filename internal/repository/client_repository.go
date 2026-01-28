package repository

import (
	"context"
	"fmt"

	"github.com/dlddu/tiny-oauth/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ClientRepository handles client data persistence
type ClientRepository struct {
	db *pgxpool.Pool
}

// NewClientRepository creates a new client repository
func NewClientRepository(db *pgxpool.Pool) *ClientRepository {
	return &ClientRepository{
		db: db,
	}
}

// GetByClientID retrieves a client by client_id
func (r *ClientRepository) GetByClientID(ctx context.Context, clientID string) (*domain.Client, error) {
	if r.db == nil {
		// For tests without DB
		return nil, nil
	}

	query := `
		SELECT id, client_id, client_secret_hash, client_name, redirect_uris,
		       grant_types, scopes, is_confidential, created_at, updated_at
		FROM clients
		WHERE client_id = $1 AND deleted_at IS NULL
	`

	var client domain.Client
	var redirectURIs, grantTypes, scopes []string

	err := r.db.QueryRow(ctx, query, clientID).Scan(
		&client.ID,
		&client.ClientID,
		&client.ClientSecretHash,
		&client.ClientName,
		&redirectURIs,
		&grantTypes,
		&scopes,
		&client.IsConfidential,
		&client.CreatedAt,
		&client.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query client: %w", err)
	}

	client.RedirectURIs = redirectURIs
	client.GrantTypes = grantTypes
	client.Scopes = scopes

	return &client, nil
}

// Create creates a new client
func (r *ClientRepository) Create(ctx context.Context, client *domain.Client) error {
	if r.db == nil {
		return nil
	}

	query := `
		INSERT INTO clients (client_id, client_secret_hash, client_name, redirect_uris,
		                     grant_types, scopes, is_confidential, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id
	`

	err := r.db.QueryRow(ctx, query,
		client.ClientID,
		client.ClientSecretHash,
		client.ClientName,
		client.RedirectURIs,
		client.GrantTypes,
		client.Scopes,
		client.IsConfidential,
		client.CreatedAt,
		client.UpdatedAt,
	).Scan(&client.ID)

	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	return nil
}

// Update updates an existing client
func (r *ClientRepository) Update(ctx context.Context, client *domain.Client) error {
	if r.db == nil {
		return nil
	}

	query := `
		UPDATE clients
		SET client_name = $1, redirect_uris = $2, grant_types = $3,
		    scopes = $4, updated_at = $5
		WHERE id = $6 AND deleted_at IS NULL
	`

	_, err := r.db.Exec(ctx, query,
		client.ClientName,
		client.RedirectURIs,
		client.GrantTypes,
		client.Scopes,
		client.UpdatedAt,
		client.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update client: %w", err)
	}

	return nil
}

// Delete soft deletes a client
func (r *ClientRepository) Delete(ctx context.Context, clientID string) error {
	if r.db == nil {
		return nil
	}

	query := `
		UPDATE clients
		SET deleted_at = NOW()
		WHERE client_id = $1 AND deleted_at IS NULL
	`

	_, err := r.db.Exec(ctx, query, clientID)
	if err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}

	return nil
}

// List retrieves a list of clients with pagination
func (r *ClientRepository) List(ctx context.Context, limit, offset int) ([]*domain.Client, error) {
	if r.db == nil {
		return []*domain.Client{}, nil
	}

	query := `
		SELECT id, client_id, client_secret_hash, client_name, redirect_uris,
		       grant_types, scopes, is_confidential, created_at, updated_at
		FROM clients
		WHERE deleted_at IS NULL
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list clients: %w", err)
	}
	defer rows.Close()

	var clients []*domain.Client

	for rows.Next() {
		var client domain.Client
		var redirectURIs, grantTypes, scopes []string

		err := rows.Scan(
			&client.ID,
			&client.ClientID,
			&client.ClientSecretHash,
			&client.ClientName,
			&redirectURIs,
			&grantTypes,
			&scopes,
			&client.IsConfidential,
			&client.CreatedAt,
			&client.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan client: %w", err)
		}

		client.RedirectURIs = redirectURIs
		client.GrantTypes = grantTypes
		client.Scopes = scopes

		clients = append(clients, &client)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return clients, nil
}
