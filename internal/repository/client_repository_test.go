package repository

import (
	"context"
	"testing"
	"time"

	"github.com/dlddu/tiny-oauth/internal/domain"
)

// TestClientRepository_GetByClientID tests retrieving a client by client_id
func TestClientRepository_GetByClientID_Success(t *testing.T) {
	// This test requires a database connection
	// For now, we'll skip if no DB available
	if testing.Short() {
		t.Skip("Skipping database integration test")
	}

	// Arrange
	ctx := context.Background()
	repo := NewClientRepository(nil) // Will need actual DB connection

	// This will fail until implementation exists
	client, err := repo.GetByClientID(ctx, "test_client_id")

	// Assert
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if client == nil {
		t.Error("expected client, got nil")
	}
}

func TestClientRepository_GetByClientID_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test")
	}

	// Arrange
	ctx := context.Background()
	repo := NewClientRepository(nil)

	// Act
	client, err := repo.GetByClientID(ctx, "non_existent_client")

	// Assert
	if err != nil {
		// Should return nil without error when not found
		t.Errorf("expected no error for not found, got %v", err)
	}

	if client != nil {
		t.Errorf("expected nil client, got %v", client)
	}
}

func TestClientRepository_Create_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test")
	}

	// Arrange
	ctx := context.Background()
	repo := NewClientRepository(nil)

	client := &domain.Client{
		ClientID:         "new_client_id",
		ClientSecretHash: "$2a$10$hashedpassword",
		ClientName:       "Test Client",
		RedirectURIs:     []string{"http://localhost:3000/callback"},
		GrantTypes:       []string{"client_credentials", "authorization_code"},
		Scopes:           []string{"read", "write"},
		IsConfidential:   true,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// Act
	err := repo.Create(ctx, client)

	// Assert
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if client.ID == "" {
		t.Error("expected ID to be set after creation")
	}
}

func TestClientRepository_Update_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test")
	}

	// Arrange
	ctx := context.Background()
	repo := NewClientRepository(nil)

	client := &domain.Client{
		ID:           "existing_id",
		ClientID:     "existing_client_id",
		ClientName:   "Updated Client Name",
		RedirectURIs: []string{"http://localhost:3000/callback", "http://localhost:3000/callback2"},
		GrantTypes:   []string{"client_credentials"},
		Scopes:       []string{"read"},
		UpdatedAt:    time.Now(),
	}

	// Act
	err := repo.Update(ctx, client)

	// Assert
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestClientRepository_Delete_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test")
	}

	// Arrange
	ctx := context.Background()
	repo := NewClientRepository(nil)

	// Act
	err := repo.Delete(ctx, "client_id_to_delete")

	// Assert
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestClientRepository_List_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test")
	}

	// Arrange
	ctx := context.Background()
	repo := NewClientRepository(nil)

	// Act
	clients, err := repo.List(ctx, 10, 0)

	// Assert
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if clients == nil {
		t.Error("expected clients slice, got nil")
	}
}
