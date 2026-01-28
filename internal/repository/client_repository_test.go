package repository

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dlddu/tiny-oauth/internal/domain"
)

// MockClientRepository is a mock implementation for testing
type MockClientRepository struct {
	mu      sync.RWMutex
	clients map[string]*domain.Client
	err     error
}

func NewMockClientRepository() *MockClientRepository {
	return &MockClientRepository{
		clients: make(map[string]*domain.Client),
	}
}

func (m *MockClientRepository) SetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

func (m *MockClientRepository) Create(ctx context.Context, client *domain.Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.clients[client.ClientID] = client
	return nil
}

func (m *MockClientRepository) GetByClientID(ctx context.Context, clientID string) (*domain.Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.err != nil {
		return nil, m.err
	}
	client, ok := m.clients[clientID]
	if !ok {
		return nil, errors.New("client not found")
	}
	return client, nil
}

func (m *MockClientRepository) Delete(ctx context.Context, clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	delete(m.clients, clientID)
	return nil
}

func TestClientRepository_Create(t *testing.T) {
	tests := []struct {
		name    string
		client  *domain.Client
		wantErr bool
	}{
		{
			name: "should create client successfully",
			client: &domain.Client{
				ID:               "id-123",
				ClientID:         "client-123",
				ClientSecretHash: "$2a$10$hashedpassword",
				ClientName:       "Test Client",
				RedirectURIs:     []string{"https://example.com/callback"},
				GrantTypes:       []string{"authorization_code", "refresh_token"},
				Scopes:           []string{"read", "write"},
				IsConfidential:   true,
				CreatedAt:        time.Now(),
				UpdatedAt:        time.Now(),
			},
			wantErr: false,
		},
		{
			name: "should create client with minimal fields",
			client: &domain.Client{
				ID:               "id-456",
				ClientID:         "client-456",
				ClientSecretHash: "$2a$10$hashedpassword",
				ClientName:       "Minimal Client",
				RedirectURIs:     []string{"https://example.com/callback"},
				GrantTypes:       []string{"client_credentials"},
				IsConfidential:   true,
				CreatedAt:        time.Now(),
				UpdatedAt:        time.Now(),
			},
			wantErr: false,
		},
		{
			name: "should create public client without secret hash",
			client: &domain.Client{
				ID:               "id-789",
				ClientID:         "client-789",
				ClientSecretHash: "",
				ClientName:       "Public Client",
				RedirectURIs:     []string{"https://example.com/callback"},
				GrantTypes:       []string{"authorization_code"},
				Scopes:           []string{"read"},
				IsConfidential:   false,
				CreatedAt:        time.Now(),
				UpdatedAt:        time.Now(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockClientRepository()
			ctx := context.Background()

			err := repo.Create(ctx, tt.client)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Verify client was created
			stored, err := repo.GetByClientID(ctx, tt.client.ClientID)
			if err != nil {
				t.Errorf("failed to retrieve created client: %v", err)
				return
			}

			if stored.ClientID != tt.client.ClientID {
				t.Errorf("expected client_id %s, got %s", tt.client.ClientID, stored.ClientID)
			}

			if stored.ClientName != tt.client.ClientName {
				t.Errorf("expected client_name %s, got %s", tt.client.ClientName, stored.ClientName)
			}

			if stored.IsConfidential != tt.client.IsConfidential {
				t.Errorf("expected is_confidential %v, got %v", tt.client.IsConfidential, stored.IsConfidential)
			}
		})
	}
}

func TestClientRepository_GetByClientID(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		setup    func(*MockClientRepository)
		wantErr  bool
	}{
		{
			name:     "should get existing client by client_id",
			clientID: "existing-client",
			setup: func(repo *MockClientRepository) {
				repo.clients["existing-client"] = &domain.Client{
					ID:               "id-123",
					ClientID:         "existing-client",
					ClientSecretHash: "$2a$10$hashedpassword",
					ClientName:       "Existing Client",
					RedirectURIs:     []string{"https://example.com/callback"},
					GrantTypes:       []string{"authorization_code"},
					IsConfidential:   true,
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
			},
			wantErr: false,
		},
		{
			name:     "should fail when client does not exist",
			clientID: "non-existent-client",
			setup:    func(repo *MockClientRepository) {},
			wantErr:  true,
		},
		{
			name:     "should fail with empty client_id",
			clientID: "",
			setup:    func(repo *MockClientRepository) {},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockClientRepository()
			ctx := context.Background()

			if tt.setup != nil {
				tt.setup(repo)
			}

			client, err := repo.GetByClientID(ctx, tt.clientID)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if client == nil {
				t.Error("client is nil")
				return
			}

			if client.ClientID != tt.clientID {
				t.Errorf("expected client_id %s, got %s", tt.clientID, client.ClientID)
			}
		})
	}
}

func TestClientRepository_Delete(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		setup    func(*MockClientRepository)
		wantErr  bool
	}{
		{
			name:     "should delete existing client",
			clientID: "client-to-delete",
			setup: func(repo *MockClientRepository) {
				repo.clients["client-to-delete"] = &domain.Client{
					ID:               "id-123",
					ClientID:         "client-to-delete",
					ClientSecretHash: "$2a$10$hashedpassword",
					ClientName:       "Client to Delete",
					RedirectURIs:     []string{"https://example.com/callback"},
					GrantTypes:       []string{"authorization_code"},
					IsConfidential:   true,
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
			},
			wantErr: false,
		},
		{
			name:     "should succeed when deleting non-existent client",
			clientID: "non-existent-client",
			setup:    func(repo *MockClientRepository) {},
			wantErr:  false, // Delete is idempotent
		},
		{
			name:     "should handle empty client_id",
			clientID: "",
			setup:    func(repo *MockClientRepository) {},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockClientRepository()
			ctx := context.Background()

			if tt.setup != nil {
				tt.setup(repo)
			}

			err := repo.Delete(ctx, tt.clientID)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Verify client was deleted
			_, err = repo.GetByClientID(ctx, tt.clientID)
			if err == nil {
				t.Error("expected client to be deleted, but still exists")
			}
		})
	}
}

func TestClientRepository_ConcurrentAccess(t *testing.T) {
	t.Run("should handle concurrent creates", func(t *testing.T) {
		repo := NewMockClientRepository()
		ctx := context.Background()

		done := make(chan bool)

		for i := 0; i < 10; i++ {
			go func(index int) {
				client := &domain.Client{
					ID:               "id-" + string(rune(index)),
					ClientID:         "client-" + string(rune(index)),
					ClientSecretHash: "$2a$10$hashedpassword",
					ClientName:       "Concurrent Client",
					RedirectURIs:     []string{"https://example.com/callback"},
					GrantTypes:       []string{"client_credentials"},
					IsConfidential:   true,
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
				_ = repo.Create(ctx, client)
				done <- true
			}(i)
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

func TestClientRepository_ErrorHandling(t *testing.T) {
	t.Run("should propagate repository errors", func(t *testing.T) {
		repo := NewMockClientRepository()
		ctx := context.Background()

		expectedErr := errors.New("database connection failed")
		repo.SetError(expectedErr)

		client := &domain.Client{
			ID:               "id-123",
			ClientID:         "client-123",
			ClientSecretHash: "$2a$10$hashedpassword",
			ClientName:       "Test Client",
			RedirectURIs:     []string{"https://example.com/callback"},
			GrantTypes:       []string{"authorization_code"},
			IsConfidential:   true,
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		}

		err := repo.Create(ctx, client)
		if err == nil {
			t.Error("expected error but got none")
		}

		_, err = repo.GetByClientID(ctx, "any-client")
		if err == nil {
			t.Error("expected error but got none")
		}

		err = repo.Delete(ctx, "any-client")
		if err == nil {
			t.Error("expected error but got none")
		}
	})
}
