package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dlddu/tiny-oauth/internal/domain"
)

// MockPasswordHasher is a mock for password hashing operations
type MockPasswordHasher struct {
	hashErr   error
	verifyErr error
}

func (m *MockPasswordHasher) HashPassword(password string) (string, error) {
	if m.hashErr != nil {
		return "", m.hashErr
	}
	return "$2a$10$" + password, nil
}

func (m *MockPasswordHasher) VerifyPassword(hash, password string) error {
	if m.verifyErr != nil {
		return m.verifyErr
	}
	expectedHash := "$2a$10$" + password
	if hash != expectedHash {
		return errors.New("password mismatch")
	}
	return nil
}

// MockClientRepository is a mock for client repository operations
type MockClientRepository struct {
	clients map[string]*domain.Client
	err     error
}

func NewMockClientRepository() *MockClientRepository {
	return &MockClientRepository{
		clients: make(map[string]*domain.Client),
	}
}

func (m *MockClientRepository) SetError(err error) {
	m.err = err
}

func (m *MockClientRepository) Create(ctx context.Context, client *domain.Client) error {
	if m.err != nil {
		return m.err
	}
	m.clients[client.ClientID] = client
	return nil
}

func (m *MockClientRepository) GetByClientID(ctx context.Context, clientID string) (*domain.Client, error) {
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
	if m.err != nil {
		return m.err
	}
	delete(m.clients, clientID)
	return nil
}

func TestClientService_CreateClient(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		clientName   string
		redirectURIs []string
		grantTypes   []string
		scopes       []string
		confidential bool
		setupMock    func(*MockPasswordHasher, *MockClientRepository)
		wantErr      bool
	}{
		{
			name:         "should create confidential client successfully",
			clientID:     "client-123",
			clientSecret: "secret-abc",
			clientName:   "Test Client",
			redirectURIs: []string{"https://example.com/callback"},
			grantTypes:   []string{"authorization_code", "refresh_token"},
			scopes:       []string{"read", "write"},
			confidential: true,
			setupMock:    func(h *MockPasswordHasher, r *MockClientRepository) {},
			wantErr:      false,
		},
		{
			name:         "should create public client without secret",
			clientID:     "public-client-123",
			clientSecret: "",
			clientName:   "Public Client",
			redirectURIs: []string{"https://example.com/callback"},
			grantTypes:   []string{"authorization_code"},
			scopes:       []string{"read"},
			confidential: false,
			setupMock:    func(h *MockPasswordHasher, r *MockClientRepository) {},
			wantErr:      false,
		},
		{
			name:         "should fail with empty client_id",
			clientID:     "",
			clientSecret: "secret",
			clientName:   "Test Client",
			redirectURIs: []string{"https://example.com/callback"},
			grantTypes:   []string{"authorization_code"},
			confidential: true,
			setupMock:    func(h *MockPasswordHasher, r *MockClientRepository) {},
			wantErr:      true,
		},
		{
			name:         "should fail with empty client_name",
			clientID:     "client-123",
			clientSecret: "secret",
			clientName:   "",
			redirectURIs: []string{"https://example.com/callback"},
			grantTypes:   []string{"authorization_code"},
			confidential: true,
			setupMock:    func(h *MockPasswordHasher, r *MockClientRepository) {},
			wantErr:      true,
		},
		{
			name:         "should fail confidential client without secret",
			clientID:     "client-123",
			clientSecret: "",
			clientName:   "Test Client",
			redirectURIs: []string{"https://example.com/callback"},
			grantTypes:   []string{"authorization_code"},
			confidential: true,
			setupMock:    func(h *MockPasswordHasher, r *MockClientRepository) {},
			wantErr:      true,
		},
		{
			name:         "should fail with empty redirect_uris",
			clientID:     "client-123",
			clientSecret: "secret",
			clientName:   "Test Client",
			redirectURIs: []string{},
			grantTypes:   []string{"authorization_code"},
			confidential: true,
			setupMock:    func(h *MockPasswordHasher, r *MockClientRepository) {},
			wantErr:      true,
		},
		{
			name:         "should fail with empty grant_types",
			clientID:     "client-123",
			clientSecret: "secret",
			clientName:   "Test Client",
			redirectURIs: []string{"https://example.com/callback"},
			grantTypes:   []string{},
			confidential: true,
			setupMock:    func(h *MockPasswordHasher, r *MockClientRepository) {},
			wantErr:      true,
		},
		{
			name:         "should fail when hashing fails",
			clientID:     "client-123",
			clientSecret: "secret",
			clientName:   "Test Client",
			redirectURIs: []string{"https://example.com/callback"},
			grantTypes:   []string{"authorization_code"},
			confidential: true,
			setupMock: func(h *MockPasswordHasher, r *MockClientRepository) {
				h.hashErr = errors.New("hashing failed")
			},
			wantErr: true,
		},
		{
			name:         "should fail when repository create fails",
			clientID:     "client-123",
			clientSecret: "secret",
			clientName:   "Test Client",
			redirectURIs: []string{"https://example.com/callback"},
			grantTypes:   []string{"authorization_code"},
			confidential: true,
			setupMock: func(h *MockPasswordHasher, r *MockClientRepository) {
				r.SetError(errors.New("database error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := &MockPasswordHasher{}
			repo := NewMockClientRepository()

			if tt.setupMock != nil {
				tt.setupMock(hasher, repo)
			}

			service := NewClientService(repo, hasher)
			ctx := context.Background()

			client, err := service.CreateClient(ctx, tt.clientID, tt.clientSecret, tt.clientName,
				tt.redirectURIs, tt.grantTypes, tt.scopes, tt.confidential)

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

			if client.ClientName != tt.clientName {
				t.Errorf("expected client_name %s, got %s", tt.clientName, client.ClientName)
			}

			if client.IsConfidential != tt.confidential {
				t.Errorf("expected is_confidential %v, got %v", tt.confidential, client.IsConfidential)
			}

			// Verify secret is hashed (not stored as plaintext)
			if tt.confidential && client.ClientSecretHash == tt.clientSecret {
				t.Error("client_secret should be hashed, not stored as plaintext")
			}

			// Verify timestamps are set
			if client.CreatedAt.IsZero() {
				t.Error("created_at should be set")
			}

			if client.UpdatedAt.IsZero() {
				t.Error("updated_at should be set")
			}
		})
	}
}

func TestClientService_AuthenticateClient(t *testing.T) {
	// Setup test data
	validClientID := "test-client"
	validSecret := "test-secret"
	hashedSecret := "$2a$10$" + validSecret

	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		setupMock    func(*MockPasswordHasher, *MockClientRepository)
		wantErr      bool
	}{
		{
			name:         "should authenticate with valid credentials",
			clientID:     validClientID,
			clientSecret: validSecret,
			setupMock: func(h *MockPasswordHasher, r *MockClientRepository) {
				r.clients[validClientID] = &domain.Client{
					ID:               "id-123",
					ClientID:         validClientID,
					ClientSecretHash: hashedSecret,
					ClientName:       "Test Client",
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
			name:         "should fail with invalid client_id",
			clientID:     "non-existent-client",
			clientSecret: validSecret,
			setupMock:    func(h *MockPasswordHasher, r *MockClientRepository) {},
			wantErr:      true,
		},
		{
			name:         "should fail with invalid client_secret",
			clientID:     validClientID,
			clientSecret: "wrong-secret",
			setupMock: func(h *MockPasswordHasher, r *MockClientRepository) {
				r.clients[validClientID] = &domain.Client{
					ID:               "id-123",
					ClientID:         validClientID,
					ClientSecretHash: hashedSecret,
					ClientName:       "Test Client",
					RedirectURIs:     []string{"https://example.com/callback"},
					GrantTypes:       []string{"authorization_code"},
					IsConfidential:   true,
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
			},
			wantErr: true,
		},
		{
			name:         "should fail with empty client_id",
			clientID:     "",
			clientSecret: validSecret,
			setupMock:    func(h *MockPasswordHasher, r *MockClientRepository) {},
			wantErr:      true,
		},
		{
			name:         "should fail with empty client_secret",
			clientID:     validClientID,
			clientSecret: "",
			setupMock: func(h *MockPasswordHasher, r *MockClientRepository) {
				r.clients[validClientID] = &domain.Client{
					ID:               "id-123",
					ClientID:         validClientID,
					ClientSecretHash: hashedSecret,
					ClientName:       "Test Client",
					RedirectURIs:     []string{"https://example.com/callback"},
					GrantTypes:       []string{"authorization_code"},
					IsConfidential:   true,
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
			},
			wantErr: true,
		},
		{
			name:         "should fail when repository fails",
			clientID:     validClientID,
			clientSecret: validSecret,
			setupMock: func(h *MockPasswordHasher, r *MockClientRepository) {
				r.SetError(errors.New("database error"))
			},
			wantErr: true,
		},
		{
			name:         "should fail when password verification fails",
			clientID:     validClientID,
			clientSecret: validSecret,
			setupMock: func(h *MockPasswordHasher, r *MockClientRepository) {
				r.clients[validClientID] = &domain.Client{
					ID:               "id-123",
					ClientID:         validClientID,
					ClientSecretHash: hashedSecret,
					ClientName:       "Test Client",
					RedirectURIs:     []string{"https://example.com/callback"},
					GrantTypes:       []string{"authorization_code"},
					IsConfidential:   true,
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
				h.verifyErr = errors.New("verification failed")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := &MockPasswordHasher{}
			repo := NewMockClientRepository()

			if tt.setupMock != nil {
				tt.setupMock(hasher, repo)
			}

			service := NewClientService(repo, hasher)
			ctx := context.Background()

			client, err := service.AuthenticateClient(ctx, tt.clientID, tt.clientSecret)

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

func TestClientService_GetClientByID(t *testing.T) {
	tests := []struct {
		name      string
		clientID  string
		setupMock func(*MockClientRepository)
		wantErr   bool
	}{
		{
			name:     "should get existing client",
			clientID: "existing-client",
			setupMock: func(r *MockClientRepository) {
				r.clients["existing-client"] = &domain.Client{
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
			name:      "should fail when client does not exist",
			clientID:  "non-existent-client",
			setupMock: func(r *MockClientRepository) {},
			wantErr:   true,
		},
		{
			name:      "should fail with empty client_id",
			clientID:  "",
			setupMock: func(r *MockClientRepository) {},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := &MockPasswordHasher{}
			repo := NewMockClientRepository()

			if tt.setupMock != nil {
				tt.setupMock(repo)
			}

			service := NewClientService(repo, hasher)
			ctx := context.Background()

			client, err := service.GetClientByID(ctx, tt.clientID)

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

func TestClientService_DeleteClient(t *testing.T) {
	tests := []struct {
		name      string
		clientID  string
		setupMock func(*MockClientRepository)
		wantErr   bool
	}{
		{
			name:     "should delete existing client",
			clientID: "client-to-delete",
			setupMock: func(r *MockClientRepository) {
				r.clients["client-to-delete"] = &domain.Client{
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
			name:      "should handle non-existent client deletion",
			clientID:  "non-existent-client",
			setupMock: func(r *MockClientRepository) {},
			wantErr:   false, // Delete is idempotent
		},
		{
			name:      "should fail with empty client_id",
			clientID:  "",
			setupMock: func(r *MockClientRepository) {},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := &MockPasswordHasher{}
			repo := NewMockClientRepository()

			if tt.setupMock != nil {
				tt.setupMock(repo)
			}

			service := NewClientService(repo, hasher)
			ctx := context.Background()

			err := service.DeleteClient(ctx, tt.clientID)

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
			_, err = service.GetClientByID(ctx, tt.clientID)
			if err == nil && tt.clientID != "" {
				t.Error("expected client to be deleted")
			}
		})
	}
}

func TestClientService_ValidateGrantTypes(t *testing.T) {
	tests := []struct {
		name       string
		grantTypes []string
		wantErr    bool
	}{
		{
			name:       "should accept valid grant types",
			grantTypes: []string{"authorization_code", "refresh_token", "client_credentials"},
			wantErr:    false,
		},
		{
			name:       "should accept single grant type",
			grantTypes: []string{"client_credentials"},
			wantErr:    false,
		},
		{
			name:       "should fail with invalid grant type",
			grantTypes: []string{"invalid_grant"},
			wantErr:    true,
		},
		{
			name:       "should fail with empty grant types",
			grantTypes: []string{},
			wantErr:    true,
		},
		{
			name:       "should fail with mixed valid and invalid grant types",
			grantTypes: []string{"authorization_code", "invalid_grant"},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := &MockPasswordHasher{}
			repo := NewMockClientRepository()
			service := NewClientService(repo, hasher)

			err := service.ValidateGrantTypes(tt.grantTypes)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
