package service

import (
	"context"
	"time"

	"github.com/dlddu/tiny-oauth/internal/domain"
	"github.com/google/uuid"
)

// ClientService handles business logic for OAuth clients
type ClientService struct {
	repo   ClientRepository
	hasher Hasher
}

// NewClientService creates a new ClientService instance
func NewClientService(repo ClientRepository, hasher Hasher) *ClientService {
	return &ClientService{
		repo:   repo,
		hasher: hasher,
	}
}

// CreateClient creates a new OAuth client
func (s *ClientService) CreateClient(
	ctx context.Context,
	clientID string,
	clientSecret string,
	clientName string,
	redirectURIs []string,
	grantTypes []string,
	scopes []string,
	isConfidential bool,
) (*domain.Client, error) {
	// Validate inputs
	if clientID == "" {
		return nil, ErrEmptyClientID
	}
	if clientName == "" {
		return nil, ErrEmptyClientName
	}
	if len(redirectURIs) == 0 {
		return nil, ErrEmptyRedirectURIs
	}
	if len(grantTypes) == 0 {
		return nil, ErrEmptyGrantTypes
	}
	if isConfidential && clientSecret == "" {
		return nil, ErrEmptySecret
	}

	// Validate grant types
	if err := s.ValidateGrantTypes(grantTypes); err != nil {
		return nil, err
	}

	// Hash client secret if confidential
	var secretHash string
	if isConfidential {
		hash, err := s.hasher.HashPassword(clientSecret)
		if err != nil {
			return nil, err
		}
		secretHash = hash
	}

	// Create client entity
	now := time.Now()
	client := &domain.Client{
		ID:               uuid.New().String(),
		ClientID:         clientID,
		ClientSecretHash: secretHash,
		ClientName:       clientName,
		RedirectURIs:     redirectURIs,
		GrantTypes:       grantTypes,
		Scopes:           scopes,
		IsConfidential:   isConfidential,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	// Persist to repository
	if err := s.repo.Create(ctx, client); err != nil {
		return nil, err
	}

	return client, nil
}

// AuthenticateClient verifies client credentials
func (s *ClientService) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (*domain.Client, error) {
	if clientID == "" {
		return nil, ErrEmptyClientID
	}
	if clientSecret == "" {
		return nil, ErrInvalidCredentials
	}

	// Retrieve client from repository
	client, err := s.repo.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Verify client secret
	if err := s.hasher.VerifyPassword(client.ClientSecretHash, clientSecret); err != nil {
		return nil, ErrInvalidCredentials
	}

	return client, nil
}

// GetClientByID retrieves a client by its client_id
func (s *ClientService) GetClientByID(ctx context.Context, clientID string) (*domain.Client, error) {
	if clientID == "" {
		return nil, ErrEmptyClientID
	}

	return s.repo.GetByClientID(ctx, clientID)
}

// DeleteClient deletes a client
func (s *ClientService) DeleteClient(ctx context.Context, clientID string) error {
	if clientID == "" {
		return ErrEmptyClientID
	}

	return s.repo.Delete(ctx, clientID)
}

// ValidateGrantTypes validates OAuth 2.0 grant types
func (s *ClientService) ValidateGrantTypes(grantTypes []string) error {
	if len(grantTypes) == 0 {
		return ErrEmptyGrantTypes
	}

	validGrantTypes := map[string]bool{
		"authorization_code": true,
		"refresh_token":      true,
		"client_credentials": true,
		"password":           true,
		"implicit":           true,
	}

	for _, gt := range grantTypes {
		if !validGrantTypes[gt] {
			return ErrInvalidGrantType
		}
	}

	return nil
}
