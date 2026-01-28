package repository

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dlddu/tiny-oauth/internal/domain"
)

// MockUserRepository is a mock implementation for testing
type MockUserRepository struct {
	mu       sync.RWMutex
	users    map[string]*domain.User
	usersByEmail map[string]*domain.User
	usersById map[string]*domain.User
	err      error
}

func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		users:        make(map[string]*domain.User),
		usersByEmail: make(map[string]*domain.User),
		usersById:    make(map[string]*domain.User),
	}
}

func (m *MockUserRepository) SetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.users[user.Username] = user
	m.usersByEmail[user.Email] = user
	m.usersById[user.ID] = user
	return nil
}

func (m *MockUserRepository) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.err != nil {
		return nil, m.err
	}
	user, ok := m.users[username]
	if !ok {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.err != nil {
		return nil, m.err
	}
	user, ok := m.usersByEmail[email]
	if !ok {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (m *MockUserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.err != nil {
		return nil, m.err
	}
	user, ok := m.usersById[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (m *MockUserRepository) Update(ctx context.Context, user *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}

	// Check if user exists
	_, ok := m.usersById[user.ID]
	if !ok {
		return errors.New("user not found")
	}

	// Remove old entries
	if oldUser, exists := m.usersById[user.ID]; exists {
		delete(m.users, oldUser.Username)
		delete(m.usersByEmail, oldUser.Email)
	}

	// Add updated entries
	m.users[user.Username] = user
	m.usersByEmail[user.Email] = user
	m.usersById[user.ID] = user
	return nil
}

func (m *MockUserRepository) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}

	user, ok := m.usersById[id]
	if ok {
		delete(m.users, user.Username)
		delete(m.usersByEmail, user.Email)
		delete(m.usersById, id)
	}
	return nil
}

func TestUserRepository_Create(t *testing.T) {
	tests := []struct {
		name    string
		user    *domain.User
		wantErr bool
	}{
		{
			name: "should create user successfully",
			user: &domain.User{
				ID:            "user-id-123",
				Username:      "testuser",
				Email:         "test@example.com",
				PasswordHash:  "$2a$10$hashedpassword",
				FirstName:     "Test",
				LastName:      "User",
				IsActive:      true,
				EmailVerified: false,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			wantErr: false,
		},
		{
			name: "should create user with minimal fields",
			user: &domain.User{
				ID:            "user-id-456",
				Username:      "minimaluser",
				Email:         "minimal@example.com",
				PasswordHash:  "$2a$10$hashedpassword",
				IsActive:      true,
				EmailVerified: false,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			wantErr: false,
		},
		{
			name: "should create inactive user",
			user: &domain.User{
				ID:            "user-id-789",
				Username:      "inactiveuser",
				Email:         "inactive@example.com",
				PasswordHash:  "$2a$10$hashedpassword",
				FirstName:     "Inactive",
				LastName:      "User",
				IsActive:      false,
				EmailVerified: false,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			wantErr: false,
		},
		{
			name: "should create user with verified email",
			user: &domain.User{
				ID:            "user-id-101",
				Username:      "verifieduser",
				Email:         "verified@example.com",
				PasswordHash:  "$2a$10$hashedpassword",
				FirstName:     "Verified",
				LastName:      "User",
				IsActive:      true,
				EmailVerified: true,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockUserRepository()
			ctx := context.Background()

			err := repo.Create(ctx, tt.user)

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

			// Verify user was created by username
			stored, err := repo.GetByUsername(ctx, tt.user.Username)
			if err != nil {
				t.Errorf("failed to retrieve created user by username: %v", err)
				return
			}

			if stored.Username != tt.user.Username {
				t.Errorf("expected username %s, got %s", tt.user.Username, stored.Username)
			}

			if stored.Email != tt.user.Email {
				t.Errorf("expected email %s, got %s", tt.user.Email, stored.Email)
			}

			if stored.IsActive != tt.user.IsActive {
				t.Errorf("expected is_active %v, got %v", tt.user.IsActive, stored.IsActive)
			}

			if stored.EmailVerified != tt.user.EmailVerified {
				t.Errorf("expected email_verified %v, got %v", tt.user.EmailVerified, stored.EmailVerified)
			}
		})
	}
}

func TestUserRepository_GetByUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		setup    func(*MockUserRepository)
		wantErr  bool
	}{
		{
			name:     "should get existing user by username",
			username: "existinguser",
			setup: func(repo *MockUserRepository) {
				repo.users["existinguser"] = &domain.User{
					ID:            "user-id-123",
					Username:      "existinguser",
					Email:         "existing@example.com",
					PasswordHash:  "$2a$10$hashedpassword",
					FirstName:     "Existing",
					LastName:      "User",
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
			},
			wantErr: false,
		},
		{
			name:     "should fail when user does not exist",
			username: "non-existent-user",
			setup:    func(repo *MockUserRepository) {},
			wantErr:  true,
		},
		{
			name:     "should fail with empty username",
			username: "",
			setup:    func(repo *MockUserRepository) {},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockUserRepository()
			ctx := context.Background()

			if tt.setup != nil {
				tt.setup(repo)
			}

			user, err := repo.GetByUsername(ctx, tt.username)

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

			if user == nil {
				t.Error("user is nil")
				return
			}

			if user.Username != tt.username {
				t.Errorf("expected username %s, got %s", tt.username, user.Username)
			}
		})
	}
}

func TestUserRepository_GetByEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		setup   func(*MockUserRepository)
		wantErr bool
	}{
		{
			name:  "should get existing user by email",
			email: "existing@example.com",
			setup: func(repo *MockUserRepository) {
				user := &domain.User{
					ID:            "user-id-123",
					Username:      "existinguser",
					Email:         "existing@example.com",
					PasswordHash:  "$2a$10$hashedpassword",
					FirstName:     "Existing",
					LastName:      "User",
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				repo.usersByEmail["existing@example.com"] = user
			},
			wantErr: false,
		},
		{
			name:    "should fail when user does not exist",
			email:   "non-existent@example.com",
			setup:   func(repo *MockUserRepository) {},
			wantErr: true,
		},
		{
			name:    "should fail with empty email",
			email:   "",
			setup:   func(repo *MockUserRepository) {},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockUserRepository()
			ctx := context.Background()

			if tt.setup != nil {
				tt.setup(repo)
			}

			user, err := repo.GetByEmail(ctx, tt.email)

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

			if user == nil {
				t.Error("user is nil")
				return
			}

			if user.Email != tt.email {
				t.Errorf("expected email %s, got %s", tt.email, user.Email)
			}
		})
	}
}

func TestUserRepository_GetByID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		setup   func(*MockUserRepository)
		wantErr bool
	}{
		{
			name: "should get existing user by id",
			id:   "user-id-123",
			setup: func(repo *MockUserRepository) {
				user := &domain.User{
					ID:            "user-id-123",
					Username:      "existinguser",
					Email:         "existing@example.com",
					PasswordHash:  "$2a$10$hashedpassword",
					FirstName:     "Existing",
					LastName:      "User",
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				repo.usersById["user-id-123"] = user
			},
			wantErr: false,
		},
		{
			name:    "should fail when user does not exist",
			id:      "non-existent-id",
			setup:   func(repo *MockUserRepository) {},
			wantErr: true,
		},
		{
			name:    "should fail with empty id",
			id:      "",
			setup:   func(repo *MockUserRepository) {},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockUserRepository()
			ctx := context.Background()

			if tt.setup != nil {
				tt.setup(repo)
			}

			user, err := repo.GetByID(ctx, tt.id)

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

			if user == nil {
				t.Error("user is nil")
				return
			}

			if user.ID != tt.id {
				t.Errorf("expected id %s, got %s", tt.id, user.ID)
			}
		})
	}
}

func TestUserRepository_Update(t *testing.T) {
	tests := []struct {
		name    string
		user    *domain.User
		setup   func(*MockUserRepository)
		wantErr bool
	}{
		{
			name: "should update existing user",
			user: &domain.User{
				ID:            "user-id-123",
				Username:      "updateduser",
				Email:         "updated@example.com",
				PasswordHash:  "$2a$10$newhash",
				FirstName:     "Updated",
				LastName:      "User",
				IsActive:      true,
				EmailVerified: true,
				CreatedAt:     time.Now().Add(-24 * time.Hour),
				UpdatedAt:     time.Now(),
			},
			setup: func(repo *MockUserRepository) {
				oldUser := &domain.User{
					ID:            "user-id-123",
					Username:      "olduser",
					Email:         "old@example.com",
					PasswordHash:  "$2a$10$oldhash",
					FirstName:     "Old",
					LastName:      "User",
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now().Add(-24 * time.Hour),
					UpdatedAt:     time.Now().Add(-24 * time.Hour),
				}
				repo.users["olduser"] = oldUser
				repo.usersByEmail["old@example.com"] = oldUser
				repo.usersById["user-id-123"] = oldUser
			},
			wantErr: false,
		},
		{
			name: "should fail when user does not exist",
			user: &domain.User{
				ID:            "non-existent-id",
				Username:      "newuser",
				Email:         "new@example.com",
				PasswordHash:  "$2a$10$hash",
				IsActive:      true,
				EmailVerified: false,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			setup:   func(repo *MockUserRepository) {},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockUserRepository()
			ctx := context.Background()

			if tt.setup != nil {
				tt.setup(repo)
			}

			err := repo.Update(ctx, tt.user)

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

			// Verify user was updated
			stored, err := repo.GetByID(ctx, tt.user.ID)
			if err != nil {
				t.Errorf("failed to retrieve updated user: %v", err)
				return
			}

			if stored.Username != tt.user.Username {
				t.Errorf("expected username %s, got %s", tt.user.Username, stored.Username)
			}

			if stored.Email != tt.user.Email {
				t.Errorf("expected email %s, got %s", tt.user.Email, stored.Email)
			}

			if stored.EmailVerified != tt.user.EmailVerified {
				t.Errorf("expected email_verified %v, got %v", tt.user.EmailVerified, stored.EmailVerified)
			}
		})
	}
}

func TestUserRepository_Delete(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		setup   func(*MockUserRepository)
		wantErr bool
	}{
		{
			name: "should delete existing user",
			id:   "user-to-delete",
			setup: func(repo *MockUserRepository) {
				user := &domain.User{
					ID:            "user-to-delete",
					Username:      "deleteuser",
					Email:         "delete@example.com",
					PasswordHash:  "$2a$10$hashedpassword",
					FirstName:     "Delete",
					LastName:      "User",
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				repo.users["deleteuser"] = user
				repo.usersByEmail["delete@example.com"] = user
				repo.usersById["user-to-delete"] = user
			},
			wantErr: false,
		},
		{
			name:    "should succeed when deleting non-existent user",
			id:      "non-existent-id",
			setup:   func(repo *MockUserRepository) {},
			wantErr: false, // Delete is idempotent
		},
		{
			name:    "should handle empty id",
			id:      "",
			setup:   func(repo *MockUserRepository) {},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockUserRepository()
			ctx := context.Background()

			if tt.setup != nil {
				tt.setup(repo)
			}

			err := repo.Delete(ctx, tt.id)

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

			// Verify user was deleted
			_, err = repo.GetByID(ctx, tt.id)
			if err == nil {
				t.Error("expected user to be deleted, but still exists")
			}
		})
	}
}

func TestUserRepository_ConcurrentAccess(t *testing.T) {
	t.Run("should handle concurrent creates", func(t *testing.T) {
		repo := NewMockUserRepository()
		ctx := context.Background()

		done := make(chan bool)

		for i := 0; i < 10; i++ {
			go func(index int) {
				user := &domain.User{
					ID:            "user-id-" + string(rune(index)),
					Username:      "user-" + string(rune(index)),
					Email:         "user" + string(rune(index)) + "@example.com",
					PasswordHash:  "$2a$10$hashedpassword",
					FirstName:     "Concurrent",
					LastName:      "User",
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				_ = repo.Create(ctx, user)
				done <- true
			}(i)
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

func TestUserRepository_ErrorHandling(t *testing.T) {
	t.Run("should propagate repository errors", func(t *testing.T) {
		repo := NewMockUserRepository()
		ctx := context.Background()

		expectedErr := errors.New("database connection failed")
		repo.SetError(expectedErr)

		user := &domain.User{
			ID:            "user-id-123",
			Username:      "testuser",
			Email:         "test@example.com",
			PasswordHash:  "$2a$10$hashedpassword",
			FirstName:     "Test",
			LastName:      "User",
			IsActive:      true,
			EmailVerified: false,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		err := repo.Create(ctx, user)
		if err == nil {
			t.Error("expected error but got none")
		}

		_, err = repo.GetByUsername(ctx, "anyuser")
		if err == nil {
			t.Error("expected error but got none")
		}

		_, err = repo.GetByEmail(ctx, "any@example.com")
		if err == nil {
			t.Error("expected error but got none")
		}

		_, err = repo.GetByID(ctx, "any-id")
		if err == nil {
			t.Error("expected error but got none")
		}

		err = repo.Update(ctx, user)
		if err == nil {
			t.Error("expected error but got none")
		}

		err = repo.Delete(ctx, "any-id")
		if err == nil {
			t.Error("expected error but got none")
		}
	})
}
