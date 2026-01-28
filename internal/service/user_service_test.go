package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dlddu/tiny-oauth/internal/domain"
)

// MockUserRepository is a mock for user repository operations
type MockUserRepository struct {
	users        map[string]*domain.User
	usersByEmail map[string]*domain.User
	usersById    map[string]*domain.User
	err          error
}

func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		users:        make(map[string]*domain.User),
		usersByEmail: make(map[string]*domain.User),
		usersById:    make(map[string]*domain.User),
	}
}

func (m *MockUserRepository) SetError(err error) {
	m.err = err
}

func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) error {
	if m.err != nil {
		return m.err
	}
	m.users[user.Username] = user
	m.usersByEmail[user.Email] = user
	m.usersById[user.ID] = user
	return nil
}

func (m *MockUserRepository) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
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
	if m.err != nil {
		return m.err
	}
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

func TestUserService_Register(t *testing.T) {
	tests := []struct {
		name      string
		username  string
		email     string
		password  string
		firstName string
		lastName  string
		setupMock func(*MockPasswordHasher, *MockUserRepository)
		wantErr   bool
	}{
		{
			name:      "should register user successfully",
			username:  "newuser",
			email:     "newuser@example.com",
			password:  "SecurePassword123!",
			firstName: "New",
			lastName:  "User",
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {},
			wantErr:   false,
		},
		{
			name:      "should register user with minimal fields",
			username:  "minimaluser",
			email:     "minimal@example.com",
			password:  "SecurePassword123!",
			firstName: "",
			lastName:  "",
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {},
			wantErr:   false,
		},
		{
			name:      "should fail with empty username",
			username:  "",
			email:     "test@example.com",
			password:  "SecurePassword123!",
			firstName: "Test",
			lastName:  "User",
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {},
			wantErr:   true,
		},
		{
			name:      "should fail with empty email",
			username:  "testuser",
			email:     "",
			password:  "SecurePassword123!",
			firstName: "Test",
			lastName:  "User",
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {},
			wantErr:   true,
		},
		{
			name:      "should fail with empty password",
			username:  "testuser",
			email:     "test@example.com",
			password:  "",
			firstName: "Test",
			lastName:  "User",
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {},
			wantErr:   true,
		},
		{
			name:      "should fail with short username",
			username:  "ab",
			email:     "test@example.com",
			password:  "SecurePassword123!",
			firstName: "Test",
			lastName:  "User",
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {},
			wantErr:   true,
		},
		{
			name:      "should fail with invalid email format",
			username:  "testuser",
			email:     "invalid-email",
			password:  "SecurePassword123!",
			firstName: "Test",
			lastName:  "User",
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {},
			wantErr:   true,
		},
		{
			name:      "should fail when username already exists",
			username:  "existinguser",
			email:     "new@example.com",
			password:  "SecurePassword123!",
			firstName: "Test",
			lastName:  "User",
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				r.users["existinguser"] = &domain.User{
					ID:            "existing-id",
					Username:      "existinguser",
					Email:         "existing@example.com",
					PasswordHash:  "$2a$10$oldhash",
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
			},
			wantErr: true,
		},
		{
			name:      "should fail when email already exists",
			username:  "newuser",
			email:     "existing@example.com",
			password:  "SecurePassword123!",
			firstName: "Test",
			lastName:  "User",
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				user := &domain.User{
					ID:            "existing-id",
					Username:      "existinguser",
					Email:         "existing@example.com",
					PasswordHash:  "$2a$10$oldhash",
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				r.usersByEmail["existing@example.com"] = user
			},
			wantErr: true,
		},
		{
			name:      "should fail when hashing fails",
			username:  "testuser",
			email:     "test@example.com",
			password:  "SecurePassword123!",
			firstName: "Test",
			lastName:  "User",
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				h.hashErr = errors.New("hashing failed")
			},
			wantErr: true,
		},
		{
			name:      "should fail when repository create fails",
			username:  "testuser",
			email:     "test@example.com",
			password:  "SecurePassword123!",
			firstName: "Test",
			lastName:  "User",
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				r.SetError(errors.New("database error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := &MockPasswordHasher{}
			repo := NewMockUserRepository()

			if tt.setupMock != nil {
				tt.setupMock(hasher, repo)
			}

			service := NewUserService(repo, hasher)
			ctx := context.Background()

			user, err := service.Register(ctx, tt.username, tt.email, tt.password, tt.firstName, tt.lastName)

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

			if user.Email != tt.email {
				t.Errorf("expected email %s, got %s", tt.email, user.Email)
			}

			if user.FirstName != tt.firstName {
				t.Errorf("expected first_name %s, got %s", tt.firstName, user.FirstName)
			}

			if user.LastName != tt.lastName {
				t.Errorf("expected last_name %s, got %s", tt.lastName, user.LastName)
			}

			// Verify password is hashed (not stored as plaintext)
			if user.PasswordHash == tt.password {
				t.Error("password should be hashed, not stored as plaintext")
			}

			// Verify default values
			if !user.IsActive {
				t.Error("new user should be active by default")
			}

			if user.EmailVerified {
				t.Error("new user should have unverified email by default")
			}

			// Verify timestamps are set
			if user.CreatedAt.IsZero() {
				t.Error("created_at should be set")
			}

			if user.UpdatedAt.IsZero() {
				t.Error("updated_at should be set")
			}

			// Verify ID is generated
			if user.ID == "" {
				t.Error("id should be generated")
			}
		})
	}
}

func TestUserService_Authenticate(t *testing.T) {
	// Setup test data
	validUsername := "testuser"
	validPassword := "SecurePassword123!"
	hashedPassword := "$2a$10$" + validPassword

	tests := []struct {
		name      string
		username  string
		password  string
		setupMock func(*MockPasswordHasher, *MockUserRepository)
		wantErr   bool
	}{
		{
			name:     "should authenticate with valid credentials",
			username: validUsername,
			password: validPassword,
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				r.users[validUsername] = &domain.User{
					ID:            "user-id-123",
					Username:      validUsername,
					Email:         "test@example.com",
					PasswordHash:  hashedPassword,
					FirstName:     "Test",
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
			name:      "should fail with invalid username",
			username:  "non-existent-user",
			password:  validPassword,
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {},
			wantErr:   true,
		},
		{
			name:     "should fail with invalid password",
			username: validUsername,
			password: "WrongPassword123!",
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				r.users[validUsername] = &domain.User{
					ID:            "user-id-123",
					Username:      validUsername,
					Email:         "test@example.com",
					PasswordHash:  hashedPassword,
					FirstName:     "Test",
					LastName:      "User",
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
			},
			wantErr: true,
		},
		{
			name:      "should fail with empty username",
			username:  "",
			password:  validPassword,
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {},
			wantErr:   true,
		},
		{
			name:     "should fail with empty password",
			username: validUsername,
			password: "",
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				r.users[validUsername] = &domain.User{
					ID:            "user-id-123",
					Username:      validUsername,
					Email:         "test@example.com",
					PasswordHash:  hashedPassword,
					FirstName:     "Test",
					LastName:      "User",
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
			},
			wantErr: true,
		},
		{
			name:     "should fail when user is inactive",
			username: validUsername,
			password: validPassword,
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				r.users[validUsername] = &domain.User{
					ID:            "user-id-123",
					Username:      validUsername,
					Email:         "test@example.com",
					PasswordHash:  hashedPassword,
					FirstName:     "Test",
					LastName:      "User",
					IsActive:      false,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
			},
			wantErr: true,
		},
		{
			name:     "should fail when repository fails",
			username: validUsername,
			password: validPassword,
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				r.SetError(errors.New("database error"))
			},
			wantErr: true,
		},
		{
			name:     "should fail when password verification fails",
			username: validUsername,
			password: validPassword,
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				r.users[validUsername] = &domain.User{
					ID:            "user-id-123",
					Username:      validUsername,
					Email:         "test@example.com",
					PasswordHash:  hashedPassword,
					FirstName:     "Test",
					LastName:      "User",
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				h.verifyErr = errors.New("verification failed")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := &MockPasswordHasher{}
			repo := NewMockUserRepository()

			if tt.setupMock != nil {
				tt.setupMock(hasher, repo)
			}

			service := NewUserService(repo, hasher)
			ctx := context.Background()

			user, err := service.Authenticate(ctx, tt.username, tt.password)

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

			if !user.IsActive {
				t.Error("authenticated user should be active")
			}
		})
	}
}

func TestUserService_GetByID(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		setupMock func(*MockUserRepository)
		wantErr   bool
	}{
		{
			name: "should get existing user",
			id:   "existing-id",
			setupMock: func(r *MockUserRepository) {
				r.usersById["existing-id"] = &domain.User{
					ID:            "existing-id",
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
			name:      "should fail when user does not exist",
			id:        "non-existent-id",
			setupMock: func(r *MockUserRepository) {},
			wantErr:   true,
		},
		{
			name:      "should fail with empty id",
			id:        "",
			setupMock: func(r *MockUserRepository) {},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := &MockPasswordHasher{}
			repo := NewMockUserRepository()

			if tt.setupMock != nil {
				tt.setupMock(repo)
			}

			service := NewUserService(repo, hasher)
			ctx := context.Background()

			user, err := service.GetByID(ctx, tt.id)

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

func TestUserService_UpdatePassword(t *testing.T) {
	validUserID := "user-id-123"
	oldPassword := "OldPassword123!"
	newPassword := "NewPassword123!"
	hashedOldPassword := "$2a$10$" + oldPassword

	tests := []struct {
		name        string
		userID      string
		oldPassword string
		newPassword string
		setupMock   func(*MockPasswordHasher, *MockUserRepository)
		wantErr     bool
	}{
		{
			name:        "should update password successfully",
			userID:      validUserID,
			oldPassword: oldPassword,
			newPassword: newPassword,
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				user := &domain.User{
					ID:            validUserID,
					Username:      "testuser",
					Email:         "test@example.com",
					PasswordHash:  hashedOldPassword,
					FirstName:     "Test",
					LastName:      "User",
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				r.usersById[validUserID] = user
			},
			wantErr: false,
		},
		{
			name:        "should fail with empty user_id",
			userID:      "",
			oldPassword: oldPassword,
			newPassword: newPassword,
			setupMock:   func(h *MockPasswordHasher, r *MockUserRepository) {},
			wantErr:     true,
		},
		{
			name:        "should fail with empty old password",
			userID:      validUserID,
			oldPassword: "",
			newPassword: newPassword,
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				user := &domain.User{
					ID:            validUserID,
					Username:      "testuser",
					Email:         "test@example.com",
					PasswordHash:  hashedOldPassword,
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				r.usersById[validUserID] = user
			},
			wantErr: true,
		},
		{
			name:        "should fail with empty new password",
			userID:      validUserID,
			oldPassword: oldPassword,
			newPassword: "",
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				user := &domain.User{
					ID:            validUserID,
					Username:      "testuser",
					Email:         "test@example.com",
					PasswordHash:  hashedOldPassword,
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				r.usersById[validUserID] = user
			},
			wantErr: true,
		},
		{
			name:        "should fail when user does not exist",
			userID:      "non-existent-id",
			oldPassword: oldPassword,
			newPassword: newPassword,
			setupMock:   func(h *MockPasswordHasher, r *MockUserRepository) {},
			wantErr:     true,
		},
		{
			name:        "should fail with incorrect old password",
			userID:      validUserID,
			oldPassword: "WrongPassword123!",
			newPassword: newPassword,
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				user := &domain.User{
					ID:            validUserID,
					Username:      "testuser",
					Email:         "test@example.com",
					PasswordHash:  hashedOldPassword,
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				r.usersById[validUserID] = user
			},
			wantErr: true,
		},
		{
			name:        "should fail when new password is same as old",
			userID:      validUserID,
			oldPassword: oldPassword,
			newPassword: oldPassword,
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				user := &domain.User{
					ID:            validUserID,
					Username:      "testuser",
					Email:         "test@example.com",
					PasswordHash:  hashedOldPassword,
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				r.usersById[validUserID] = user
			},
			wantErr: true,
		},
		{
			name:        "should fail when hashing fails",
			userID:      validUserID,
			oldPassword: oldPassword,
			newPassword: newPassword,
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				user := &domain.User{
					ID:            validUserID,
					Username:      "testuser",
					Email:         "test@example.com",
					PasswordHash:  hashedOldPassword,
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				r.usersById[validUserID] = user
				h.hashErr = errors.New("hashing failed")
			},
			wantErr: true,
		},
		{
			name:        "should fail when repository update fails",
			userID:      validUserID,
			oldPassword: oldPassword,
			newPassword: newPassword,
			setupMock: func(h *MockPasswordHasher, r *MockUserRepository) {
				user := &domain.User{
					ID:            validUserID,
					Username:      "testuser",
					Email:         "test@example.com",
					PasswordHash:  hashedOldPassword,
					IsActive:      true,
					EmailVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				r.usersById[validUserID] = user
				r.SetError(errors.New("database error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := &MockPasswordHasher{}
			repo := NewMockUserRepository()

			if tt.setupMock != nil {
				tt.setupMock(hasher, repo)
			}

			service := NewUserService(repo, hasher)
			ctx := context.Background()

			err := service.UpdatePassword(ctx, tt.userID, tt.oldPassword, tt.newPassword)

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

			// Verify password was updated
			user, err := repo.GetByID(ctx, tt.userID)
			if err != nil {
				t.Errorf("failed to retrieve user after password update: %v", err)
				return
			}

			// Verify new password hash is different from old
			if user.PasswordHash == hashedOldPassword {
				t.Error("password hash should have been updated")
			}

			// Verify new password is not stored as plaintext
			if user.PasswordHash == tt.newPassword {
				t.Error("new password should be hashed, not stored as plaintext")
			}
		})
	}
}

func TestUserService_ValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{
			name:    "should accept valid email",
			email:   "test@example.com",
			wantErr: false,
		},
		{
			name:    "should accept email with subdomain",
			email:   "test@mail.example.com",
			wantErr: false,
		},
		{
			name:    "should accept email with plus sign",
			email:   "test+tag@example.com",
			wantErr: false,
		},
		{
			name:    "should accept email with dots",
			email:   "first.last@example.com",
			wantErr: false,
		},
		{
			name:    "should fail with missing @",
			email:   "testexample.com",
			wantErr: true,
		},
		{
			name:    "should fail with missing domain",
			email:   "test@",
			wantErr: true,
		},
		{
			name:    "should fail with missing local part",
			email:   "@example.com",
			wantErr: true,
		},
		{
			name:    "should fail with invalid characters",
			email:   "test user@example.com",
			wantErr: true,
		},
		{
			name:    "should fail with empty email",
			email:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := &MockPasswordHasher{}
			repo := NewMockUserRepository()
			service := NewUserService(repo, hasher)

			err := service.ValidateEmail(tt.email)

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

func TestUserService_ValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{
			name:     "should accept valid username",
			username: "validuser",
			wantErr:  false,
		},
		{
			name:     "should accept username with numbers",
			username: "user123",
			wantErr:  false,
		},
		{
			name:     "should accept username with underscore",
			username: "user_name",
			wantErr:  false,
		},
		{
			name:     "should accept minimum length username",
			username: "abc",
			wantErr:  false,
		},
		{
			name:     "should fail with too short username",
			username: "ab",
			wantErr:  true,
		},
		{
			name:     "should fail with empty username",
			username: "",
			wantErr:  true,
		},
		{
			name:     "should fail with special characters",
			username: "user@name",
			wantErr:  true,
		},
		{
			name:     "should fail with spaces",
			username: "user name",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := &MockPasswordHasher{}
			repo := NewMockUserRepository()
			service := NewUserService(repo, hasher)

			err := service.ValidateUsername(tt.username)

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
