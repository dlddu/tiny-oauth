package service

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/dlddu/tiny-oauth/internal/domain"
	"github.com/google/uuid"
)

// userService handles business logic for user operations
type userService struct {
	repo   UserRepository
	hasher Hasher
}

// NewUserService creates a new UserService instance
func NewUserService(repo UserRepository, hasher Hasher) UserService {
	return &userService{
		repo:   repo,
		hasher: hasher,
	}
}

// Register creates a new user account
func (s *userService) Register(ctx context.Context, username, email, password, firstName, lastName string) (*domain.User, error) {
	// Validate inputs
	if username == "" {
		return nil, ErrInvalidUsername
	}
	if email == "" {
		return nil, ErrInvalidEmail
	}
	if password == "" {
		return nil, errors.New("password cannot be empty")
	}

	// Validate username format
	if err := s.ValidateUsername(username); err != nil {
		return nil, err
	}

	// Validate email format
	if err := s.ValidateEmail(email); err != nil {
		return nil, err
	}

	// Check if username already exists
	_, err := s.repo.GetByUsername(ctx, username)
	if err == nil {
		return nil, ErrUserAlreadyExists
	}

	// Check if email already exists
	_, err = s.repo.GetByEmail(ctx, email)
	if err == nil {
		return nil, ErrUserAlreadyExists
	}

	// Hash password
	passwordHash, err := s.hasher.HashPassword(password)
	if err != nil {
		return nil, err
	}

	// Create user entity
	now := time.Now().UTC()
	user := &domain.User{
		ID:            uuid.New().String(),
		Username:      username,
		Email:         email,
		PasswordHash:  passwordHash,
		FirstName:     firstName,
		LastName:      lastName,
		IsActive:      true,
		EmailVerified: false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	// Persist to repository
	if err := s.repo.Create(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// Authenticate verifies user credentials and returns the user if valid
func (s *userService) Authenticate(ctx context.Context, username, password string) (*domain.User, error) {
	// Validate inputs
	if username == "" {
		return nil, ErrInvalidCredentials
	}
	if password == "" {
		return nil, ErrInvalidCredentials
	}

	// Retrieve user from repository
	user, err := s.repo.GetByUsername(ctx, username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Verify password
	if err := s.hasher.VerifyPassword(user.PasswordHash, password); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Check if user is active
	if !user.IsActive {
		return nil, ErrUserInactive
	}

	return user, nil
}

// GetByID retrieves a user by ID
func (s *userService) GetByID(ctx context.Context, id string) (*domain.User, error) {
	if id == "" {
		return nil, errors.New("id cannot be empty")
	}

	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// UpdatePassword updates a user's password
func (s *userService) UpdatePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	// Validate inputs
	if userID == "" {
		return errors.New("user_id cannot be empty")
	}
	if oldPassword == "" {
		return errors.New("old password cannot be empty")
	}
	if newPassword == "" {
		return errors.New("new password cannot be empty")
	}

	// Check if new password is same as old
	if oldPassword == newPassword {
		return ErrSamePassword
	}

	// Retrieve user
	user, err := s.repo.GetByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Verify old password
	if err := s.hasher.VerifyPassword(user.PasswordHash, oldPassword); err != nil {
		return ErrInvalidCredentials
	}

	// Hash new password
	newPasswordHash, err := s.hasher.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update user entity
	user.PasswordHash = newPasswordHash
	user.UpdatedAt = time.Now().UTC()

	// Persist changes
	if err := s.repo.Update(ctx, user); err != nil {
		return err
	}

	return nil
}

// ValidateEmail validates email format
func (s *userService) ValidateEmail(email string) error {
	if email == "" {
		return ErrInvalidEmail
	}

	// Check for @ symbol
	if !strings.Contains(email, "@") {
		return ErrInvalidEmail
	}

	// Split local and domain parts
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ErrInvalidEmail
	}

	localPart := parts[0]
	domainPart := parts[1]

	// Check local part is not empty
	if localPart == "" {
		return ErrInvalidEmail
	}

	// Check domain part is not empty
	if domainPart == "" {
		return ErrInvalidEmail
	}

	// Check domain has at least one dot or is valid
	if !strings.Contains(domainPart, ".") && domainPart != "localhost" {
		return ErrInvalidEmail
	}

	// Check for spaces (invalid in email)
	if strings.Contains(email, " ") {
		return ErrInvalidEmail
	}

	return nil
}

// ValidateUsername validates username format
func (s *userService) ValidateUsername(username string) error {
	if username == "" {
		return ErrInvalidUsername
	}

	// Check minimum length (3 characters)
	if len(username) < 3 {
		return ErrInvalidUsername
	}

	// Check for valid characters (alphanumeric and underscore only)
	validUsername := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if !validUsername.MatchString(username) {
		return ErrInvalidUsername
	}

	return nil
}
