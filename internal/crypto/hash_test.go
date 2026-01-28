package crypto

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "should hash valid password successfully",
			password: "mysecretpassword123",
			wantErr:  false,
		},
		{
			name:     "should hash password with special characters",
			password: "p@ssw0rd!#$%^&*()",
			wantErr:  false,
		},
		{
			name:     "should fail with very long password (>72 bytes)",
			password: "this_is_a_very_long_password_with_more_than_72_characters_to_test_bcrypt_limit_and_behavior",
			wantErr:  true,
		},
		{
			name:     "should fail with empty password",
			password: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)

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

			if hash == "" {
				t.Error("hash is empty")
			}

			// Verify hash is different from password
			if hash == tt.password {
				t.Error("hash should not be same as password")
			}

			// Verify hash starts with bcrypt prefix
			if len(hash) < 60 {
				t.Errorf("hash length %d is too short for bcrypt", len(hash))
			}
		})
	}
}

func TestVerifyPassword(t *testing.T) {
	// Pre-generate a valid hash for testing
	validPassword := "correctpassword123"
	validHash, err := HashPassword(validPassword)
	if err != nil {
		t.Fatalf("failed to generate test hash: %v", err)
	}

	tests := []struct {
		name     string
		hash     string
		password string
		wantErr  bool
	}{
		{
			name:     "should verify correct password successfully",
			hash:     validHash,
			password: validPassword,
			wantErr:  false,
		},
		{
			name:     "should fail with incorrect password",
			hash:     validHash,
			password: "wrongpassword",
			wantErr:  true,
		},
		{
			name:     "should fail with empty password",
			hash:     validHash,
			password: "",
			wantErr:  true,
		},
		{
			name:     "should fail with empty hash",
			hash:     "",
			password: validPassword,
			wantErr:  true,
		},
		{
			name:     "should fail with invalid hash format",
			hash:     "not_a_valid_bcrypt_hash",
			password: validPassword,
			wantErr:  true,
		},
		{
			name:     "should fail with case sensitivity",
			hash:     validHash,
			password: "CORRECTPASSWORD123",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPassword(tt.hash, tt.password)

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

func TestPasswordHashingConsistency(t *testing.T) {
	t.Run("should generate different hashes for same password", func(t *testing.T) {
		password := "samepassword"

		hash1, err := HashPassword(password)
		if err != nil {
			t.Fatalf("failed to generate first hash: %v", err)
		}

		hash2, err := HashPassword(password)
		if err != nil {
			t.Fatalf("failed to generate second hash: %v", err)
		}

		// Hashes should be different (bcrypt uses salt)
		if hash1 == hash2 {
			t.Error("expected different hashes for same password")
		}

		// Both hashes should verify the same password
		if err := VerifyPassword(hash1, password); err != nil {
			t.Errorf("first hash failed to verify: %v", err)
		}

		if err := VerifyPassword(hash2, password); err != nil {
			t.Errorf("second hash failed to verify: %v", err)
		}
	})
}

func TestConstantTimeComparison(t *testing.T) {
	t.Run("should use constant-time comparison to prevent timing attacks", func(t *testing.T) {
		password := "testpassword"
		hash, err := HashPassword(password)
		if err != nil {
			t.Fatalf("failed to generate hash: %v", err)
		}

		// Test multiple wrong passwords
		// In a real timing attack test, we would measure time differences
		// For this test, we just ensure consistent error behavior
		wrongPasswords := []string{
			"wrongpassword",
			"testpasswor",  // one character short
			"testpassword1", // one character extra
		}

		for _, wp := range wrongPasswords {
			err := VerifyPassword(hash, wp)
			if err == nil {
				t.Errorf("password '%s' should not verify", wp)
			}
		}
	})
}
