package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	tests := []struct {
		name    string
		bitSize int
		wantErr bool
	}{
		{
			name:    "should generate 2048-bit key pair successfully",
			bitSize: 2048,
			wantErr: false,
		},
		{
			name:    "should generate 4096-bit key pair successfully",
			bitSize: 4096,
			wantErr: false,
		},
		{
			name:    "should fail with invalid bit size",
			bitSize: 512,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, publicKey, err := GenerateKeyPair(tt.bitSize)

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

			if privateKey == nil {
				t.Error("private key is nil")
			}

			if publicKey == nil {
				t.Error("public key is nil")
			}

			// Verify key size
			if privateKey != nil && privateKey.N.BitLen() != tt.bitSize {
				t.Errorf("expected key size %d, got %d", tt.bitSize, privateKey.N.BitLen())
			}
		})
	}
}

func TestSaveKeyPair(t *testing.T) {
	// Generate a test key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	tests := []struct {
		name           string
		privateKeyPath string
		publicKeyPath  string
		setupFunc      func(string, string) error
		wantErr        bool
	}{
		{
			name:           "should save key pair to valid paths",
			privateKeyPath: filepath.Join(t.TempDir(), "private.pem"),
			publicKeyPath:  filepath.Join(t.TempDir(), "public.pem"),
			setupFunc:      nil,
			wantErr:        false,
		},
		{
			name:           "should fail when directory does not exist",
			privateKeyPath: "/nonexistent/directory/private.pem",
			publicKeyPath:  "/nonexistent/directory/public.pem",
			setupFunc:      nil,
			wantErr:        true,
		},
		{
			name:           "should fail when path is read-only",
			privateKeyPath: "",
			publicKeyPath:  "",
			setupFunc: func(privPath, pubPath string) error {
				// Create read-only directory
				dir := t.TempDir()
				if err := os.Chmod(dir, 0444); err != nil {
					return err
				}
				return nil
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privPath := tt.privateKeyPath
			pubPath := tt.publicKeyPath

			if tt.setupFunc != nil {
				if err := tt.setupFunc(privPath, pubPath); err != nil {
					t.Skipf("setup failed: %v", err)
				}
			}

			err := SaveKeyPair(privateKey, privPath, pubPath)

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

			// Verify files exist
			if _, err := os.Stat(privPath); os.IsNotExist(err) {
				t.Error("private key file was not created")
			}

			if _, err := os.Stat(pubPath); os.IsNotExist(err) {
				t.Error("public key file was not created")
			}

			// Verify file permissions
			privInfo, err := os.Stat(privPath)
			if err != nil {
				t.Errorf("failed to stat private key file: %v", err)
			} else if privInfo.Mode().Perm() != 0600 {
				t.Errorf("expected private key permissions 0600, got %o", privInfo.Mode().Perm())
			}
		})
	}
}

func TestLoadPrivateKeyFromFile(t *testing.T) {
	// Generate a test key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	tests := []struct {
		name       string
		setupFunc  func() (string, error)
		wantErr    bool
		errMessage string
	}{
		{
			name: "should load valid private key from file",
			setupFunc: func() (string, error) {
				tmpFile := filepath.Join(t.TempDir(), "private.pem")
				privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
				pemBlock := &pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: privBytes,
				}
				return tmpFile, os.WriteFile(tmpFile, pem.EncodeToMemory(pemBlock), 0600)
			},
			wantErr: false,
		},
		{
			name: "should fail when file does not exist",
			setupFunc: func() (string, error) {
				return "/nonexistent/private.pem", nil
			},
			wantErr:    true,
			errMessage: "file does not exist",
		},
		{
			name: "should fail with invalid PEM format",
			setupFunc: func() (string, error) {
				tmpFile := filepath.Join(t.TempDir(), "invalid.pem")
				return tmpFile, os.WriteFile(tmpFile, []byte("not a valid PEM"), 0600)
			},
			wantErr:    true,
			errMessage: "invalid PEM format",
		},
		{
			name: "should fail with wrong key type",
			setupFunc: func() (string, error) {
				tmpFile := filepath.Join(t.TempDir(), "wrong_type.pem")
				pemBlock := &pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: []byte("wrong data"),
				}
				return tmpFile, os.WriteFile(tmpFile, pem.EncodeToMemory(pemBlock), 0600)
			},
			wantErr:    true,
			errMessage: "wrong key type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath, err := tt.setupFunc()
			if err != nil {
				t.Fatalf("setup failed: %v", err)
			}

			loadedKey, err := LoadPrivateKeyFromFile(keyPath)

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

			if loadedKey == nil {
				t.Fatalf("loaded key is nil")
			}

			// Verify the loaded key matches the original
			if loadedKey.N.Cmp(privateKey.N) != 0 {
				t.Error("loaded key does not match original key")
			}
		})
	}
}

func TestLoadPublicKeyFromFile(t *testing.T) {
	// Generate a test key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	tests := []struct {
		name       string
		setupFunc  func() (string, error)
		wantErr    bool
		errMessage string
	}{
		{
			name: "should load valid public key from file",
			setupFunc: func() (string, error) {
				tmpFile := filepath.Join(t.TempDir(), "public.pem")
				pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
				if err != nil {
					return "", err
				}
				pemBlock := &pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubBytes,
				}
				return tmpFile, os.WriteFile(tmpFile, pem.EncodeToMemory(pemBlock), 0644)
			},
			wantErr: false,
		},
		{
			name: "should fail when file does not exist",
			setupFunc: func() (string, error) {
				return "/nonexistent/public.pem", nil
			},
			wantErr:    true,
			errMessage: "file does not exist",
		},
		{
			name: "should fail with invalid PEM format",
			setupFunc: func() (string, error) {
				tmpFile := filepath.Join(t.TempDir(), "invalid.pem")
				return tmpFile, os.WriteFile(tmpFile, []byte("not a valid PEM"), 0644)
			},
			wantErr:    true,
			errMessage: "invalid PEM format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath, err := tt.setupFunc()
			if err != nil {
				t.Fatalf("setup failed: %v", err)
			}

			loadedKey, err := LoadPublicKeyFromFile(keyPath)

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

			if loadedKey == nil {
				t.Fatalf("loaded key is nil")
			}

			// Verify the loaded key matches the original
			if loadedKey.N.Cmp(publicKey.N) != 0 {
				t.Error("loaded public key does not match original key")
			}
		})
	}
}

func TestLoadPrivateKeyFromEnv(t *testing.T) {
	// Generate a test key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	}
	validPEM := string(pem.EncodeToMemory(pemBlock))

	tests := []struct {
		name       string
		envVarName string
		envValue   string
		wantErr    bool
	}{
		{
			name:       "should load valid private key from environment variable",
			envVarName: "TEST_PRIVATE_KEY",
			envValue:   validPEM,
			wantErr:    false,
		},
		{
			name:       "should fail when environment variable is not set",
			envVarName: "NONEXISTENT_KEY",
			envValue:   "",
			wantErr:    true,
		},
		{
			name:       "should fail with invalid PEM in environment variable",
			envVarName: "INVALID_PRIVATE_KEY",
			envValue:   "not a valid PEM",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			if tt.envValue != "" {
				os.Setenv(tt.envVarName, tt.envValue)
				defer os.Unsetenv(tt.envVarName)
			}

			loadedKey, err := LoadPrivateKeyFromEnv(tt.envVarName)

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

			if loadedKey == nil {
				t.Error("loaded key is nil")
			}
		})
	}
}

func TestLoadPublicKeyFromEnv(t *testing.T) {
	// Generate a test key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	validPEM := string(pem.EncodeToMemory(pemBlock))

	tests := []struct {
		name       string
		envVarName string
		envValue   string
		wantErr    bool
	}{
		{
			name:       "should load valid public key from environment variable",
			envVarName: "TEST_PUBLIC_KEY",
			envValue:   validPEM,
			wantErr:    false,
		},
		{
			name:       "should fail when environment variable is not set",
			envVarName: "NONEXISTENT_KEY",
			envValue:   "",
			wantErr:    true,
		},
		{
			name:       "should fail with invalid PEM in environment variable",
			envVarName: "INVALID_PUBLIC_KEY",
			envValue:   "not a valid PEM",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			if tt.envValue != "" {
				os.Setenv(tt.envVarName, tt.envValue)
				defer os.Unsetenv(tt.envVarName)
			}

			loadedKey, err := LoadPublicKeyFromEnv(tt.envVarName)

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

			if loadedKey == nil {
				t.Error("loaded key is nil")
			}
		})
	}
}
