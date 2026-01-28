package auth

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestParseBasicAuth(t *testing.T) {
	tests := []struct {
		name             string
		authHeader       string
		wantClientID     string
		wantClientSecret string
		wantErr          bool
	}{
		{
			name:             "should parse valid Basic Auth header",
			authHeader:       "Basic " + base64.StdEncoding.EncodeToString([]byte("client123:secret456")),
			wantClientID:     "client123",
			wantClientSecret: "secret456",
			wantErr:          false,
		},
		{
			name:             "should parse Basic Auth with special characters in secret",
			authHeader:       "Basic " + base64.StdEncoding.EncodeToString([]byte("myclient:p@ssw0rd!#$")),
			wantClientID:     "myclient",
			wantClientSecret: "p@ssw0rd!#$",
			wantErr:          false,
		},
		{
			name:             "should parse Basic Auth with colon in secret",
			authHeader:       "Basic " + base64.StdEncoding.EncodeToString([]byte("client:secret:with:colons")),
			wantClientID:     "client",
			wantClientSecret: "secret:with:colons",
			wantErr:          false,
		},
		{
			name:             "should parse Basic Auth with empty secret",
			authHeader:       "Basic " + base64.StdEncoding.EncodeToString([]byte("client:")),
			wantClientID:     "client",
			wantClientSecret: "",
			wantErr:          false,
		},
		{
			name:       "should fail with empty header",
			authHeader: "",
			wantErr:    true,
		},
		{
			name:       "should fail without Basic prefix",
			authHeader: base64.StdEncoding.EncodeToString([]byte("client:secret")),
			wantErr:    true,
		},
		{
			name:       "should fail with wrong scheme",
			authHeader: "Bearer " + base64.StdEncoding.EncodeToString([]byte("client:secret")),
			wantErr:    true,
		},
		{
			name:       "should fail with invalid base64",
			authHeader: "Basic not-valid-base64!!!",
			wantErr:    true,
		},
		{
			name:       "should fail without colon separator",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("clientsecret")),
			wantErr:    true,
		},
		{
			name:       "should fail with empty credentials",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte(":")),
			wantErr:    true,
		},
		{
			name:       "should fail with whitespace only",
			authHeader: "Basic    ",
			wantErr:    true,
		},
		{
			name:       "should fail with case-sensitive scheme",
			authHeader: "basic " + base64.StdEncoding.EncodeToString([]byte("client:secret")),
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientID, clientSecret, err := ParseBasicAuth(tt.authHeader)

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

			if clientID != tt.wantClientID {
				t.Errorf("expected client_id %q, got %q", tt.wantClientID, clientID)
			}

			if clientSecret != tt.wantClientSecret {
				t.Errorf("expected client_secret %q, got %q", tt.wantClientSecret, clientSecret)
			}
		})
	}
}

func TestParseBasicAuthWithURLEncoding(t *testing.T) {
	tests := []struct {
		name             string
		clientID         string
		clientSecret     string
		wantClientID     string
		wantClientSecret string
	}{
		{
			name:             "should handle URL-encoded characters in client_id",
			clientID:         "client%20with%20spaces",
			clientSecret:     "secret",
			wantClientID:     "client%20with%20spaces",
			wantClientSecret: "secret",
		},
		{
			name:             "should handle URL-encoded characters in secret",
			clientID:         "client",
			clientSecret:     "secret%40%23%24",
			wantClientID:     "client",
			wantClientSecret: "secret%40%23%24",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credentials := fmt.Sprintf("%s:%s", tt.clientID, tt.clientSecret)
			authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))

			clientID, clientSecret, err := ParseBasicAuth(authHeader)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if clientID != tt.wantClientID {
				t.Errorf("expected client_id %q, got %q", tt.wantClientID, clientID)
			}

			if clientSecret != tt.wantClientSecret {
				t.Errorf("expected client_secret %q, got %q", tt.wantClientSecret, clientSecret)
			}
		})
	}
}

func TestParseBasicAuthEdgeCases(t *testing.T) {
	t.Run("should handle very long credentials", func(t *testing.T) {
		longClientID := strings.Repeat("a", 1000)
		longSecret := strings.Repeat("b", 1000)

		credentials := fmt.Sprintf("%s:%s", longClientID, longSecret)
		authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))

		clientID, clientSecret, err := ParseBasicAuth(authHeader)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if len(clientID) != 1000 {
			t.Errorf("expected client_id length 1000, got %d", len(clientID))
		}

		if len(clientSecret) != 1000 {
			t.Errorf("expected client_secret length 1000, got %d", len(clientSecret))
		}
	})

	t.Run("should handle unicode characters", func(t *testing.T) {
		credentials := "client_日本語:secret_한글"
		authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))

		clientID, clientSecret, err := ParseBasicAuth(authHeader)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if clientID != "client_日本語" {
			t.Errorf("expected client_id with unicode, got %q", clientID)
		}

		if clientSecret != "secret_한글" {
			t.Errorf("expected client_secret with unicode, got %q", clientSecret)
		}
	})
}
