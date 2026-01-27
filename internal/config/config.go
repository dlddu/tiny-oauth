package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds the application configuration
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	OAuth    OAuthConfig
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	Port    string
	BaseURL string
}

// DatabaseConfig holds database connection configuration
type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// JWTConfig holds JWT-related configuration
type JWTConfig struct {
	PrivateKeyPath string
	PublicKeyPath  string
	Issuer         string
}

// OAuthConfig holds OAuth-specific configuration
type OAuthConfig struct {
	AccessTokenTTL       time.Duration
	RefreshTokenTTL      time.Duration
	AuthorizationCodeTTL time.Duration
}

// Load returns a new Config populated from environment variables
func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Port:    getEnv("PORT", "8080"),
			BaseURL: getEnv("BASE_URL", "http://localhost:8080"),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnvAsInt("DB_PORT", 5432),
			User:     getEnv("DB_USER", "oauth"),
			Password: getEnv("DB_PASSWORD", ""),
			DBName:   getEnv("DB_NAME", "tiny_oauth"),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
		JWT: JWTConfig{
			PrivateKeyPath: getEnv("JWT_PRIVATE_KEY_PATH", "keys/private.pem"),
			PublicKeyPath:  getEnv("JWT_PUBLIC_KEY_PATH", "keys/public.pem"),
			Issuer:         getEnv("JWT_ISSUER", "http://localhost:8080"),
		},
		OAuth: OAuthConfig{
			AccessTokenTTL:       getEnvAsDuration("ACCESS_TOKEN_TTL", 15*time.Minute),
			RefreshTokenTTL:      getEnvAsDuration("REFRESH_TOKEN_TTL", 7*24*time.Hour),
			AuthorizationCodeTTL: getEnvAsDuration("AUTHORIZATION_CODE_TTL", 10*time.Minute),
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
