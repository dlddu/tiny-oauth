.PHONY: test test-verbose test-short test-coverage test-integration lint build run clean help

# Test commands
test: ## Run all tests
	go test -v -race ./...

test-verbose: ## Run tests with verbose output
	go test -v -race -count=1 ./...

test-short: ## Run short tests (skip integration tests)
	go test -v -short ./...

test-coverage: ## Run tests with coverage report
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	go tool cover -func=coverage.out

test-integration: ## Run only integration tests
	go test -v -race -run Integration ./...

# Linting
lint: ## Run golangci-lint
	golangci-lint run --timeout=5m

# Build commands
build: ## Build the server binary
	mkdir -p bin
	go build -o bin/server ./cmd/server

run: ## Run the server (requires database and keys)
	go run ./cmd/server

# Database commands
db-up: ## Start PostgreSQL with docker-compose
	docker-compose up -d postgres

db-down: ## Stop PostgreSQL
	docker-compose down

db-migrate: ## Run database migrations
	@echo "Running migrations..."
	# TODO: Add migration command when migration tool is set up

# Key generation
generate-keys: ## Generate RSA keys for JWT
	./scripts/generate-keys.sh

# Clean
clean: ## Clean build artifacts and test cache
	rm -rf bin/
	rm -f coverage.out coverage.html
	go clean -testcache

# Development
dev: db-up generate-keys ## Setup development environment
	@echo "Development environment ready"
	@echo "Run 'make run' to start the server"

# Help
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
