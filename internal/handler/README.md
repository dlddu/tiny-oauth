# Token Handler Tests

This directory contains tests for the OAuth 2.0 token endpoint handler.

## Test File

- `token_handler_test.go` - Tests for `/oauth/token` endpoint

## Test Coverage

### Client Credentials Grant - Basic Auth (`TestTokenHandler_ClientCredentialsGrant_BasicAuth`)

Tests the client credentials flow using HTTP Basic Authentication:

1. **Happy Path**:
   - Valid credentials with Basic Auth → 200 + access_token
   - Token with requested scope → 200 + access_token
   - Token with multiple scopes → 200 + access_token

2. **Error Cases**:
   - Invalid client_id → 401 + invalid_client
   - Invalid client_secret → 401 + invalid_client
   - Missing grant_type → 400 + invalid_request
   - Unsupported grant_type → 400 + unsupported_grant_type
   - Client doesn't support client_credentials → 400 + unauthorized_client
   - Missing Authorization header → 401 + invalid_client
   - Malformed Authorization header → 401 + invalid_client

### Client Credentials Grant - POST Body (`TestTokenHandler_ClientCredentialsGrant_PostBody`)

Tests the client credentials flow using credentials in POST body:

1. **Happy Path**:
   - Valid credentials in POST body → 200 + access_token
   - Token with scope in POST body → 200 + access_token

2. **Error Cases**:
   - Invalid client_id in POST body → 401 + invalid_client
   - Invalid client_secret in POST body → 401 + invalid_client
   - Missing client_id → 401 + invalid_client
   - Missing client_secret → 401 + invalid_client

### HTTP Method Validation (`TestTokenHandler_MethodNotAllowed`)

Tests that only POST method is accepted:

- GET → 405 Method Not Allowed
- PUT → 405 Method Not Allowed
- DELETE → 405 Method Not Allowed
- POST → Accepted

### Content-Type Validation (`TestTokenHandler_ContentTypeValidation`)

Tests Content-Type header validation:

- application/x-www-form-urlencoded → Accepted
- application/x-www-form-urlencoded; charset=utf-8 → Accepted
- application/json → Rejected
- text/plain → Rejected

### Scope Validation (`TestTokenHandler_ScopeValidation`)

Tests scope validation:

- Requested scope within allowed scopes → 200 + token
- Scope not allowed for client → 400 + invalid_scope
- No scope requested (use defaults) → 200 + token

### Cache Control Headers (`TestTokenHandler_CacheControlHeaders`)

Tests security headers:

- Cache-Control: no-store
- Pragma: no-cache

## Expected Implementation

The tests expect a `TokenHandler` implementation with the following signature:

```go
package handler

type TokenHandler struct {
    clientService ClientService
    tokenService  TokenService
}

func NewTokenHandler(clientService ClientService, tokenService TokenService) *TokenHandler

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

### Required Interfaces

```go
type ClientService interface {
    AuthenticateClient(ctx context.Context, clientID, clientSecret string) (*domain.Client, error)
    GetClientByID(ctx context.Context, clientID string) (*domain.Client, error)
}

type TokenService interface {
    GenerateAccessToken(ctx context.Context, clientID string, scopes []string) (string, time.Duration, error)
}
```

## Running Tests

```bash
# Run all handler tests
go test -v ./internal/handler/...

# Run specific test
go test -v ./internal/handler/... -run TestTokenHandler_ClientCredentialsGrant_BasicAuth

# Run with coverage
go test -v -cover ./internal/handler/...

# Run with race detection
go test -v -race ./internal/handler/...
```

## Test Status

These tests are currently **FAILING** as they are written following TDD's Red Phase. The handler implementation (`token_handler.go`) needs to be created to make these tests pass.

## OAuth 2.0 Compliance

The tests follow [RFC 6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749):

- Section 2.3: Client Authentication
- Section 4.4: Client Credentials Grant
- Section 5.1: Successful Response
- Section 5.2: Error Response

Error codes used:
- `invalid_request` - Missing or malformed parameter
- `invalid_client` - Client authentication failed
- `unauthorized_client` - Client not authorized for grant type
- `unsupported_grant_type` - Grant type not supported
- `invalid_scope` - Requested scope is invalid

## Next Steps

1. Implement `token_handler.go` with the `TokenHandler` struct
2. Implement client authentication (Basic Auth and POST body)
3. Implement grant_type validation
4. Implement scope validation
5. Implement token generation
6. Run tests and ensure they pass
