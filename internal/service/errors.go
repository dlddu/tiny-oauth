package service

import "fmt"

// OAuthError represents an OAuth 2.0 error response
type OAuthError struct {
	Code             string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

func (e *OAuthError) Error() string {
	return e.Code
}

// OAuth 2.0 error constructors
func NewInvalidRequestError(description string) *OAuthError {
	return &OAuthError{
		Code:             "invalid_request",
		ErrorDescription: description,
	}
}

func NewInvalidClientError(description string) *OAuthError {
	return &OAuthError{
		Code:             "invalid_client",
		ErrorDescription: description,
	}
}

func NewInvalidGrantError(description string) *OAuthError {
	return &OAuthError{
		Code:             "invalid_grant",
		ErrorDescription: description,
	}
}

func NewUnauthorizedClientError(description string) *OAuthError {
	return &OAuthError{
		Code:             "unauthorized_client",
		ErrorDescription: description,
	}
}

func NewUnsupportedGrantTypeError(description string) *OAuthError {
	return &OAuthError{
		Code:             "unsupported_grant_type",
		ErrorDescription: description,
	}
}

func NewInvalidScopeError(description string) *OAuthError {
	return &OAuthError{
		Code:             "invalid_scope",
		ErrorDescription: description,
	}
}

// Simple error type that returns just the error code
type simpleOAuthError string

func (e simpleOAuthError) Error() string {
	return string(e)
}

// Simple error constants for tests
const (
	ErrInvalidRequest       = simpleOAuthError("invalid_request")
	ErrInvalidClient        = simpleOAuthError("invalid_client")
	ErrInvalidGrant         = simpleOAuthError("invalid_grant")
	ErrUnauthorizedClient   = simpleOAuthError("unauthorized_client")
	ErrUnsupportedGrantType = simpleOAuthError("unsupported_grant_type")
	ErrInvalidScope         = simpleOAuthError("invalid_scope")
)

// Helper to create simple errors that match test expectations
func newSimpleError(code string) error {
	return fmt.Errorf(code)
}
