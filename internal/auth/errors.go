package auth

import "errors"

var (
	// ErrMissingToken is returned when Authorization is absent or not Bearer.
	ErrMissingToken = errors.New("missing or invalid Authorization bearer token")
	// ErrInvalidToken is returned when JWT signature/claims validation fails.
	ErrInvalidToken = errors.New("invalid or expired access token")
	// ErrForbidden is returned when the principal is authenticated but not authorized
	// for the requested Namespace.
	ErrForbidden = errors.New("principal not authorized for namespace")
	// ErrMissingNamespace is returned when X-Namespace is absent.
	ErrMissingNamespace = errors.New("X-Namespace header required")
)
