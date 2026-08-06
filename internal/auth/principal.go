package auth

import "context"

// Principal is the authenticated caller after JWT validation.
// Tokens and bearer secrets never appear on this type.
type Principal struct {
	Subject    string
	Email      string
	Namespaces []string
	RawClaims  map[string]any
}

// Validator verifies Temporal Cloud JWTs (passAccessToken bearer).
type Validator interface {
	Validate(ctx context.Context, bearerToken string) (Principal, error)
}

// Authorizer decides whether a principal may encode/decode for a Temporal Namespace.
// X-Namespace alone must never grant access; the Authorizer binds the token principal
// to the requested namespace.
type Authorizer interface {
	// Authorize returns nil when allowed. ErrUnauthorized when denied.
	Authorize(ctx context.Context, principal Principal, namespace string) error
}
