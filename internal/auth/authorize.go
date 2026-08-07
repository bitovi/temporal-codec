package auth

import (
	"context"
	"strings"

	"github.com/bitovi/temporal-codec/internal/shared"
)

// ClaimAuthorizer authorizes when the principal's namespace claim list includes
// the requested Namespace. Two forms are accepted:
//   - exact match: claim "payments.acct" authorizes request "payments.acct"
//   - short-name match: claim "payments" authorizes request "payments.acct123"
//     (claim carries the short name, request carries the Cloud full name)
//
// Notably, a full-name claim does NOT authorize a different full-name namespace:
// claim "payments.accountA" does not authorize "payments.accountB".
//
// Fail-closed: empty or missing permission claims deny all namespaces.
//
// TODO(production): Confirm Temporal Cloud JWT claim schema for namespace
// membership against live passAccessToken JWTs (see extractNamespaces note).
type ClaimAuthorizer struct{}

// Authorize implements Authorizer.
func (ClaimAuthorizer) Authorize(_ context.Context, principal Principal, namespace string) error {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return ErrMissingNamespace
	}
	if len(principal.Namespaces) == 0 {
		return ErrForbidden
	}

	wantShort := shared.ShortName(namespace)
	for _, allowed := range principal.Namespaces {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}
		// equalNS(allowed, namespace): exact match (full or short name)
		// equalNS(allowed, wantShort): claim is the short name, request is full Cloud form
		if equalNS(allowed, namespace) || equalNS(allowed, wantShort) {
			return nil
		}
	}
	return ErrForbidden
}

// StaticAuthorizer is a test/dev authorizer: subject -> allowed namespaces.
type StaticAuthorizer struct {
	// Allow maps subject (or "*") to namespaces. Use "*" namespace to allow all
	// for that subject in tests only.
	Allow map[string][]string
}

// Authorize implements Authorizer.
func (s StaticAuthorizer) Authorize(_ context.Context, principal Principal, namespace string) error {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return ErrMissingNamespace
	}
	allowed := s.Allow[principal.Subject]
	if allowed == nil {
		allowed = s.Allow["*"]
	}
	if allowed == nil {
		return ErrForbidden
	}
	wantShort := shared.ShortName(namespace)
	for _, a := range allowed {
		if a == "*" || equalNS(a, namespace) || equalNS(a, wantShort) {
			return nil
		}
	}
	return ErrForbidden
}

// AllowAllAuthorizer is only for AUTH_DISABLED / local development.
type AllowAllAuthorizer struct{}

// Authorize always returns nil.
func (AllowAllAuthorizer) Authorize(_ context.Context, _ Principal, namespace string) error {
	if strings.TrimSpace(namespace) == "" {
		return ErrMissingNamespace
	}
	return nil
}

func equalNS(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
