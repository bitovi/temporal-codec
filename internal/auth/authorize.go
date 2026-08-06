package auth

import (
	"context"
	"strings"
)

// ClaimAuthorizer authorizes when the principal's namespace claim list includes
// the requested Namespace. X-Namespace is compared as supplied and also as its
// short name (prefix before first '.') so Cloud forms like "payments.acct"
// match a claim of "payments".
//
// Fail-closed: empty or missing permission claims deny all namespaces.
//
// TODO(production): Confirm Temporal Cloud JWT claim schema for namespace
// membership against live passAccessToken JWTs. Until then, principals only
// pass when permissions appear under TEMPORAL_NAMESPACE_PERMISSION_CLAIM
// (default "permissions") or the provisional keys listed in extractNamespaces.
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

	wantShort := shortName(namespace)
	for _, allowed := range principal.Namespaces {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}
		if equalNS(allowed, namespace) || equalNS(shortName(allowed), wantShort) {
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
	wantShort := shortName(namespace)
	for _, a := range allowed {
		if a == "*" || equalNS(a, namespace) || equalNS(shortName(a), wantShort) {
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

func shortName(ns string) string {
	if i := strings.IndexByte(ns, '.'); i > 0 {
		return ns[:i]
	}
	return ns
}

func equalNS(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
