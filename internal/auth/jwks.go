package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// JWKSConfig configures Temporal Cloud JWT validation via JWKS.
type JWKSConfig struct {
	URL             string
	Audience        string
	Issuer          string
	PermissionClaim string
	RefreshInterval time.Duration
}

// JWKSValidator validates Temporal Cloud JWTs against a JWKS endpoint.
// It never logs tokens.
type JWKSValidator struct {
	kf              keyfunc.Keyfunc
	audience        string
	issuer          string
	permissionClaim string
}

// NewJWKSValidator fetches JWKS and returns a Validator suitable for readiness
// once construction succeeds (JWKS client initialized).
func NewJWKSValidator(ctx context.Context, cfg JWKSConfig) (*JWKSValidator, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("JWKS URL is required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("JWT audience is required")
	}
	if cfg.PermissionClaim == "" {
		cfg.PermissionClaim = "permissions"
	}

	var kf keyfunc.Keyfunc
	var err error
	if cfg.RefreshInterval > 0 {
		kf, err = keyfunc.NewDefaultOverrideCtx(ctx, []string{cfg.URL}, keyfunc.Override{
			RefreshInterval: cfg.RefreshInterval,
		})
	} else {
		kf, err = keyfunc.NewDefaultCtx(ctx, []string{cfg.URL})
	}
	if err != nil {
		return nil, fmt.Errorf("init JWKS: %w", err)
	}

	return &JWKSValidator{
		kf:              kf,
		audience:        cfg.Audience,
		issuer:          cfg.Issuer,
		permissionClaim: cfg.PermissionClaim,
	}, nil
}

// NewJWKSValidatorFromKeyfunc builds a validator from an injected Keyfunc (tests).
func NewJWKSValidatorFromKeyfunc(kf keyfunc.Keyfunc, cfg JWKSConfig) (*JWKSValidator, error) {
	if kf == nil {
		return nil, fmt.Errorf("keyfunc is required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("JWT audience is required")
	}
	if cfg.PermissionClaim == "" {
		cfg.PermissionClaim = "permissions"
	}
	return &JWKSValidator{
		kf:              kf,
		audience:        cfg.Audience,
		issuer:          cfg.Issuer,
		permissionClaim: cfg.PermissionClaim,
	}, nil
}

// Validate parses and verifies a bearer JWT (without the "Bearer " prefix).
func (v *JWKSValidator) Validate(ctx context.Context, bearerToken string) (Principal, error) {
	token := bearerToken
	if token == "" {
		return Principal{}, ErrMissingToken
	}

	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"}),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
	}
	if v.issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(v.issuer))
	}

	// Prefer context-aware key lookup.
	keyFn := v.kf.KeyfuncCtx(ctx)
	parsed, err := jwt.Parse(token, keyFn, parserOpts...)
	if err != nil || parsed == nil || !parsed.Valid {
		return Principal{}, fmt.Errorf("%w", ErrInvalidToken)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return Principal{}, ErrInvalidToken
	}

	principal := Principal{
		Subject:    stringClaim(claims, "sub"),
		Email:      firstNonEmpty(stringClaim(claims, "email"), stringClaim(claims, "https://saas-api.tmprl.cloud/email")),
		Namespaces: extractNamespaces(claims, v.permissionClaim),
		RawClaims:  map[string]any(claims),
	}
	if principal.Subject == "" {
		return Principal{}, fmt.Errorf("%w: missing sub", ErrInvalidToken)
	}
	return principal, nil
}

func stringClaim(claims jwt.MapClaims, key string) string {
	v, ok := claims[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// extractNamespaces reads the namespace list from the configured claim. When
// the configured claim is present and non-empty it is authoritative — other
// claim keys cannot widen access.  If the configured claim is absent, the
// function falls back to a set of well-known Temporal Cloud claim names to
// accommodate dev environments and unconfirmed token schemas.
//
// Production note: pin TEMPORAL_NAMESPACE_PERMISSION_CLAIM against a real
// passAccessToken JWT so the fallback path is never reached in production.
func extractNamespaces(claims jwt.MapClaims, primaryClaim string) []string {
	if ns := claimStringList(claims[primaryClaim]); len(ns) > 0 {
		return ns
	}
	// Fallback for dev / unconfirmed schemas — skips primaryClaim (already empty).
	seen := map[string]struct{}{}
	var out []string
	for _, key := range []string{
		"permissions",
		"namespaces",
		"https://saas-api.tmprl.cloud/permissions",
		"https://saas-api.tmprl.cloud/namespaces",
	} {
		if key == primaryClaim {
			continue
		}
		for _, ns := range claimStringList(claims[key]) {
			if _, ok := seen[ns]; !ok {
				seen[ns] = struct{}{}
				out = append(out, ns)
			}
		}
	}
	return out
}

func claimStringList(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if t == "" {
			return nil
		}
		// Comma-separated fallback implemented in authorize equalNS path via single element.
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}
