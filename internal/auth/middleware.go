package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

type ctxKey int

const principalKey ctxKey = 1

// PrincipalFrom returns the authenticated principal or zero value.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey).(Principal)
	return p, ok
}

// Middleware enforces Bearer JWT validation and Namespace-bound authorization
// for encode/decode. Health and OPTIONS are excluded by the route table.
// X-Namespace is never trusted alone.
func Middleware(v Validator, a Authorizer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ns := strings.TrimSpace(r.Header.Get("X-Namespace"))
			if ns == "" {
				http.Error(w, ErrMissingNamespace.Error(), http.StatusBadRequest)
				return
			}

			raw := r.Header.Get("Authorization")
			token, ok := bearerToken(raw)
			if !ok {
				http.Error(w, ErrMissingToken.Error(), http.StatusUnauthorized)
				return
			}

			principal, err := v.Validate(r.Context(), token)
			if err != nil {
				status := http.StatusUnauthorized
				if errors.Is(err, ErrForbidden) {
					status = http.StatusForbidden
				}
				// Never echo the token or raw JWT validation internals that
				// might include sensitive material.
				http.Error(w, publicAuthError(err), status)
				return
			}

			if err := a.Authorize(r.Context(), principal, ns); err != nil {
				if errors.Is(err, ErrMissingNamespace) {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				// Authenticated but not authorized: 403, and never call KMS.
				http.Error(w, ErrForbidden.Error(), http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), principalKey, principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func bearerToken(header string) (string, bool) {
	header = strings.TrimSpace(header)
	const prefix = "Bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(header[len(prefix):])
	return tok, tok != ""
}

func publicAuthError(err error) string {
	switch {
	case errors.Is(err, ErrMissingToken):
		return ErrMissingToken.Error()
	case errors.Is(err, ErrInvalidToken):
		return ErrInvalidToken.Error()
	case errors.Is(err, ErrForbidden):
		return ErrForbidden.Error()
	default:
		return ErrInvalidToken.Error()
	}
}

// DisabledValidator accepts any non-empty bearer string for AUTH_DISABLED.
type DisabledValidator struct{}

// Validate implements Validator.
func (DisabledValidator) Validate(_ context.Context, bearerToken string) (Principal, error) {
	if strings.TrimSpace(bearerToken) == "" {
		return Principal{}, ErrMissingToken
	}
	return Principal{Subject: "auth-disabled", Namespaces: []string{"*"}}, nil
}
