package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"

	"github.com/bitovi/temporal-codec/internal/auth"
)

const testAudience = "https://saas-api.tmprl.cloud"

func TestClaimAuthorizer_wrongNamespaceDenied(t *testing.T) {
	a := auth.ClaimAuthorizer{}
	p := auth.Principal{Subject: "user-a", Namespaces: []string{"payments"}}
	if err := a.Authorize(context.Background(), p, "orders"); err == nil {
		t.Fatal("expected deny for unauthorized namespace")
	}
}

func TestClaimAuthorizer_authorizedNamespaceAllowed(t *testing.T) {
	a := auth.ClaimAuthorizer{}
	p := auth.Principal{Subject: "user-a", Namespaces: []string{"payments"}}
	if err := a.Authorize(context.Background(), p, "payments"); err != nil {
		t.Fatalf("expected allow: %v", err)
	}
	// Cloud-style X-Namespace matches short claim.
	if err := a.Authorize(context.Background(), p, "payments.acct123"); err != nil {
		t.Fatalf("expected allow for cloud ns form: %v", err)
	}
}

func TestClaimAuthorizer_xNamespaceAloneNeverAuthorizes(t *testing.T) {
	a := auth.ClaimAuthorizer{}
	p := auth.Principal{Subject: "user-a"} // no permission claims
	if err := a.Authorize(context.Background(), p, "payments"); err == nil {
		t.Fatal("expected deny when token has no namespace permissions")
	}
}

func TestEmailAuthorizer_emailACLallow(t *testing.T) {
	acl := map[string][]string{
		"alice@example.com": {"payments"},
		"bob@example.com":   {"orders", "inventory"},
	}
	authorizer := auth.EmailAuthorizer{ACL: acl, Fallback: auth.ClaimAuthorizer{}}

	// Alice can access payments
	p := auth.Principal{Email: "alice@example.com"}
	if err := authorizer.Authorize(context.Background(), p, "payments"); err != nil {
		t.Fatalf("expected allow: %v", err)
	}

	// Bob can access orders and inventory
	p = auth.Principal{Email: "bob@example.com"}
	if err := authorizer.Authorize(context.Background(), p, "orders"); err != nil {
		t.Fatalf("expected allow: %v", err)
	}

	// Alice cannot access orders
	p = auth.Principal{Email: "alice@example.com"}
	if err := authorizer.Authorize(context.Background(), p, "orders"); err == nil {
		t.Fatal("expected deny")
	}
}

func TestEmailAuthorizer_caseInsensitiveEmail(t *testing.T) {
	acl := map[string][]string{
		"alice@example.com": {"payments"},
	}
	authorizer := auth.EmailAuthorizer{ACL: acl, Fallback: auth.ClaimAuthorizer{}}

	// Uppercase email should still match (normalized to lowercase)
	p := auth.Principal{Email: "ALICE@EXAMPLE.COM"}
	if err := authorizer.Authorize(context.Background(), p, "payments"); err != nil {
		t.Fatalf("expected allow for case-insensitive match: %v", err)
	}
}

func TestEmailAuthorizer_fallbackToClaimAuth(t *testing.T) {
	acl := map[string][]string{
		"alice@example.com": {"payments"},
	}
	authorizer := auth.EmailAuthorizer{ACL: acl, Fallback: auth.ClaimAuthorizer{}}

	// User not in ACL falls back to claim auth
	p := auth.Principal{
		Email:      "charlie@example.com",
		Namespaces: []string{"reports"},
	}
	if err := authorizer.Authorize(context.Background(), p, "reports"); err != nil {
		t.Fatalf("expected fallback to allow: %v", err)
	}

	// Fallback denies if namespace not in claims
	if err := authorizer.Authorize(context.Background(), p, "payments"); err == nil {
		t.Fatal("expected fallback deny")
	}
}

func TestEmailAuthorizer_LoadACL_reloadOnRead(t *testing.T) {
	acl := map[string][]string{
		"alice@example.com": {"payments"},
	}
	calls := 0
	authorizer := auth.EmailAuthorizer{
		LoadACL: func() map[string][]string {
			calls++
			return acl
		},
		Fallback: auth.ClaimAuthorizer{},
	}

	p := auth.Principal{Email: "alice@example.com"}
	if err := authorizer.Authorize(context.Background(), p, "payments"); err != nil {
		t.Fatalf("expected allow: %v", err)
	}
	// Mutate underlying map — next authorize must see the update
	acl["alice@example.com"] = []string{"orders"}
	if err := authorizer.Authorize(context.Background(), p, "payments"); err == nil {
		t.Fatal("expected deny after ACL reload removed payments")
	}
	if err := authorizer.Authorize(context.Background(), p, "orders"); err != nil {
		t.Fatalf("expected allow for orders after reload: %v", err)
	}
	if calls < 3 {
		t.Fatalf("expected LoadACL called per authorize, got %d", calls)
	}
}

func TestMiddleware_validJWTWrongNamespace403(t *testing.T) {
	priv, kf := testRSAKeyfunc(t)
	validator, err := auth.NewJWKSValidatorFromKeyfunc(kf, auth.JWKSConfig{
		Audience:        testAudience,
		PermissionClaim: "permissions",
	})
	if err != nil {
		t.Fatal(err)
	}

	token := signToken(t, priv, map[string]any{
		"sub":         "user-a",
		"aud":         testAudience,
		"exp":         time.Now().Add(time.Hour).Unix(),
		"permissions": []string{"payments"},
	})

	called := false
	h := auth.Middleware(validator, auth.ClaimAuthorizer{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/decode", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Namespace", "orders")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if called {
		t.Fatal("handler must not run when namespace unauthorized (no decrypt)")
	}
}

func TestMiddleware_authorizedNamespaceAllows(t *testing.T) {
	priv, kf := testRSAKeyfunc(t)
	validator, err := auth.NewJWKSValidatorFromKeyfunc(kf, auth.JWKSConfig{
		Audience:        testAudience,
		PermissionClaim: "permissions",
	})
	if err != nil {
		t.Fatal(err)
	}

	token := signToken(t, priv, map[string]any{
		"sub":         "user-a",
		"aud":         testAudience,
		"exp":         time.Now().Add(time.Hour).Unix(),
		"permissions": []string{"payments"},
	})

	called := false
	h := auth.Middleware(validator, auth.ClaimAuthorizer{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		p, ok := auth.PrincipalFrom(r.Context())
		if !ok || p.Subject != "user-a" {
			t.Errorf("missing principal")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/decode", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Namespace", "payments")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !called {
		t.Fatal("expected handler invocation")
	}
}

func TestMiddleware_missingToken401(t *testing.T) {
	h := auth.Middleware(auth.DisabledValidator{}, auth.AllowAllAuthorizer{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not run")
	}))
	req := httptest.NewRequest(http.MethodPost, "/decode", nil)
	req.Header.Set("X-Namespace", "payments")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
}

func testRSAKeyfunc(t *testing.T) (*rsa.PrivateKey, keyfunc.Keyfunc) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store := jwkset.NewMemoryStorage()
	jwk, err := jwkset.NewJWKFromKey(priv, jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{KID: "test-key"},
		Marshal:  jwkset.JWKMarshalOptions{Private: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.KeyWrite(ctx, jwk); err != nil {
		t.Fatal(err)
	}
	// Ensure storage is readable as public JWKS JSON (sanity).
	if _, err := store.JSONPublic(ctx); err != nil {
		t.Fatal(err)
	}
	kf, err := keyfunc.New(keyfunc.Options{Ctx: ctx, Storage: store})
	if err != nil {
		t.Fatal(err)
	}
	return priv, kf
}

func signToken(t *testing.T, priv *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	// Normalize claims into MapClaims with registered types.
	mc := jwt.MapClaims{}
	for k, v := range claims {
		mc[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, mc)
	tok.Header["kid"] = "test-key"
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	// Ensure JSON serializable claims for debugging of failures without logging secrets.
	_ = json.Marshal
	return s
}

func TestBitoviEmailAuthorizer_bitovi_com_allowed(t *testing.T) {
	a := auth.BitoviEmailAuthorizer{}
	p := auth.Principal{Subject: "user-a", Email: "mchaffe@bitovi.com"}
	if err := a.Authorize(context.Background(), p, "payments"); err != nil {
		t.Fatalf("expected allow for @bitovi.com email: %v", err)
	}
}

func TestBitoviEmailAuthorizer_bitovi_com_case_insensitive(t *testing.T) {
	a := auth.BitoviEmailAuthorizer{}
	p := auth.Principal{Subject: "user-a", Email: "MChaffe@BITOVI.COM"}
	if err := a.Authorize(context.Background(), p, "payments"); err != nil {
		t.Fatalf("expected allow for case-insensitive @bitovi.com email: %v", err)
	}
}

func TestBitoviEmailAuthorizer_non_bitovi_denied(t *testing.T) {
	a := auth.BitoviEmailAuthorizer{}
	p := auth.Principal{Subject: "user-a", Email: "user@example.com"}
	if err := a.Authorize(context.Background(), p, "payments"); err == nil {
		t.Fatal("expected deny for non-@bitovi.com email")
	}
}

func TestBitoviEmailAuthorizer_empty_email_denied(t *testing.T) {
	a := auth.BitoviEmailAuthorizer{}
	p := auth.Principal{Subject: "user-a", Email: ""}
	if err := a.Authorize(context.Background(), p, "payments"); err == nil {
		t.Fatal("expected deny for empty email")
	}
}

func TestBitoviEmailAuthorizer_missing_namespace_denied(t *testing.T) {
	a := auth.BitoviEmailAuthorizer{}
	p := auth.Principal{Subject: "user-a", Email: "mchaffe@bitovi.com"}
	if err := a.Authorize(context.Background(), p, ""); err == nil {
		t.Fatal("expected deny for missing namespace")
	}
}
