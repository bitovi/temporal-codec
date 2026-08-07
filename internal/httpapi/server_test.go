package httpapi_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	proxycrypto "github.com/temporalio/temporal-proxy/pkg/crypto"
	commonpb "go.temporal.io/api/common/v1"

	"github.com/bitovi/temporal-codec/internal/auth"
	"github.com/bitovi/temporal-codec/internal/codec"
	"github.com/bitovi/temporal-codec/internal/httpapi"
)

const testingURI = "testing://KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio="

func TestHealthReady(t *testing.T) {
	mgr, err := codec.New(context.Background(), codec.Options{DefaultURI: testingURI})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mgr.Close() }()

	s := httpapi.New(httpapi.Options{
		Manager:    mgr,
		Validator:  auth.DisabledValidator{},
		Authorizer: auth.AllowAllAuthorizer{},
		Ready:      func() bool { return true },
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Fatalf("body=%v", body)
	}
}

func TestHealthNotReady(t *testing.T) {
	mgr, err := codec.New(context.Background(), codec.Options{DefaultURI: testingURI})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mgr.Close() }()

	s := httpapi.New(httpapi.Options{
		Manager:    mgr,
		Validator:  auth.DisabledValidator{},
		Authorizer: auth.AllowAllAuthorizer{},
		Ready:      func() bool { return false },
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestCORSPreflight(t *testing.T) {
	mgr, err := codec.New(context.Background(), codec.Options{DefaultURI: testingURI})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mgr.Close() }()

	s := httpapi.New(httpapi.Options{
		Manager:     mgr,
		Validator:   auth.DisabledValidator{},
		Authorizer:  auth.AllowAllAuthorizer{},
		CORSOrigins: []string{"https://cloud.temporal.io"},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/decode", nil)
	req.Header.Set("Origin", "https://cloud.temporal.io")
	req.Header.Set("Access-Control-Request-Method", "POST")
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://cloud.temporal.io" {
		t.Fatalf("allow-origin=%q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Fatal("missing allow-headers")
	}
}

func TestEncodeRouteAbsentByDefault(t *testing.T) {
	mgr, err := codec.New(context.Background(), codec.Options{DefaultURI: testingURI})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mgr.Close() }()

	s := httpapi.New(httpapi.Options{
		Manager:    mgr,
		Validator:  auth.DisabledValidator{},
		Authorizer: auth.AllowAllAuthorizer{},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/encode", strings.NewReader(`{"payloads":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer x")
	req.Header.Set("X-Namespace", "payments")
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected encode absent, status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestDecodeHTTP_proxyEncrypted_wireCompat(t *testing.T) {
	ctx := context.Background()
	mgr, err := codec.New(ctx, codec.Options{DefaultURI: testingURI})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mgr.Close() }()

	// Encrypt with temporal-proxy pkg/crypto only (Cloud UI path: no /encode).
	factory := proxycrypto.NewKeyFactory()
	kek, err := factory.Create(ctx, testingURI)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := proxycrypto.NewKEKRegistry(proxycrypto.WithDefaultKey(kek))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reg.Close() }()
	vault, err := proxycrypto.NewVault(reg,
		proxycrypto.WithDefaultKeyConfig(proxycrypto.KeyConfig{Duration: time.Hour, RenewBefore: 15 * time.Minute}),
	)
	if err != nil {
		t.Fatal(err)
	}

	plain := &commonpb.Payload{
		Metadata: map[string][]byte{"encoding": []byte("json/plain")},
		Data:     []byte(`{"hello":"ui-path"}`),
	}
	data, err := plain.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := vault.Seal(ctx, "payments", data)
	if err != nil {
		t.Fatal(err)
	}
	encPayload := &commonpb.Payload{
		Metadata: map[string][]byte{
			"encoding":          []byte("binary/encrypted"),
			"encryption-key-id": []byte(msg.KeyMaterial.KEKID),
			"encryption-dek":    []byte(msg.KeyMaterial.EncryptedDEK),
		},
		Data: msg.Ciphertext,
	}

	// Temporal PayloadCodec HTTP JSON uses base64 for bytes fields.
	body := mustPayloadCodecJSON(t, encPayload)

	s := httpapi.New(httpapi.Options{
		Manager:     mgr,
		Validator:   auth.DisabledValidator{},
		Authorizer:  auth.AllowAllAuthorizer{},
		CORSOrigins: []string{"https://cloud.temporal.io"},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/decode", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("X-Namespace", "payments")
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("decode status=%d body=%s", rr.Code, rr.Body.String())
	}
	wantData := base64.StdEncoding.EncodeToString([]byte(`{"hello":"ui-path"}`))
	if !strings.Contains(rr.Body.String(), wantData) {
		t.Fatalf("decoded body missing cleartext data: %s", rr.Body.String())
	}
}

func TestDecodeHTTP_wrongNamespace403_noDecrypt(t *testing.T) {
	// Authz denies wrong X-Namespace before handleCodec runs (no decrypt).
	mgr, err := codec.New(context.Background(), codec.Options{DefaultURI: testingURI})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mgr.Close() }()

	v := fixedPrincipalValidator{p: auth.Principal{Subject: "user-a", Namespaces: []string{"payments"}}}
	s := httpapi.New(httpapi.Options{
		Manager:    mgr,
		Validator:  v,
		Authorizer: auth.ClaimAuthorizer{},
	})

	calledBody := `{"payloads":[{"metadata":{"encoding":"YmluYXJ5L2VuY3J5cHRlZA=="},"data":"e30="}]}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/decode", strings.NewReader(calledBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer anything")
	req.Header.Set("X-Namespace", "orders")
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

type fixedPrincipalValidator struct {
	p auth.Principal
}

func (v fixedPrincipalValidator) Validate(_ context.Context, _ string) (auth.Principal, error) {
	return v.p, nil
}

func mustPayloadCodecJSON(t *testing.T, p *commonpb.Payload) string {
	t.Helper()
	// Use SDK converter JSON marshal via Encode-to-wire as converter does —
	// Temporal payloads over HTTP use the protojson-ish payload array shape.
	type md map[string]string
	meta := md{}
	for k, v := range p.GetMetadata() {
		meta[k] = base64.StdEncoding.EncodeToString(v)
	}
	payloads := []map[string]any{{
		"metadata": meta,
		"data":     base64.StdEncoding.EncodeToString(p.GetData()),
	}}
	b, err := json.Marshal(map[string]any{"payloads": payloads})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
