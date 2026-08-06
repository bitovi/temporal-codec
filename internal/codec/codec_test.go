package codec_test

import (
	"bytes"
	"context"
	"testing"

	commonpb "go.temporal.io/api/common/v1"

	"github.com/bitovi/temporal-codec/internal/codec"
)

// Fixed 32-byte key material, base64-encoded for testing:// scheme
// (same approach as temporal-proxy POC: testing://…base64…).
const testingURI = "testing://KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio="

func TestRoundTripEncodeDecode(t *testing.T) {
	ctx := context.Background()
	mgr, err := codec.New(ctx, codec.Options{DefaultURI: testingURI})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer func() { _ = mgr.Close() }()

	pc := mgr.PayloadCodec("payments")
	plain := []*commonpb.Payload{{
		Metadata: map[string][]byte{"encoding": []byte("json/plain")},
		Data:     []byte(`{"hello":"world"}`),
	}}

	enc, err := pc.Encode(plain)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(enc) != 1 {
		t.Fatalf("encoded len=%d", len(enc))
	}
	if string(enc[0].GetMetadata()["encoding"]) != "binary/encrypted" {
		t.Fatalf("encoding metadata=%q", enc[0].GetMetadata()["encoding"])
	}
	if len(enc[0].GetMetadata()["encryption-key-id"]) == 0 {
		t.Fatal("missing encryption-key-id")
	}
	if len(enc[0].GetMetadata()["encryption-dek"]) == 0 {
		t.Fatal("missing encryption-dek")
	}
	if bytes.Equal(enc[0].GetData(), plain[0].GetData()) {
		t.Fatal("ciphertext must not equal plaintext data")
	}

	dec, err := pc.Decode(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(dec) != 1 {
		t.Fatalf("decoded len=%d", len(dec))
	}
	if !bytes.Equal(dec[0].GetData(), plain[0].GetData()) {
		t.Fatalf("data mismatch: got %q want %q", dec[0].GetData(), plain[0].GetData())
	}
	if string(dec[0].GetMetadata()["encoding"]) != "json/plain" {
		t.Fatalf("restored encoding=%q", dec[0].GetMetadata()["encoding"])
	}
}

func TestDecodeRejectsForeignNamespaceKey(t *testing.T) {
	// Two distinct testing KEKs (different base64 materials — 32 bytes each).
	const (
		paymentsURI = "testing://QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
		ordersURI   = "testing://QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
	)
	ctx := context.Background()

	ordersVault, closeOrders := newProxyVault(t, ordersURI)
	defer closeOrders()

	plain := []*commonpb.Payload{{
		Metadata: map[string][]byte{"encoding": []byte("json/plain")},
		Data:     []byte(`{"ns":"orders"}`),
	}}
	// Ciphertext sealed under the orders key.
	cipher := proxyEncryptPayloads(t, ordersVault, "orders", plain)

	// Manager authorized as payments must not unwrap orders' DEK.
	mgr, err := codec.New(ctx, codec.Options{
		NamespaceURIs: map[string]string{
			"payments": paymentsURI,
			"orders":   ordersURI,
		},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	defer func() { _ = mgr.Close() }()

	_, err = mgr.PayloadCodec("payments").Decode(cipher)
	if err == nil {
		t.Fatal("expected decrypt to fail for foreign namespace key")
	}
}

func TestResolveURI_platformTemplate(t *testing.T) {
	ctx := context.Background()
	// Template-only would open real KMS; use map + template fallthrough for name not in map.
	// Seed with DefaultURI for Manager construction without AWS.
	mgr, err := codec.New(ctx, codec.Options{
		DefaultURI:           testingURI,
		NamespaceURITemplate: codec.PlatformDefaultURITemplate,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mgr.Close() }()

	// Map empty → template
	uri, err := mgr.ResolveURI("payments.acct123")
	if err != nil {
		t.Fatal(err)
	}
	want := "awskms://alias/platform-managed/payments-codec"
	if uri != want {
		t.Fatalf("uri=%q want %q", uri, want)
	}
}

func TestDecodePassthroughUnencrypted(t *testing.T) {
	ctx := context.Background()
	mgr, err := codec.New(ctx, codec.Options{DefaultURI: testingURI})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mgr.Close() }()

	pc := mgr.PayloadCodec("payments")
	plain := []*commonpb.Payload{{
		Metadata: map[string][]byte{"encoding": []byte("json/plain")},
		Data:     []byte(`ok`),
	}}
	out, err := pc.Decode(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out[0].GetData(), plain[0].GetData()) {
		t.Fatal("passthrough failed")
	}
}
