package codec_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	proxycrypto "github.com/temporalio/temporal-proxy/pkg/crypto"
	commonpb "go.temporal.io/api/common/v1"

	"github.com/bitovi/temporal-codec/internal/codec"
)

// Wire metadata keys must match temporal-proxy internal/proxy/encryption.go
// (and codec.Manager payload adapter). Source pin: temporal-proxy v0.4.0.
const (
	proxyMetadataEncoding        = "encoding"
	proxyMetadataEncryptionKeyID = "encryption-key-id"
	proxyMetadataEncryptionDEK   = "encryption-dek"
	proxyEncryptionEncoding      = "binary/encrypted"
)

// proxyEncryptPayloads mirrors temporal-proxy encryptPayloads: marshal entire
// payload, Vault.Seal, set encoding / encryption-key-id / encryption-dek.
// Uses only temporal-proxy pkg/crypto for encrypt (no codec.Manager.Encode).
func proxyEncryptPayloads(t *testing.T, vault *proxycrypto.Vault, namespace string, payloads []*commonpb.Payload) []*commonpb.Payload {
	t.Helper()
	ctx := context.Background()
	out := make([]*commonpb.Payload, len(payloads))
	for i, p := range payloads {
		data, err := p.Marshal()
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		msg, err := vault.Seal(ctx, namespace, data)
		if err != nil {
			t.Fatalf("proxy Seal: %v", err)
		}
		out[i] = &commonpb.Payload{
			Metadata: map[string][]byte{
				proxyMetadataEncoding:        []byte(proxyEncryptionEncoding),
				proxyMetadataEncryptionKeyID: []byte(msg.KeyMaterial.KEKID),
				proxyMetadataEncryptionDEK:   []byte(msg.KeyMaterial.EncryptedDEK),
			},
			Data: msg.Ciphertext,
		}
	}
	return out
}

func newProxyVault(t *testing.T, uri string) (*proxycrypto.Vault, func()) {
	t.Helper()
	ctx := context.Background()
	factory := proxycrypto.NewKeyFactory()
	kek, err := factory.Create(ctx, uri)
	if err != nil {
		t.Fatalf("open testing KEK: %v", err)
	}
	reg, err := proxycrypto.NewKEKRegistry(proxycrypto.WithDefaultKey(kek))
	if err != nil {
		_ = kek.Close()
		t.Fatalf("registry: %v", err)
	}
	vault, err := proxycrypto.NewVault(reg,
		proxycrypto.WithDefaultKeyConfig(proxycrypto.KeyConfig{
			Duration:    time.Hour,
			RenewBefore: 15 * time.Minute,
		}),
		proxycrypto.WithCacheSize(32),
	)
	if err != nil {
		_ = reg.Close()
		t.Fatalf("vault: %v", err)
	}
	return vault, func() { _ = reg.Close() }
}

// TestProxyEncrypt_CodecDecrypt_wireCompat simulates Temporal Cloud UI decode:
// workers write via temporal-proxy envelope encryption; codec server only
// decrypts. CI uses testing://; accept with awskms:// against a real key later.
func TestProxyEncrypt_CodecDecode_wireCompat(t *testing.T) {
	ctx := context.Background()
	ns := "payments"

	vault, closeVault := newProxyVault(t, testingURI)
	defer closeVault()

	plain := []*commonpb.Payload{{
		Metadata: map[string][]byte{"encoding": []byte("json/plain")},
		Data:     []byte(`{"hello":"proxy-wire"}`),
	}}
	cipher := proxyEncryptPayloads(t, vault, ns, plain)

	if string(cipher[0].GetMetadata()[proxyMetadataEncoding]) != proxyEncryptionEncoding {
		t.Fatalf("encoding=%q", cipher[0].GetMetadata()[proxyMetadataEncoding])
	}
	if len(cipher[0].GetMetadata()[proxyMetadataEncryptionKeyID]) == 0 {
		t.Fatal("missing encryption-key-id")
	}
	if len(cipher[0].GetMetadata()[proxyMetadataEncryptionDEK]) == 0 {
		t.Fatal("missing encryption-dek")
	}
	if bytes.Equal(cipher[0].GetData(), plain[0].GetData()) {
		t.Fatal("ciphertext must not equal plaintext")
	}

	// Decode-only path: Manager without relying on Encode.
	mgr, err := codec.New(ctx, codec.Options{DefaultURI: testingURI})
	if err != nil {
		t.Fatalf("codec manager: %v", err)
	}
	defer func() { _ = mgr.Close() }()

	got, err := mgr.PayloadCodec(ctx, ns).Decode(cipher)
	if err != nil {
		t.Fatalf("codec decode: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("decoded len=%d", len(got))
	}
	if !bytes.Equal(got[0].GetData(), plain[0].GetData()) {
		t.Fatalf("data mismatch: got %q want %q", got[0].GetData(), plain[0].GetData())
	}
	if string(got[0].GetMetadata()["encoding"]) != "json/plain" {
		t.Fatalf("restored encoding=%q", got[0].GetMetadata()["encoding"])
	}
}

// Acceptance with awskms:// is manual / env-gated (needs KMS + IRSA).
// Set WIRECOMPAT_AWSKMS_URI=awskms://alias/... to exercise the same gate.
func TestProxyEncrypt_CodecDecode_awskmsOptional(t *testing.T) {
	uri := os.Getenv("WIRECOMPAT_AWSKMS_URI")
	if uri == "" {
		t.Skip("set WIRECOMPAT_AWSKMS_URI=awskms://... for KMS acceptance (ADR 0008 gate 1)")
	}
	ctx := context.Background()
	ns := "payments"

	vault, closeVault := newProxyVault(t, uri)
	defer closeVault()

	plain := []*commonpb.Payload{{
		Metadata: map[string][]byte{"encoding": []byte("json/plain")},
		Data:     []byte(`{"hello":"awskms"}`),
	}}
	cipher := proxyEncryptPayloads(t, vault, ns, plain)

	mgr, err := codec.New(ctx, codec.Options{DefaultURI: uri})
	if err != nil {
		t.Fatalf("codec manager: %v", err)
	}
	defer func() { _ = mgr.Close() }()

	got, err := mgr.PayloadCodec(ctx, ns).Decode(cipher)
	if err != nil {
		t.Fatalf("codec decode: %v", err)
	}
	if !bytes.Equal(got[0].GetData(), plain[0].GetData()) {
		t.Fatalf("data mismatch under awskms")
	}
}
