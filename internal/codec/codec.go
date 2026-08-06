package codec

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"gocloud.dev/secrets"
	_ "gocloud.dev/secrets/awskms"
	_ "gocloud.dev/secrets/localsecrets"

	proxycrypto "github.com/temporalio/temporal-proxy/pkg/crypto"
)

// Wire metadata keys and encoding — must match temporal-proxy internal/proxy/encryption.go.
// Source pin: github.com/temporalio/temporal-proxy v0.4.0
const (
	metadataEncoding        = "encoding"
	metadataEncryptionKeyID = "encryption-key-id"
	metadataEncryptionDEK   = "encryption-dek"
	encryptionEncoding      = "binary/encrypted"

	// PlatformDefaultURITemplate is the platform CMK alias for a Temporal
	// Cloud short name (TCN Composition, ADR 0008): one Cloud namespace → one CMK.
	PlatformDefaultURITemplate = "awskms://alias/platform-managed/%s-codec"
)

// Options configures the payload codec / vault.
type Options struct {
	// DefaultURI is used when a namespace has no map override and no template
	// (unit tests / single-key local). Production prefers NamespaceURITemplate.
	DefaultURI string
	// NamespaceURIs maps Temporal Namespace short name (or full Cloud name) → KEK URI.
	NamespaceURIs map[string]string
	// NamespaceURITemplate is sprintf'd with the Cloud short name when no map
	// entry exists. Production: PlatformDefaultURITemplate.
	NamespaceURITemplate string
	// DEKDuration / RenewBefore mirror temporal-proxy KeyPolicy defaults.
	DEKDuration time.Duration
	RenewBefore time.Duration
	CacheSize   int
}

// Manager builds a PayloadCodec wire-compatible with temporal-proxy envelope encryption
// (awskms://, testing://, etc. via gocloud / pkg/crypto).
//
// Decode is namespace-bound: after auth binds the request to a Temporal
// Namespace, only that namespace's KMS key may unwrap payloads. Never open an
// arbitrary wire encryption-key-id (would allow ns A JWT to decrypt ns B data
// under fleet-reader IRSA).
type Manager struct {
	defaultURI  string
	uriTemplate string
	nsURIs      map[string]string

	vault   *proxycrypto.Vault
	reg     *proxycrypto.KEKRegistry
	factory *proxycrypto.KeyFactory

	mu   sync.Mutex
	keks map[string]proxycrypto.KEK // cache by resolve URI for namespace
}

// New builds a Manager. Call Close when finished.
func New(ctx context.Context, opts Options) (*Manager, error) {
	if opts.DefaultURI == "" && opts.NamespaceURITemplate == "" && len(opts.NamespaceURIs) == 0 {
		return nil, fmt.Errorf("default encryption URI, namespace URI template, or namespace overrides are required")
	}
	if opts.DEKDuration <= 0 {
		opts.DEKDuration = time.Hour
	}
	if opts.RenewBefore <= 0 {
		opts.RenewBefore = 15 * time.Minute
	}
	if opts.CacheSize <= 0 {
		opts.CacheSize = 200
	}
	if opts.NamespaceURIs == nil {
		opts.NamespaceURIs = map[string]string{}
	}

	factory := proxycrypto.NewKeyFactory()

	// Seed registry with DefaultURI when present so Encode and same-key vault
	// Open work for single-key tests. Multi-namespace production keys are
	// opened lazily per authorized short name.
	var defaultKey proxycrypto.KEK
	var regOpts []proxycrypto.KEKRegistryOption
	seenIDs := map[string]struct{}{}

	if opts.DefaultURI != "" {
		k, err := factory.Create(ctx, opts.DefaultURI)
		if err != nil {
			return nil, fmt.Errorf("open default encryption key: %w", err)
		}
		defaultKey = k
		seenIDs[k.ID()] = struct{}{}
		regOpts = append(regOpts, proxycrypto.WithDefaultKey(defaultKey))
	}

	for ns, uri := range opts.NamespaceURIs {
		k, err := factory.Create(ctx, uri)
		if err != nil {
			if defaultKey != nil {
				_ = defaultKey.Close()
			}
			return nil, fmt.Errorf("open encryption key for namespace %q: %w", ns, err)
		}
		if _, dup := seenIDs[k.ID()]; dup {
			_ = k.Close()
			continue
		}
		seenIDs[k.ID()] = struct{}{}
		if defaultKey == nil {
			defaultKey = k
			regOpts = append(regOpts, proxycrypto.WithDefaultKey(k))
		} else {
			regOpts = append(regOpts, proxycrypto.WithKeyForNamespace(ns, k))
			if short := shortName(ns); short != ns {
				regOpts = append(regOpts, proxycrypto.WithKeyForNamespace(short, k))
			}
		}
	}

	if defaultKey == nil {
		// Template-only startup: open a provisional keeper using a placeholder
		// short name so Vault/registry can construct; real decode opens the
		// authorized namespace's URI on demand and never uses this for other NS.
		bootstrapURI := fmt.Sprintf(opts.NamespaceURITemplate, "bootstrap")
		k, err := factory.Create(ctx, bootstrapURI)
		if err != nil {
			return nil, fmt.Errorf("open bootstrap encryption key from template: %w", err)
		}
		defaultKey = k
		regOpts = append(regOpts, proxycrypto.WithDefaultKey(defaultKey))
	}

	reg, err := proxycrypto.NewKEKRegistry(regOpts...)
	if err != nil {
		_ = defaultKey.Close()
		return nil, fmt.Errorf("kek registry: %w", err)
	}

	vault, err := proxycrypto.NewVault(reg,
		proxycrypto.WithDefaultKeyConfig(proxycrypto.KeyConfig{
			Duration:    opts.DEKDuration,
			RenewBefore: opts.RenewBefore,
		}),
		proxycrypto.WithCacheSize(opts.CacheSize),
	)
	if err != nil {
		_ = reg.Close()
		return nil, fmt.Errorf("vault: %w", err)
	}

	return &Manager{
		defaultURI:  opts.DefaultURI,
		uriTemplate: opts.NamespaceURITemplate,
		nsURIs:      opts.NamespaceURIs,
		vault:       vault,
		reg:         reg,
		factory:     factory,
		keks:        map[string]proxycrypto.KEK{},
	}, nil
}

// Close releases KMS keepers / KEKs.
func (m *Manager) Close() error {
	m.mu.Lock()
	for id, k := range m.keks {
		_ = k.Close()
		delete(m.keks, id)
	}
	m.mu.Unlock()
	if m.reg != nil {
		return m.reg.Close()
	}
	return nil
}

// ResolveURI returns the KEK URI for a Temporal Namespace (short name or Cloud
// form name.account). Map overrides win; then URI template; then DefaultURI.
func (m *Manager) ResolveURI(namespace string) (string, error) {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return "", fmt.Errorf("namespace is required to resolve encryption URI")
	}
	short := shortName(namespace)
	if uri, ok := m.nsURIs[namespace]; ok && uri != "" {
		return uri, nil
	}
	if uri, ok := m.nsURIs[short]; ok && uri != "" {
		return uri, nil
	}
	if m.uriTemplate != "" {
		if !strings.Contains(m.uriTemplate, "%s") && !strings.Contains(m.uriTemplate, "%") {
			return "", fmt.Errorf("namespace URI template must include a %%s placeholder for the short name")
		}
		return fmt.Sprintf(m.uriTemplate, short), nil
	}
	if m.defaultURI != "" {
		return m.defaultURI, nil
	}
	return "", fmt.Errorf("no encryption URI for namespace %q", short)
}

// PayloadCodec returns a converter.PayloadCodec bound to ns for Seal on Encode
// and namespace-bound Open on Decode. Caller must only pass a namespace that
// auth already authorized (JWT bound to X-Namespace).
func (m *Manager) PayloadCodec(namespace string) converter.PayloadCodec {
	return &payloadCodec{m: m, namespace: strings.TrimSpace(namespace)}
}

type payloadCodec struct {
	m         *Manager
	namespace string
}

// Encode implements converter.PayloadCodec — mirrors temporal-proxy encryptPayloads.
func (c *payloadCodec) Encode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	ctx := context.Background()
	res := make([]*commonpb.Payload, len(payloads))
	for i, p := range payloads {
		data, err := p.Marshal()
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}
		msg, err := c.m.vault.Seal(ctx, c.namespace, data)
		if err != nil {
			return nil, fmt.Errorf("encrypt payload: %w", err)
		}
		res[i] = &commonpb.Payload{
			Metadata: map[string][]byte{
				metadataEncoding:        []byte(encryptionEncoding),
				metadataEncryptionKeyID: []byte(msg.KeyMaterial.KEKID),
				metadataEncryptionDEK:   []byte(msg.KeyMaterial.EncryptedDEK),
			},
			Data: msg.Ciphertext,
		}
	}
	return res, nil
}

// Decode implements converter.PayloadCodec — mirrors temporal-proxy decryptPayloads.
// Uses only the KEK for the authorized namespace (never opens wire-id alone).
func (c *payloadCodec) Decode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	ctx := context.Background()
	res := make([]*commonpb.Payload, len(payloads))
	for i, p := range payloads {
		if enc := string(p.GetMetadata()[metadataEncoding]); enc != encryptionEncoding {
			res[i] = p
			continue
		}
		msg := &proxycrypto.Message{
			Ciphertext: p.GetData(),
			KeyMaterial: &proxycrypto.DEKMaterial{
				KEKID:        string(p.GetMetadata()[metadataEncryptionKeyID]),
				EncryptedDEK: string(p.GetMetadata()[metadataEncryptionDEK]),
			},
		}
		pt, err := c.m.openForNamespace(ctx, c.namespace, msg)
		if err != nil {
			return nil, fmt.Errorf("decrypt payload: %w", err)
		}
		og := new(commonpb.Payload)
		if err := og.Unmarshal(pt); err != nil {
			return nil, fmt.Errorf("unmarshal payload: %w", err)
		}
		res[i] = og
	}
	return res, nil
}

// openForNamespace unwraps using the CMK for the authorized namespace only.
// Wire encryption-key-id must refer to that same key (URI or opened KEK ID).
func (m *Manager) openForNamespace(ctx context.Context, namespace string, msg *proxycrypto.Message) ([]byte, error) {
	if msg == nil || msg.KeyMaterial == nil {
		return nil, fmt.Errorf("missing key material")
	}
	uri, err := m.ResolveURI(namespace)
	if err != nil {
		return nil, err
	}
	kek, err := m.getKEK(ctx, uri)
	if err != nil {
		return nil, err
	}
	wireID := strings.TrimSpace(msg.KeyMaterial.KEKID)
	if !keyIDBoundToNamespace(wireID, uri, kek.ID()) {
		return nil, fmt.Errorf("payload encryption-key-id is not the authorized namespace key")
	}
	// Prefer full-registry Open when wire ID is already registered (same ID).
	if pt, err := m.vault.Open(ctx, msg); err == nil {
		return pt, nil
	}
	// Namespace-bound unwrap only: rewrite wire ID to the opened KEK's ID so
	// a one-shot vault keyed solely by that KEK can find it (alias vs ARN vs URI).
	bound := &proxycrypto.Message{
		Ciphertext: msg.Ciphertext,
		KeyMaterial: &proxycrypto.DEKMaterial{
			KEKID:        kek.ID(),
			EncryptedDEK: msg.KeyMaterial.EncryptedDEK,
		},
	}
	return openWithKEK(ctx, kek, bound)
}

func keyIDBoundToNamespace(wireID, resolvedURI, openedID string) bool {
	if wireID == "" {
		return false
	}
	if strings.EqualFold(wireID, resolvedURI) {
		return true
	}
	if strings.EqualFold(wireID, openedID) {
		return true
	}
	// testing:// vs base64key:// material forms used in wire / gocloud.
	if mt := normalizeTestingID(wireID); mt != "" {
		if mt == normalizeTestingID(resolvedURI) || mt == normalizeTestingID(openedID) {
			return true
		}
	}
	return false
}

func normalizeTestingID(id string) string {
	low := strings.ToLower(strings.TrimSpace(id))
	for _, p := range []string{"testing://", "base64key://"} {
		if strings.HasPrefix(low, p) {
			return strings.TrimPrefix(low, p)
		}
	}
	return ""
}

func openWithKEK(ctx context.Context, kek proxycrypto.KEK, msg *proxycrypto.Message) ([]byte, error) {
	// One-shot registry for this namespace's KEK only. Do not Close the KEK
	// (cached on Manager); GC drops vault/reg structs.
	reg, err := proxycrypto.NewKEKRegistry(proxycrypto.WithDefaultKey(kek))
	if err != nil {
		return nil, err
	}
	vault, err := proxycrypto.NewVault(reg,
		proxycrypto.WithCacheSize(32),
		proxycrypto.WithDefaultKeyConfig(proxycrypto.KeyConfig{
			Duration:    time.Hour,
			RenewBefore: 15 * time.Minute,
		}),
	)
	if err != nil {
		return nil, err
	}
	return vault.Open(ctx, msg)
}

func (m *Manager) getKEK(ctx context.Context, uri string) (proxycrypto.KEK, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.keks[uri]; ok {
		return k, nil
	}

	id := uri
	openURI := uri
	if strings.HasPrefix(strings.ToLower(uri), "base64key://") {
		material := uri[len("base64key://"):]
		openURI = "testing://" + material
	}

	k, err := m.factory.Create(ctx, openURI)
	if err != nil {
		kp, kErr := secrets.OpenKeeper(ctx, openURI)
		if kErr != nil {
			return nil, fmt.Errorf("open KEK %s: %w", redactURI(uri), err)
		}
		k = &keeperKEK{id: id, kp: kp}
	}
	if k.ID() != id {
		// Prefer stable wire form when registry stores URI-form IDs.
		if strings.EqualFold(k.ID(), openURI) || strings.HasPrefix(strings.ToLower(id), "awskms://") {
			k = &idOverrideKEK{inner: k, id: id}
		}
	}
	m.keks[uri] = k
	return k, nil
}

func shortName(ns string) string {
	if i := strings.IndexByte(ns, '.'); i > 0 {
		return ns[:i]
	}
	return ns
}

type keeperKEK struct {
	id string
	kp *secrets.Keeper
}

func (k *keeperKEK) ID() string { return k.id }

func (k *keeperKEK) Encrypt(ctx context.Context, _ string, dek []byte) ([]byte, error) {
	return k.kp.Encrypt(ctx, dek)
}

func (k *keeperKEK) Decrypt(ctx context.Context, dek []byte) ([]byte, error) {
	return k.kp.Decrypt(ctx, dek)
}

func (k *keeperKEK) Close() error { return k.kp.Close() }

type idOverrideKEK struct {
	inner proxycrypto.KEK
	id    string
}

func (k *idOverrideKEK) ID() string { return k.id }

func (k *idOverrideKEK) Encrypt(ctx context.Context, ns string, dek []byte) ([]byte, error) {
	return k.inner.Encrypt(ctx, ns, dek)
}

func (k *idOverrideKEK) Decrypt(ctx context.Context, dek []byte) ([]byte, error) {
	return k.inner.Decrypt(ctx, dek)
}

func (k *idOverrideKEK) Close() error { return k.inner.Close() }

func redactURI(uri string) string {
	low := strings.ToLower(uri)
	if strings.HasPrefix(low, "testing://") || strings.HasPrefix(low, "base64key://") {
		return "testing://<redacted>"
	}
	return uri
}

var _ converter.PayloadCodec = (*payloadCodec)(nil)
