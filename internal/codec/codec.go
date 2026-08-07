package codec

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"gocloud.dev/secrets"
	_ "gocloud.dev/secrets/awskms"
	_ "gocloud.dev/secrets/localsecrets"

	proxycrypto "github.com/temporalio/temporal-proxy/pkg/crypto"

	"github.com/bitovi/temporal-codec/internal/shared"
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
	dekDuration time.Duration
	renewBefore time.Duration
	cacheSize   int

	vault   *proxycrypto.Vault
	reg     *proxycrypto.KEKRegistry
	factory *proxycrypto.KeyFactory

	mu       sync.Mutex
	keks     map[string]proxycrypto.KEK    // cache by resolved URI
	nsVaults map[string]*proxycrypto.Vault // per-namespace vault; reuses DEK LRU
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

	// Sort namespace keys for deterministic registry wiring (first alphabetically
	// becomes the default when no explicit DefaultURI is provided).
	nsKeys := make([]string, 0, len(opts.NamespaceURIs))
	for ns := range opts.NamespaceURIs {
		nsKeys = append(nsKeys, ns)
	}
	sort.Strings(nsKeys)

	for _, ns := range nsKeys {
		uri := opts.NamespaceURIs[ns]
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
			if short := shared.ShortName(ns); short != ns {
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
		dekDuration: opts.DEKDuration,
		renewBefore: opts.RenewBefore,
		cacheSize:   opts.CacheSize,
		vault:       vault,
		reg:         reg,
		factory:     factory,
		keks:        map[string]proxycrypto.KEK{},
		nsVaults:    map[string]*proxycrypto.Vault{},
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
	short := shared.ShortName(namespace)
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
// and namespace-bound Open on Decode. The supplied context propagates to KMS
// calls (deadline, cancellation) — pass r.Context() from the HTTP handler.
// Caller must only pass a namespace that auth already authorized (JWT bound to
// X-Namespace).
func (m *Manager) PayloadCodec(ctx context.Context, namespace string) converter.PayloadCodec {
	return &payloadCodec{m: m, namespace: strings.TrimSpace(namespace), ctx: ctx}
}

type payloadCodec struct {
	m         *Manager
	namespace string
	ctx       context.Context
}

// Encode implements converter.PayloadCodec — mirrors temporal-proxy encryptPayloads.
func (c *payloadCodec) Encode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	ctx := c.ctx
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
	ctx := c.ctx
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
	// the per-namespace vault (keyed solely by that KEK) can find it
	// (alias vs ARN vs URI form differences).
	bound := &proxycrypto.Message{
		Ciphertext: msg.Ciphertext,
		KeyMaterial: &proxycrypto.DEKMaterial{
			KEKID:        kek.ID(),
			EncryptedDEK: msg.KeyMaterial.EncryptedDEK,
		},
	}
	nsVault, err := m.nsVaultFor(uri, kek)
	if err != nil {
		return nil, err
	}
	return nsVault.Open(ctx, bound)
}

// nsVaultFor returns a cached per-namespace vault for the given URI and KEK.
// Each namespace gets its own vault with a DEK LRU, so repeated decrypts of
// the same DEK hit the cache instead of calling KMS on every payload.
// The vault does not own the KEK lifecycle (owned by m.keks); GC is safe.
func (m *Manager) nsVaultFor(uri string, kek proxycrypto.KEK) (*proxycrypto.Vault, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.nsVaults[uri]; ok {
		return v, nil
	}
	reg, err := proxycrypto.NewKEKRegistry(proxycrypto.WithDefaultKey(kek))
	if err != nil {
		return nil, err
	}
	vault, err := proxycrypto.NewVault(reg,
		proxycrypto.WithCacheSize(m.cacheSize),
		proxycrypto.WithDefaultKeyConfig(proxycrypto.KeyConfig{
			Duration:    m.dekDuration,
			RenewBefore: m.renewBefore,
		}),
	)
	if err != nil {
		return nil, err
	}
	m.nsVaults[uri] = vault
	return vault, nil
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

func (m *Manager) getKEK(ctx context.Context, uri string) (proxycrypto.KEK, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.keks[uri]; ok {
		return k, nil
	}

	k, err := m.factory.Create(ctx, uri)
	if err != nil {
		kp, kErr := secrets.OpenKeeper(ctx, uri)
		if kErr != nil {
			return nil, fmt.Errorf("open KEK %s: %w", redactURI(uri), err)
		}
		k = &keeperKEK{id: uri, kp: kp}
	}
	if k.ID() != uri {
		// Prefer stable wire form when the opened KEK's ID differs from the URI
		// (e.g. alias → resolved ARN for awskms://).
		if strings.EqualFold(k.ID(), uri) || strings.HasPrefix(strings.ToLower(uri), "awskms://") {
			k = &idOverrideKEK{inner: k, id: uri}
		}
	}
	m.keks[uri] = k
	return k, nil
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
