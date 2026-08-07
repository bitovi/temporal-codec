package config

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Config is the process configuration for temporal-codec.
type Config struct {
	Port          int
	LogLevel      string
	JWKSURL       string
	JWTAudience   string
	JWTIssuer     string
	CORSOrigins   []string
	EncryptionURI string
	// NamespaceURITemplate sprintf's Cloud short name into a platform KMS
	// alias (ADR 0008): awskms://alias/platform-managed/%s-codec.
	// Decode never uses a foreign key; only the template/map URI for the
	// JWT-authorized namespace.
	NamespaceURITemplate string
	NamespaceURIs        map[string]string
	PermissionClaim      string
	// NamespaceACL maps email addresses (lowercase) to allowed namespaces.
	// Format: EMAIL1=ns1,ns2;EMAIL2=ns3. Used by EmailAuthorizer.
	NamespaceACL         map[string][]string
	AuthDisabled         bool
	EnableEncode         bool
	JWKSRefresh          time.Duration
	ReadHeaderTimeout    time.Duration
	WriteTimeout         time.Duration
	IdleTimeout          time.Duration
	MaxBodyBytes         int64
}

// Load reads configuration from the environment.
func Load() (Config, error) {
	port, err := envInt("PORT", 8080)
	if err != nil {
		return Config{}, err
	}
	authDisabled, err := envBool("AUTH_DISABLED", false)
	if err != nil {
		return Config{}, err
	}
	enableEncode, err := envBool("ENABLE_ENCODE", false)
	if err != nil {
		return Config{}, err
	}
	jwksRefresh, err := envDuration("JWKS_REFRESH_INTERVAL", time.Hour)
	if err != nil {
		return Config{}, err
	}
	readHeaderTimeout, err := envDuration("READ_HEADER_TIMEOUT", 10*time.Second)
	if err != nil {
		return Config{}, err
	}
	writeTimeout, err := envDuration("WRITE_TIMEOUT", 30*time.Second)
	if err != nil {
		return Config{}, err
	}
	idleTimeout, err := envDuration("IDLE_TIMEOUT", 120*time.Second)
	if err != nil {
		return Config{}, err
	}
	maxBodyBytes, err := envInt64("MAX_BODY_BYTES", 10<<20) // 10 MiB
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		Port:                 port,
		LogLevel:             envOr("LOG_LEVEL", "info"),
		JWKSURL:              envOr("TEMPORAL_CLOUD_JWKS_URL", "https://login.tmprl.cloud/.well-known/jwks.json"),
		JWTAudience:          envOr("TEMPORAL_CLOUD_JWT_AUDIENCE", "https://saas-api.tmprl.cloud"),
		JWTIssuer:            envOr("TEMPORAL_CLOUD_JWT_ISSUER", ""),
		CORSOrigins:          splitCSV(envOr("CORS_ALLOWED_ORIGINS", "https://cloud.temporal.io")),
		EncryptionURI:        envOr("ENCRYPTION_URI", ""),
		NamespaceURITemplate: envOr("ENCRYPTION_URI_TEMPLATE", ""),
		NamespaceURIs:        parseNamespaceURIs(envOr("ENCRYPTION_URI_OVERRIDES", "")),
		PermissionClaim:      envOr("TEMPORAL_NAMESPACE_PERMISSION_CLAIM", "permissions"),
		NamespaceACL:         parseNamespaceACL(envOr("NAMESPACE_ACL", "")),
		AuthDisabled:         authDisabled,
		// Temporal Cloud UI only needs /decode; encode stays off unless local debug.
		EnableEncode:      enableEncode,
		JWKSRefresh:       jwksRefresh,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxBodyBytes:      maxBodyBytes,
	}

	if cfg.Port <= 0 || cfg.Port > 65535 {
		return Config{}, fmt.Errorf("PORT must be between 1 and 65535")
	}
	if cfg.EncryptionURI == "" && cfg.NamespaceURITemplate == "" && len(cfg.NamespaceURIs) == 0 {
		return Config{}, fmt.Errorf("ENCRYPTION_URI, ENCRYPTION_URI_TEMPLATE, or ENCRYPTION_URI_OVERRIDES is required")
	}
	// Fleet production default when only template is needed: leave EncryptionURI empty.
	// Sort keys for deterministic selection.
	if cfg.EncryptionURI == "" && cfg.NamespaceURITemplate == "" {
		keys := make([]string, 0, len(cfg.NamespaceURIs))
		for k := range cfg.NamespaceURIs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > 0 {
			cfg.EncryptionURI = cfg.NamespaceURIs[keys[0]]
		}
	}
	if !cfg.AuthDisabled {
		if cfg.JWKSURL == "" {
			return Config{}, fmt.Errorf("TEMPORAL_CLOUD_JWKS_URL is required when AUTH_DISABLED is false")
		}
		if cfg.JWTAudience == "" {
			return Config{}, fmt.Errorf("TEMPORAL_CLOUD_JWT_AUDIENCE is required when AUTH_DISABLED is false")
		}
	}
	return cfg, nil
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def, fmt.Errorf("%s=%q: %w", key, v, err)
	}
	return n, nil
}

func envInt64(key string, def int64) (int64, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def, fmt.Errorf("%s=%q: %w", key, v, err)
	}
	return n, nil
}

func envBool(key string, def bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def, fmt.Errorf("%s=%q: expected true/false/1/0, %w", key, v, err)
	}
	return b, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def, fmt.Errorf("%s=%q: %w", key, v, err)
	}
	return d, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseNamespaceURIs parses "ns1=uri1,ns2=uri2".
func parseNamespaceURIs(s string) map[string]string {
	if s == "" {
		return map[string]string{}
	}
	out := make(map[string]string)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ns, uri, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		ns = strings.TrimSpace(ns)
		uri = strings.TrimSpace(uri)
		if ns != "" && uri != "" {
			out[ns] = uri
		}
	}
	return out
}

// parseNamespaceACL parses "email1=ns1,ns2;email2=ns3".
// Returns a map of lowercase email -> namespaces.
func parseNamespaceACL(s string) map[string][]string {
	if s == "" {
		return map[string][]string{}
	}
	out := make(map[string][]string)
	for _, pair := range strings.Split(s, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		email, nsList, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		email = strings.ToLower(strings.TrimSpace(email))
		if email == "" {
			continue
		}
		var namespaces []string
		for _, ns := range strings.Split(nsList, ",") {
			ns = strings.TrimSpace(ns)
			if ns != "" {
				namespaces = append(namespaces, ns)
			}
		}
		if len(namespaces) > 0 {
			out[email] = namespaces
		}
	}
	return out
}
