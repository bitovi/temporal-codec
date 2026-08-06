package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the process configuration for temporal-codec.
type Config struct {
	Port              int
	LogLevel          string
	JWKSURL           string
	JWTAudience       string
	JWTIssuer         string
	CORSOrigins       []string
	EncryptionURI     string
	// NamespaceURITemplate sprintf's Cloud short name into a platform KMS
	// alias (ADR 0008): awskms://alias/platform-managed/%s-codec.
	// Decode never uses a foreign key; only the template/map URI for the
	// JWT-authorized namespace.
	NamespaceURITemplate string
	NamespaceURIs        map[string]string
	PermissionClaim      string
	AuthDisabled         bool
	EnableEncode         bool
	JWKSRefresh          time.Duration
	ReadHeaderTimeout    time.Duration
}

// Load reads configuration from the environment.
func Load() (Config, error) {
	cfg := Config{
		Port:                 envInt("PORT", 8080),
		LogLevel:             envOr("LOG_LEVEL", "info"),
		JWKSURL:              envOr("TEMPORAL_CLOUD_JWKS_URL", "https://login.tmprl.cloud/.well-known/jwks.json"),
		JWTAudience:          envOr("TEMPORAL_CLOUD_JWT_AUDIENCE", "https://saas-api.tmprl.cloud"),
		JWTIssuer:            envOr("TEMPORAL_CLOUD_JWT_ISSUER", ""),
		CORSOrigins:          splitCSV(envOr("CORS_ALLOWED_ORIGINS", "https://cloud.temporal.io")),
		EncryptionURI:        envOr("ENCRYPTION_URI", ""),
		NamespaceURITemplate: envOr("ENCRYPTION_URI_TEMPLATE", ""),
		NamespaceURIs:        parseNamespaceURIs(envOr("ENCRYPTION_URI_OVERRIDES", "")),
		PermissionClaim:      envOr("TEMPORAL_NAMESPACE_PERMISSION_CLAIM", "permissions"),
		AuthDisabled:         envBool("AUTH_DISABLED", false),
		// Temporal Cloud UI only needs /decode; encode stays off unless local debug.
		EnableEncode:      envBool("ENABLE_ENCODE", false),
		JWKSRefresh:       envDuration("JWKS_REFRESH_INTERVAL", time.Hour),
		ReadHeaderTimeout: envDuration("READ_HEADER_TIMEOUT", 10*time.Second),
	}

	if cfg.Port <= 0 || cfg.Port > 65535 {
		return Config{}, fmt.Errorf("PORT must be between 1 and 65535")
	}
	if cfg.EncryptionURI == "" && cfg.NamespaceURITemplate == "" && len(cfg.NamespaceURIs) == 0 {
		return Config{}, fmt.Errorf("ENCRYPTION_URI, ENCRYPTION_URI_TEMPLATE, or ENCRYPTION_URI_OVERRIDES is required")
	}
	// Fleet production default when only template is needed: leave EncryptionURI empty.
	if cfg.EncryptionURI == "" && cfg.NamespaceURITemplate == "" {
		for _, uri := range cfg.NamespaceURIs {
			cfg.EncryptionURI = uri
			break
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

func envInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envDuration(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
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
