package config_test

import (
	"os"
	"testing"

	"github.com/bitovi/temporal-codec/internal/config"
)

func TestLoadNamespaceACL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string][]string
	}{
		{
			name:  "empty",
			input: "",
			want:  map[string][]string{},
		},
		{
			name:  "single email single namespace",
			input: "alice@example.com=payments",
			want: map[string][]string{
				"alice@example.com": {"payments"},
			},
		},
		{
			name:  "single email multiple namespaces",
			input: "alice@example.com=payments,orders",
			want: map[string][]string{
				"alice@example.com": {"payments", "orders"},
			},
		},
		{
			name:  "multiple emails",
			input: "alice@example.com=payments;bob@example.com=orders,inventory",
			want: map[string][]string{
				"alice@example.com": {"payments"},
				"bob@example.com":   {"orders", "inventory"},
			},
		},
		{
			name:  "case normalization",
			input: "ALICE@EXAMPLE.COM=payments",
			want: map[string][]string{
				"alice@example.com": {"payments"},
			},
		},
		{
			name:  "whitespace trimming",
			input: "  alice@example.com  =  payments , orders  ;  bob@example.com = inventory ",
			want: map[string][]string{
				"alice@example.com": {"payments", "orders"},
				"bob@example.com":   {"inventory"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set env var and load config
			os.Setenv("NAMESPACE_ACL", tt.input)
			os.Setenv("PORT", "8080")
			os.Setenv("ENCRYPTION_URI", "awskms://alias/test")
			os.Setenv("AUTH_DISABLED", "true")
			defer func() {
				os.Unsetenv("NAMESPACE_ACL")
				os.Unsetenv("PORT")
				os.Unsetenv("ENCRYPTION_URI")
				os.Unsetenv("AUTH_DISABLED")
			}()

			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}

			if !mapsEqual(cfg.NamespaceACL, tt.want) {
				t.Errorf("Load NAMESPACE_ACL(%q)\ngot: %v\nwant: %v", tt.input, cfg.NamespaceACL, tt.want)
			}
		})
	}
}

func TestLoadNamespaceACLFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/namespace_acl"
	content := "alice@example.com=payments,orders;bob@example.com=inventory\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got := config.LoadNamespaceACLFile(path)
	want := map[string][]string{
		"alice@example.com": {"payments", "orders"},
		"bob@example.com":   {"inventory"},
	}
	if !mapsEqual(got, want) {
		t.Errorf("LoadNamespaceACLFile\ngot: %v\nwant: %v", got, want)
	}

	missing := config.LoadNamespaceACLFile(dir + "/missing")
	if len(missing) != 0 {
		t.Errorf("missing file should return empty map, got %v", missing)
	}
}

func mapsEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		bv, ok := b[k]
		if !ok {
			return false
		}
		if !slicesEqual(v, bv) {
			return false
		}
	}
	return true
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
