package authhelpers

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestGenerateKeyUsesJJDGuardPrefixWithoutEntropyRegression(t *testing.T) {
	seen := make(map[string]struct{}, 256)
	for i := 0; i < 256; i++ {
		key := GenerateKey()
		if !strings.HasPrefix(key, "jjd_") {
			t.Fatalf("generated key prefix is not jjd_; length=%d", len(key))
		}
		body := strings.TrimPrefix(key, "jjd_")
		if len(body) != 36 {
			t.Fatalf("generated UUID body length=%d, want 36", len(body))
		}
		parsed, err := uuid.Parse(body)
		if err != nil {
			t.Fatalf("generated UUID body is invalid")
		}
		if parsed.Version() != 4 {
			t.Fatalf("generated UUID version=%d, want 4", parsed.Version())
		}
		if _, exists := seen[key]; exists {
			t.Fatal("duplicate generated key")
		}
		seen[key] = struct{}{}
	}
}

func TestHashKeyKeepsLegacyRawKeyCompatibility(t *testing.T) {
	const (
		legacy = "na_1234567890abcdef"
		want   = "fb40a127e6fad0e3f950feef73991c026a0d46c28df0eb16a72eb047b84b0a78"
	)
	if got := HashKey(legacy); got != want {
		t.Fatalf("legacy key SHA-256 changed")
	}
	if got := GetKeyPrefix(legacy); got != "na_12345..." {
		t.Fatalf("legacy display prefix changed: %q", got)
	}
}
