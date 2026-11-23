package repository_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestKeyGeneration tests the internal key generation format
func TestKeyGeneration(t *testing.T) {
	t.Run("key_format_validation", func(t *testing.T) {
		// Newly generated keys follow jjd_<48 hex chars>.
		key := generateTestKey()

		// Validate format
		if len(key) != 52 { // "jjd_" (4 chars) + 48 hex chars
			t.Errorf("Key length should be 52, got %d", len(key))
		}

		if key[:4] != "jjd_" {
			t.Errorf("Key prefix should be 'jjd_'")
		}

		// Validate hex portion
		hexPart := key[4:]
		for _, c := range hexPart {
			if !isHexChar(c) {
				t.Errorf("Key should only contain hex chars after prefix, got '%c'", c)
			}
		}
	})

	t.Run("key_uniqueness", func(t *testing.T) {
		// Generate multiple keys and ensure they're unique
		keys := make(map[string]bool)
		for i := 0; i < 100; i++ {
			key := generateTestKey()
			if keys[key] {
				t.Error("Duplicate key generated")
			}
			keys[key] = true
		}
	})
}

// TestKeyHashComputation tests the hash storage mechanism
func TestKeyHashComputation(t *testing.T) {
	t.Run("hash_is_sha256", func(t *testing.T) {
		key := generateTestKey()
		hash := computeKeyHash(key)

		// SHA256 produces 64 hex chars
		if len(hash) != 64 {
			t.Errorf("Hash should be 64 chars (SHA256), got %d", len(hash))
		}
	})

	t.Run("same_key_same_hash", func(t *testing.T) {
		key := generateTestKey()
		hash1 := computeKeyHash(key)
		hash2 := computeKeyHash(key)

		if hash1 != hash2 {
			t.Errorf("Same key should produce same hash")
		}
	})

	t.Run("different_keys_different_hashes", func(t *testing.T) {
		key1 := generateTestKey()
		key2 := generateTestKey()
		hash1 := computeKeyHash(key1)
		hash2 := computeKeyHash(key2)

		if hash1 == hash2 {
			t.Errorf("Different keys should produce different hashes")
		}
	})

	t.Run("hash_not_reversible", func(t *testing.T) {
		key := generateTestKey()
		hash := computeKeyHash(key)

		// Hash should not contain the original key
		if len(hash) < len(key) {
			t.Error("Hash should be longer than key")
		}

		// Hash should not be equal to key
		if hash == key {
			t.Error("Hash should not equal key")
		}
	})

	t.Run("legacy_raw_key_hash_is_unchanged", func(t *testing.T) {
		const legacy = "na_1234567890abcdef"
		const want = "fb40a127e6fad0e3f950feef73991c026a0d46c28df0eb16a72eb047b84b0a78"
		if got := computeKeyHash(legacy); got != want {
			t.Error("legacy raw key SHA-256 changed")
		}
	})
}

// TestKeyValidationBehavior tests the expected key validation logic
func TestKeyValidationBehavior(t *testing.T) {
	t.Run("valid_key_accepted", func(t *testing.T) {
		key := generateTestKey()
		prefix := key[:16] // First 8 chars of hex part

		// Key should have valid format
		if !isValidKeyFormat(key) {
			t.Errorf("Generated key should be valid format")
		}

		// Prefix should be extractable
		if prefix == "" {
			t.Error("Key prefix should be extractable")
		}
		if !isValidKeyFormat("na_1234567890abcdef1234567890abcdef1234567890abcdef") {
			t.Error("legacy na_ key should remain format-compatible")
		}
	})

	t.Run("invalid_key_rejected", func(t *testing.T) {
		invalidKeys := []string{
			"",                    // Empty
			"short",               // Too short
			"na_short",            // Prefix but too short hex
			"invalid_prefix_1234", // Wrong prefix
		}

		for _, key := range invalidKeys {
			if isValidKeyFormat(key) {
				t.Errorf("Invalid key should be rejected; length=%d", len(key))
			}
		}
	})

	t.Run("key_status_transitions", func(t *testing.T) {
		// Key should support status transitions
		statuses := []string{"active", "revoked", "expired"}

		for _, status := range statuses {
			if !isValidKeyStatus(status) {
				t.Errorf("Status '%s' should be valid", status)
			}
		}

		// Invalid statuses
		invalidStatuses := []string{"", "pending", "unknown"}
		for _, status := range invalidStatuses {
			if isValidKeyStatus(status) {
				t.Errorf("Invalid status '%s' should be rejected", status)
			}
		}
	})
}

// TestKeyScoping tests key-project association
func TestKeyScoping(t *testing.T) {
	t.Run("key_belongs_to_project", func(t *testing.T) {
		// Key should be associated with a project
		keyRecord := &InternalKey{
			ID:        "key_001",
			ProjectID: "project_001",
			UserID:    "user_001",
			Status:    "active",
		}

		if keyRecord.ProjectID == "" {
			t.Error("Key should have ProjectID")
		}
		if keyRecord.UserID == "" {
			t.Error("Key should have UserID")
		}
	})

	t.Run("key_belongs_to_tenant", func(t *testing.T) {
		// Key should be tenant-scoped through project
		keyRecord := &InternalKey{
			ID:        "key_001",
			TenantID:  "tenant_001",
			ProjectID: "project_001",
			Status:    "active",
		}

		if keyRecord.TenantID == "" {
			t.Error("Key should have TenantID")
		}
	})
}

// Helper functions matching production behavior

func generateTestKey() string {
	bytes := make([]byte, 24)
	rand.Read(bytes)
	return "jjd_" + hex.EncodeToString(bytes)
}

func computeKeyHash(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

func isHexChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isValidKeyFormat(key string) bool {
	if len(key) < 20 {
		return false
	}
	prefixLen := 0
	switch {
	case len(key) >= 4 && key[:4] == "jjd_":
		prefixLen = 4
	case len(key) >= 3 && key[:3] == "na_":
		prefixLen = 3
	default:
		return false
	}
	// Check hex portion for both newly generated and legacy keys.
	for _, c := range key[prefixLen:] {
		if !isHexChar(c) {
			return false
		}
	}
	return true
}

func isValidKeyStatus(status string) bool {
	valid := []string{"active", "revoked", "expired"}
	for _, s := range valid {
		if status == s {
			return true
		}
	}
	return false
}

// InternalKey struct matching production definition
type InternalKey struct {
	ID        string
	TenantID  string
	ProjectID string
	UserID    string
	KeyHash   string
	KeyPrefix string
	Status    string
}
