package secrets

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncryptDecryptProviderSecret(t *testing.T) {
	t.Setenv(providerSecretEnv, "unit-test-secret-key")

	ciphertext, keyRef, err := EncryptProviderSecret("sk-test-123")
	if err != nil {
		t.Fatalf("EncryptProviderSecret returned error: %v", err)
	}
	if !strings.HasPrefix(ciphertext, providerSecretPrefix) {
		t.Fatalf("expected encrypted prefix, got %q", ciphertext)
	}
	if keyRef != "env:"+providerSecretEnv {
		t.Fatalf("expected key ref for provider secret env, got %q", keyRef)
	}

	plaintext, err := DecryptProviderSecret(ciphertext)
	if err != nil {
		t.Fatalf("DecryptProviderSecret returned error: %v", err)
	}
	if plaintext != "sk-test-123" {
		t.Fatalf("expected decrypted plaintext to match original, got %q", plaintext)
	}
}

func TestDecryptProviderSecretLegacyPlaintext(t *testing.T) {
	plaintext, err := DecryptProviderSecret("legacy-plain-text-secret")
	if err != nil {
		t.Fatalf("DecryptProviderSecret returned error for legacy plaintext: %v", err)
	}
	if plaintext != "legacy-plain-text-secret" {
		t.Fatalf("expected legacy plaintext to pass through, got %q", plaintext)
	}
}

func TestEncryptDecryptCAPrivateKey(t *testing.T) {
	t.Setenv(internalAPISecretEnv, "ca-unit-test-internal-secret")
	ciphertext, err := EncryptCAPrivateKey("-----BEGIN RSA PRIVATE KEY-----")
	if err != nil {
		t.Fatalf("EncryptCAPrivateKey returned error: %v", err)
	}
	if !strings.HasPrefix(ciphertext, caPrivateKeyPrefix) {
		t.Fatalf("expected CA ciphertext prefix, got %q", ciphertext)
	}
	plaintext, err := DecryptCAPrivateKey(ciphertext)
	if err != nil {
		t.Fatalf("DecryptCAPrivateKey returned error: %v", err)
	}
	if plaintext != "-----BEGIN RSA PRIVATE KEY-----" {
		t.Fatalf("unexpected decrypted CA private key %q", plaintext)
	}
}

func TestDecryptCAPrivateKeyLegacyPlaintext(t *testing.T) {
	plaintext, err := DecryptCAPrivateKey("legacy-ca-private-key")
	if err != nil || plaintext != "legacy-ca-private-key" {
		t.Fatalf("legacy CA private key compatibility failed: plaintext=%q err=%v", plaintext, err)
	}
}

func TestMCPResultEncryptionRequiresExactAAD(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "mcp-result-key")
	ciphertext, err := EncryptMCPResult([]byte(`{"jsonrpc":"2.0","id":9,"result":{}}`), []byte("aad-a"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ciphertext, "enc:v2:") {
		t.Fatalf("ciphertext=%q", ciphertext)
	}
	plaintext, err := DecryptMCPResult(ciphertext, []byte("aad-a"))
	if err != nil || !bytes.Contains(plaintext, []byte(`"result"`)) {
		t.Fatalf("decrypt=(%q,%v)", plaintext, err)
	}
	if _, err := DecryptMCPResult(ciphertext, []byte("aad-b")); err == nil {
		t.Fatal("different AAD decrypted MCP result")
	}
}
