package secrets

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestRawEvidenceRoundTripAndBinding(t *testing.T) {
	for _, mode := range []string{"", CipherSM4GCM} {
		t.Setenv(providerSecretEnv, "unit-test-provider-secret-0123456789")
		t.Setenv(CipherEnv, mode)
		aad := []byte("tenant-a\x00req-1\x00input\x000")
		enc, err := EncryptRawEvidence([]byte("身份证 110101199003071234"), aad)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(enc, "enc:v3:") || strings.Contains(enc, "1101") {
			t.Fatalf("bad ciphertext %q", enc)
		}
		plain, err := DecryptRawEvidence(enc, aad)
		if err != nil || string(plain) != "身份证 110101199003071234" {
			t.Fatalf("round trip: %q %v", plain, err)
		}
		if _, err := DecryptRawEvidence(enc, []byte("tenant-b\x00req-1\x00input\x000")); err == nil {
			t.Fatal("AAD binding not enforced")
		}
		if _, err := DecryptProviderSecret(strings.Replace(enc, "enc:v3:", "enc:v1:", 1)); err == nil {
			t.Fatal("domain separation: provider API must not open raw evidence")
		}
	}
	t.Setenv(CipherEnv, "")
	// AAD 绑定用户与会话：改挂到别的用户/会话解不开。
	aad := RawEvidenceAAD("t", "r", "u1", "s1", "input", 0, "masked")
	enc, err := EncryptRawEvidence([]byte("原文"), aad)
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range [][]byte{
		RawEvidenceAAD("t", "r", "u2", "s1", "input", 0, "masked"),
		RawEvidenceAAD("t", "r", "", "s1", "input", 0, "masked"),
		RawEvidenceAAD("t", "r", "u1", "s2", "input", 0, "masked"),
	} {
		if _, err := DecryptRawEvidence(enc, other); err == nil {
			t.Fatalf("AAD must bind user and session: %q", other)
		}
	}
	if plain, err := DecryptRawEvidence(enc, aad); err != nil || string(plain) != "原文" {
		t.Fatalf("round trip with user/session AAD: %q %v", plain, err)
	}
	if _, err := EncryptRawEvidence(nil, []byte("a")); err == nil {
		t.Fatal("empty plaintext accepted")
	}
	t.Setenv(providerSecretEnv, "")
	t.Setenv(masterSecretEnv, "")
	if _, err := EncryptRawEvidence([]byte("x"), []byte("a")); err == nil {
		t.Fatal("missing key must fail closed")
	}
}

// 去重摘要是带密钥的 HMAC：不等于无盐 SHA-256，换密钥/换租户结果不同，没有密钥报错。
func TestRawEvidenceContentMAC(t *testing.T) {
	for _, mode := range []string{"", CipherSM4GCM} {
		t.Setenv(providerSecretEnv, "unit-test-provider-secret-0123456789")
		t.Setenv(CipherEnv, mode)
		plain := []byte("身份证 110101199003071234")
		a, err := RawEvidenceContentMAC("tenant-a", plain)
		if err != nil || len(a) != 32 {
			t.Fatalf("mac: %x %v", a, err)
		}
		again, _ := RawEvidenceContentMAC("tenant-a", plain)
		if string(a) != string(again) {
			t.Fatal("mac must be deterministic for dedup")
		}
		bare := sha256.Sum256(plain)
		if string(a) == string(bare[:]) {
			t.Fatal("mac must not be a bare sha256")
		}
		if b, _ := RawEvidenceContentMAC("tenant-b", plain); string(a) == string(b) {
			t.Fatal("mac must be tenant separated")
		}
		t.Setenv(providerSecretEnv, "another-provider-secret-0123456789xx")
		if mode == "" {
			if c, _ := RawEvidenceContentMAC("tenant-a", plain); string(a) == string(c) {
				t.Fatal("mac must depend on the data key")
			}
		}
	}
	t.Setenv(CipherEnv, "")
	t.Setenv(providerSecretEnv, "")
	t.Setenv(masterSecretEnv, "")
	if _, err := RawEvidenceContentMAC("t", []byte("x")); err == nil {
		t.Fatal("missing key must fail closed")
	}
}
