package secrets

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
)

// Clears every variable the package reads so cases do not leak into each other.
func resetSecretEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{providerSecretEnv, masterSecretEnv, internalAPISecretEnv, CipherEnv, SM4KeyringEnv, SM4ActiveKeyEnv} {
		t.Setenv(k, "")
	}
	t.Setenv(providerSecretEnv, "ws10-provider-root-secret")
	t.Setenv(internalAPISecretEnv, "ws10-internal-api-secret")
}

// Known-answer tests pin the primitives: GB/T 32907-2016 appendix A.1 and
// GB/T 32905-2016 appendix A.1 ("abc").
func TestSM4AndSM3KnownAnswers(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	want, _ := hex.DecodeString("681edf34d206965e86b3e94f536e4246")
	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 16)
	block.Encrypt(got, key)
	if !bytes.Equal(got, want) {
		t.Fatalf("SM4 KAT got %x want %x", got, want)
	}
	sum := sm3.Sum([]byte("abc"))
	if hex.EncodeToString(sum[:]) != "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" {
		t.Fatalf("SM3 KAT got %x", sum)
	}
	// RFC 8998 A.1 SM4-GCM through the same constructor the envelope uses.
	aead, err := newSM4GCM(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := hex.DecodeString("00001234567800000000abcd")
	pt, _ := hex.DecodeString("aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa")
	aad, _ := hex.DecodeString("feedfacedeadbeeffeedfacedeadbeefabaddad2")
	if got := hex.EncodeToString(aead.Seal(nil, nonce, pt, aad)); got != "17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d83de3541e4c2b58177e065a9bf7b62ec" {
		t.Fatalf("SM4-GCM RFC 8998 KAT got %s", got)
	}
}

func TestDefaultCipherStaysAESGCM(t *testing.T) {
	resetSecretEnv(t)
	ct, _, err := EncryptProviderSecret("sk-default")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ct, providerSecretPrefix) || strings.Contains(ct, sm4Marker) {
		t.Fatalf("default must be legacy AES-GCM format, got %q", ct)
	}
	if DescribeCiphertext(ct) != CipherAESGCM {
		t.Fatalf("describe=%q", DescribeCiphertext(ct))
	}
	ca, err := EncryptCAPrivateKey("pem")
	if err != nil || strings.Contains(ca, sm4Marker) {
		t.Fatalf("CA default must be AES: %q %v", ca, err)
	}
}

func TestSM4EnabledReadsOldAndWritesSM4(t *testing.T) {
	resetSecretEnv(t)
	legacy, _, err := EncryptProviderSecret("sk-legacy-aes")
	if err != nil {
		t.Fatal(err)
	}
	legacyCA, err := EncryptCAPrivateKey("-----BEGIN PRIVATE KEY-----")
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv(CipherEnv, "SM4-GCM") // case-insensitive
	for name, pair := range map[string][2]string{"provider": {legacy, "sk-legacy-aes"}} {
		got, err := DecryptProviderSecret(pair[0])
		if err != nil || got != pair[1] {
			t.Fatalf("%s: old AES value unreadable after enabling SM4: %q %v", name, got, err)
		}
	}
	if got, err := DecryptCAPrivateKey(legacyCA); err != nil || got != "-----BEGIN PRIVATE KEY-----" {
		t.Fatalf("old AES CA key unreadable after enabling SM4: %q %v", got, err)
	}

	ct, ref, err := EncryptProviderSecret("sk-new-sm4")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ct, providerSecretPrefix+sm4Marker+sm4RootKeyID+":") {
		t.Fatalf("new value must be SM4 under the enc:v1: family, got %q", ct)
	}
	if ref != "env:"+providerSecretEnv {
		t.Fatalf("key ref changed: %q", ref)
	}
	if got, err := DecryptProviderSecret(ct); err != nil || got != "sk-new-sm4" {
		t.Fatalf("SM4 round trip: %q %v", got, err)
	}
	if DescribeCiphertext(ct) != "sm4-gcm:root" {
		t.Fatalf("describe=%q", DescribeCiphertext(ct))
	}

	caCT, err := EncryptCAPrivateKey("ca-pem")
	if err != nil || !strings.HasPrefix(caCT, caPrivateKeyPrefix+sm4Marker) {
		t.Fatalf("CA SM4 write: %q %v", caCT, err)
	}
	if got, err := DecryptCAPrivateKey(caCT); err != nil || got != "ca-pem" {
		t.Fatalf("CA SM4 round trip: %q %v", got, err)
	}
}

// With SM4 turned off again, existing SM4 values must stay readable and
// new values go back to AES; Rewrap converts SM4 values back to AES.
func TestRollbackToAESKeepsSM4Readable(t *testing.T) {
	resetSecretEnv(t)
	t.Setenv(CipherEnv, CipherSM4GCM)
	sm4CT, _, err := EncryptProviderSecret("sk-written-under-sm4")
	if err != nil {
		t.Fatal(err)
	}
	sm4CA, err := EncryptCAPrivateKey("ca-under-sm4")
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv(CipherEnv, "") // rollback to default
	if got, err := DecryptProviderSecret(sm4CT); err != nil || got != "sk-written-under-sm4" {
		t.Fatalf("SM4 value unreadable after rollback: %q %v", got, err)
	}
	fresh, _, _ := EncryptProviderSecret("sk-after-rollback")
	if DescribeCiphertext(fresh) != CipherAESGCM {
		t.Fatalf("writes after rollback must be AES, got %q", fresh)
	}

	back, changed, err := RewrapProviderSecret(sm4CT)
	if err != nil || !changed || DescribeCiphertext(back) != CipherAESGCM {
		t.Fatalf("rewrap to AES: %q changed=%v err=%v", back, changed, err)
	}
	if got, _ := DecryptProviderSecret(back); got != "sk-written-under-sm4" {
		t.Fatalf("rewrapped value lost plaintext: %q", got)
	}
	backCA, changed, err := RewrapCAPrivateKey(sm4CA)
	if err != nil || !changed || DescribeCiphertext(backCA) != CipherAESGCM {
		t.Fatalf("CA rewrap to AES: %q %v %v", backCA, changed, err)
	}
	// Idempotent: already in target format.
	if again, changed, err := RewrapProviderSecret(back); err != nil || changed || again != back {
		t.Fatalf("rewrap must be a no-op on target format: changed=%v err=%v", changed, err)
	}
}

func TestSM4KeyRotation(t *testing.T) {
	resetSecretEnv(t)
	t.Setenv(CipherEnv, CipherSM4GCM)
	t.Setenv(SM4KeyringEnv, "k2025=first-rotation-secret-0001")
	oldCT, _, err := EncryptProviderSecret("sk-rotate")
	if err != nil || DescribeCiphertext(oldCT) != "sm4-gcm:k2025" {
		t.Fatalf("write under k2025: %q %v", oldCT, err)
	}

	// Rotate: new key first (active by default), old key kept for reading.
	t.Setenv(SM4KeyringEnv, "k2026=second-rotation-secret-002,k2025=first-rotation-secret-0001")
	if got, err := DecryptProviderSecret(oldCT); err != nil || got != "sk-rotate" {
		t.Fatalf("old key unreadable during rotation: %q %v", got, err)
	}
	newCT, changed, err := RewrapProviderSecret(oldCT)
	if err != nil || !changed || DescribeCiphertext(newCT) != "sm4-gcm:k2026" {
		t.Fatalf("rewrap to k2026: %q %v %v", newCT, changed, err)
	}

	// Explicit active key overrides keyring order.
	t.Setenv(SM4ActiveKeyEnv, "k2025")
	if id, _ := ActiveSM4KeyID(); id != "k2025" {
		t.Fatalf("active=%q", id)
	}
	t.Setenv(SM4ActiveKeyEnv, "")

	// Retire the old key: rewrapped data still readable, un-rewrapped data fails loudly.
	t.Setenv(SM4KeyringEnv, "k2026=second-rotation-secret-002")
	if got, err := DecryptProviderSecret(newCT); err != nil || got != "sk-rotate" {
		t.Fatalf("rotated value unreadable: %q %v", got, err)
	}
	if _, err := DecryptProviderSecret(oldCT); !errors.Is(err, ErrSM4KeyNotFound) {
		t.Fatalf("retired key must fail with ErrSM4KeyNotFound, got %v", err)
	}
}

func TestSM4TamperAndMisuseFailClosed(t *testing.T) {
	resetSecretEnv(t)
	t.Setenv(CipherEnv, CipherSM4GCM)
	t.Setenv(SM4KeyringEnv, "ka=aaaaaaaaaaaaaaaaaaaa,kb=bbbbbbbbbbbbbbbbbbbb")
	ct, _, err := EncryptProviderSecret("sk-bound")
	if err != nil {
		t.Fatal(err)
	}
	// Relabel the key id: header is in the AAD, so this must not decrypt.
	relabelled := strings.Replace(ct, sm4Marker+"ka:", sm4Marker+"kb:", 1)
	if _, err := DecryptProviderSecret(relabelled); err == nil {
		t.Fatal("relabelled key id decrypted")
	}
	// Move a provider value into the CA family.
	moved := caPrivateKeyPrefix + strings.TrimPrefix(ct, providerSecretPrefix)
	if _, err := DecryptCAPrivateKey(moved); err == nil {
		t.Fatal("provider SM4 value decrypted as CA key")
	}
	// Bit flip in the body.
	flipped := []byte(ct)
	flipped[len(flipped)-3] ^= 0x01
	if _, err := DecryptProviderSecret(string(flipped)); err == nil {
		t.Fatal("tampered SM4 value decrypted")
	}
	// A broken SM4 header must not fall back to AES parsing.
	if _, err := DecryptProviderSecret(providerSecretPrefix + sm4Marker + "no-payload-separator"); !errors.Is(err, ErrMalformedSM4Header) {
		t.Fatalf("malformed header err=%v", err)
	}
	if DescribeCiphertext(providerSecretPrefix+sm4Marker+"BAD KEY:xx") != "malformed" {
		t.Fatal("malformed header not classified")
	}
}

func TestInvalidConfigurationFailsClosedOnWrite(t *testing.T) {
	resetSecretEnv(t)
	aesCT, _, _ := EncryptProviderSecret("sk-before")

	t.Setenv(CipherEnv, "sm4-cbc")
	if _, _, err := EncryptProviderSecret("x"); !errors.Is(err, ErrUnsupportedCipher) {
		t.Fatalf("unknown cipher must fail, got %v", err)
	}
	// Reads do not depend on the write switch.
	if got, err := DecryptProviderSecret(aesCT); err != nil || got != "sk-before" {
		t.Fatalf("read under bad write config: %q %v", got, err)
	}

	t.Setenv(CipherEnv, CipherSM4GCM)
	for _, ring := range []string{"root=reserved-name-secret-01", "Bad=abcdefghijklmnopqr", "k1=short", "k1=abcdefghijklmnopqr,k1=abcdefghijklmnopqr", "k1"} {
		t.Setenv(SM4KeyringEnv, ring)
		if _, _, err := EncryptProviderSecret("x"); !errors.Is(err, ErrInvalidSM4Keyring) {
			t.Fatalf("ring %q must be rejected, got %v", ring, err)
		}
	}
	t.Setenv(SM4KeyringEnv, "k1=abcdefghijklmnopqr")
	t.Setenv(SM4ActiveKeyEnv, "k9")
	if _, _, err := EncryptProviderSecret("x"); !errors.Is(err, ErrSM4KeyNotFound) {
		t.Fatalf("unknown active key must fail, got %v", err)
	}
}

func TestMCPResultSM4KeepsAADBinding(t *testing.T) {
	resetSecretEnv(t)
	aesCT, err := EncryptMCPResult([]byte(`{"r":1}`), []byte("aad-a"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(CipherEnv, CipherSM4GCM)
	sm4CT, err := EncryptMCPResult([]byte(`{"r":2}`), []byte("aad-a"))
	if err != nil || !strings.HasPrefix(sm4CT, mcpResultPrefix+sm4Marker) {
		t.Fatalf("SM4 MCP write: %q %v", sm4CT, err)
	}
	for _, ct := range []string{aesCT, sm4CT} {
		if _, err := DecryptMCPResult(ct, []byte("aad-a")); err != nil {
			t.Fatalf("decrypt %q: %v", ct[:12], err)
		}
		if _, err := DecryptMCPResult(ct, []byte("aad-b")); err == nil {
			t.Fatalf("different AAD decrypted %q", ct[:12])
		}
	}
	// SM4 MCP result must not be readable through the no-AAD provider API.
	if _, err := DecryptProviderSecret(providerSecretPrefix + strings.TrimPrefix(sm4CT, mcpResultPrefix)); err == nil {
		t.Fatal("MCP result decrypted via provider-secret API")
	}
}
