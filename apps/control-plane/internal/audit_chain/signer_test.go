package audit_chain

import (
	"testing"
)

func TestSignVerify(t *testing.T) {
	key := []byte("test-secret-key")
	ch := ChainHash("", PayloadHash(map[string]any{"action": "login"}), 1)

	sig := Sign(ch, key)
	if !Verify(ch, sig, key) {
		t.Fatal("expected Verify to return true for valid signature")
	}
}

func TestVerifyFailsOnTamperedChainHash(t *testing.T) {
	key := []byte("test-secret-key")
	ch := ChainHash("", PayloadHash(map[string]any{"action": "login"}), 1)
	sig := Sign(ch, key)

	tampered := ch[:len(ch)-1] + "x"
	if Verify(tampered, sig, key) {
		t.Fatal("expected Verify to return false for tampered chain_hash")
	}
}

func TestVerifyFailsWithWrongKey(t *testing.T) {
	ch := ChainHash("", PayloadHash(map[string]any{"action": "logout"}), 2)
	sig := Sign(ch, []byte("key-a"))
	if Verify(ch, sig, []byte("key-b")) {
		t.Fatal("expected Verify to return false with wrong key")
	}
}
