package audit_chain

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

func TestSM3PrimitivesKnownAnswerAndIndependence(t *testing.T) {
	// ChainHashSM3 hashes prev+payloadHash+decimal(seq); "ab"+""+"c" is not
	// reachable, so use prev="a", payloadHash="b", seq=0 -> SM3("ab0") and
	// compare against the library directly, plus the GB/T 32905 "abc" vector.
	want := sm3.Sum([]byte("ab0"))
	if ChainHashSM3("a", "b", 0) != hex.EncodeToString(want[:]) {
		t.Fatal("ChainHashSM3 input layout changed")
	}
	abc := sm3.Sum([]byte("abc"))
	if hex.EncodeToString(abc[:]) != "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" {
		t.Fatal("SM3 KAT failed")
	}
	if got := PayloadHashSM3(map[string]any{}); len(got) != 64 {
		t.Fatalf("SM3 hex digest must fit CHAR(64), got %d", len(got))
	}
	payload := map[string]any{"b": 2, "a": "x"}
	if PayloadHashSM3(payload) == PayloadHash(payload) {
		t.Fatal("SM3 and SHA-256 payload hashes must differ")
	}
	// Canonical ordering: key order must not matter.
	if PayloadHashSM3(map[string]any{"a": "x", "b": 2}) != PayloadHashSM3(payload) {
		t.Fatal("SM3 payload hash is not canonical")
	}
	sig := SignSM3("chain", []byte("k"))
	if !VerifySM3("chain", sig, []byte("k")) || VerifySM3("chain", sig, []byte("k2")) || VerifySM3("chain2", sig, []byte("k")) {
		t.Fatal("HMAC-SM3 verify mismatch")
	}
	if Verify("chain", sig, []byte("k")) {
		t.Fatal("SM3 signature accepted by SHA-256 verifier")
	}
}

func TestAlgorithmByNameFailsClosed(t *testing.T) {
	for _, n := range []string{"", AlgSHA256, AlgSM3} {
		if _, ok := AlgorithmByName(n); !ok {
			t.Fatalf("%q must resolve", n)
		}
	}
	if _, ok := AlgorithmByName("md5"); ok {
		t.Fatal("unknown algorithm resolved")
	}
	if a, _ := AlgorithmByName(""); a.Name != AlgSHA256 {
		t.Fatal("default algorithm must stay SHA-256")
	}
}

func TestVerifyRowDetectsEachBreak(t *testing.T) {
	alg, _ := AlgorithmByName(AlgSM3)
	key := []byte("audit-key")
	payload := map[string]any{"event": "login", "user": "u1"}
	ph := alg.PayloadHash(payload)
	ch := alg.ChainHash("prev", ph, 7)
	sig := alg.Sign(ch, key)
	if d := VerifyRow(alg, key, "prev", true, "prev", payload, ph, ch, sig, 7); d != "" {
		t.Fatalf("intact row reported %q", d)
	}
	cases := map[string]string{
		"prev_hash mismatch":    VerifyRow(alg, key, "other", true, "prev", payload, ph, ch, sig, 7),
		"payload_hash mismatch": VerifyRow(alg, key, "prev", true, "prev", map[string]any{"event": "logout", "user": "u1"}, ph, ch, sig, 7),
		"chain_hash mismatch":   VerifyRow(alg, key, "prev", true, "prev", payload, ph, ch, sig, 8),
		"signature invalid":     VerifyRow(alg, []byte("wrong"), "prev", true, "prev", payload, ph, ch, sig, 7),
	}
	for want, got := range cases {
		if got != want {
			t.Fatalf("want %q got %q", want, got)
		}
	}
	// A SHA-256 chain row must not verify under SM3.
	sha, _ := AlgorithmByName(AlgSHA256)
	sph := sha.PayloadHash(payload)
	sch := sha.ChainHash("prev", sph, 7)
	if d := VerifyRow(alg, key, "prev", true, "prev", payload, sph, sch, sha.Sign(sch, key), 7); !strings.Contains(d, "mismatch") {
		t.Fatalf("SHA-256 row verified under SM3: %q", d)
	}
}
