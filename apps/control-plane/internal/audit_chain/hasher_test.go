package audit_chain

import (
	"testing"
)

func TestCanonicalJSONStable(t *testing.T) {
	// Two maps with same content but different insertion order must produce same hash
	h1 := PayloadHash(map[string]any{"b": 2, "a": 1})
	h2 := PayloadHash(map[string]any{"a": 1, "b": 2})
	if h1 != h2 {
		t.Fatalf("hash mismatch: %q vs %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("expected 64-char hex, got %d", len(h1))
	}
}

func TestChainHashDependsOnPrev(t *testing.T) {
	ph := PayloadHash(map[string]any{"x": 1})
	h1 := ChainHash("prev_aaa", ph, 1)
	h2 := ChainHash("prev_bbb", ph, 1)
	if h1 == h2 {
		t.Fatal("different prevHash should produce different chain_hash")
	}
}

func TestChainHashDependsOnSeq(t *testing.T) {
	ph := PayloadHash(map[string]any{"x": 1})
	h1 := ChainHash("sameprev", ph, 1)
	h2 := ChainHash("sameprev", ph, 2)
	if h1 == h2 {
		t.Fatal("different seq should produce different chain_hash")
	}
}

func TestCanonicalJSONNestedArray(t *testing.T) {
	a := map[string]any{"tools": []any{map[string]any{"b": 2, "a": 1}}}
	b := map[string]any{"tools": []any{map[string]any{"a": 1, "b": 2}}}
	if PayloadHash(a) != PayloadHash(b) {
		t.Error("nested array of maps should produce stable hash")
	}
}
