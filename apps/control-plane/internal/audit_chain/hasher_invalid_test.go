package audit_chain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

func TestAuditCanonicalHashesRejectInvalidJSONUnderBothAlgorithms(t *testing.T) {
	for _, name := range []string{AlgSHA256, AlgSM3} {
		t.Run(name, func(t *testing.T) {
			alg, _ := AlgorithmByName(name)
			for _, payload := range []any{map[string]any{"number": math.NaN()}, map[string]any{"number": math.Inf(1)}, map[string]any{"raw": json.RawMessage(`{"a":1,"a":2}`)}} {
				if digest := alg.PayloadHash(payload); digest != "" {
					t.Fatalf("invalid input fabricated a digest: %s", name)
				}
				sha := sha256.Sum256(nil)
				digest := hex.EncodeToString(sha[:])
				if name == AlgSM3 {
					sm := sm3.Sum(nil)
					digest = hex.EncodeToString(sm[:])
				}
				chain := alg.ChainHash("", digest, 1)
				key := []byte("synthetic-audit-test-key")
				if detail := VerifyRow(alg, key, "", false, "", payload, digest, chain, alg.Sign(chain, key), 1); detail != "payload_hash mismatch" {
					t.Fatalf("invalid input passed content verification: %q", detail)
				}
			}
		})
	}
}
