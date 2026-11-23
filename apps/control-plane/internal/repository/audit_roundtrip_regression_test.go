package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
)

type auditChangingJSON struct{ calls int }

func (v *auditChangingJSON) MarshalJSON() ([]byte, error) {
	v.calls++
	return []byte(fmt.Sprintf(`{"value":%d}`, v.calls)), nil
}

func TestAuditCanonicalWriteReadPreservesJSONTypesAndExactNumbers(t *testing.T) {
	_, repo := setupAuditChainTestDB(t)
	ctx := context.Background()
	for _, alg := range []string{audit_chain.AlgSHA256, audit_chain.AlgSM3} {
		t.Run(alg, func(t *testing.T) {
			payload := map[string]any{
				"struct": struct {
					Z int `json:"z"`
					A int `json:"a"`
				}{1, 2},
				"typed_slice": []struct {
					Z int `json:"z"`
					A int `json:"a"`
				}{{3, 4}},
				"raw":       json.RawMessage(`{"z":1e2,"a":1.2300,"large":9007199254740993,"decimal":0.10000000000000001,"zero":-0}`),
				"large_int": int64(9007199254740993), "large_neighbor": int64(9007199254740992),
				"nil_map": map[string]any(nil), "nil_slice": []any(nil), "typed_nil_slice": []string(nil),
				"empty_map": map[string]any{}, "empty_slice": []any{},
				"tiny": json.Number("1e-100"), "big_exp": json.Number("1e100"),
				"at": time.Date(2026, 10, 8, 19, 29, 40, 783227000, time.FixedZone("CST", 8*3600)),
			}
			id := "roundtrip-" + fmt.Sprint(time.Now().UnixNano())
			if err := repo.AppendWithAlgorithm(ctx, alg, "audit-test", "roundtrip", id, payload); err != nil {
				t.Fatal(err)
			}
			seq := currentMaxSeq(t, repo)
			res, err := repo.VerifyByRecordedAlgorithm(ctx, seq, seq)
			if err != nil || !res.OK {
				t.Fatalf("JSONB roundtrip failed: %+v %v", res, err)
			}
			if alg == audit_chain.AlgSHA256 {
				res, err = repo.Verify(ctx, seq, seq)
				if err != nil || !res.OK {
					t.Fatalf("SHA verifier: %+v %v", res, err)
				}
			}
			var raw []byte
			if err = repo.db.QueryRow(ctx, `SELECT payload_json FROM audit_chain WHERE seq=$1`, seq).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var decoded map[string]json.RawMessage
			if err = json.Unmarshal(raw, &decoded); err != nil {
				t.Fatal(err)
			}
			if string(decoded["large_int"]) != "9007199254740993" || string(decoded["large_neighbor"]) != "9007199254740992" || string(decoded["nil_map"]) != "null" || string(decoded["nil_slice"]) != "null" {
				t.Fatal("stored exact numbers/null changed")
			}
		})
	}
}

func TestAuditAppendFreezesPayloadBeforeHashAndStorage(t *testing.T) {
	_, repo := setupAuditChainTestDB(t)
	ctx := context.Background()
	for _, alg := range []string{audit_chain.AlgSHA256, audit_chain.AlgSM3} {
		changing := &auditChangingJSON{}
		if err := repo.AppendWithAlgorithm(ctx, alg, "audit-test", "freeze", fmt.Sprint(time.Now().UnixNano()), map[string]any{"mutable": changing}); err != nil {
			t.Fatal(err)
		}
		seq := currentMaxSeq(t, repo)
		res, err := repo.VerifyByRecordedAlgorithm(ctx, seq, seq)
		if err != nil || !res.OK || changing.calls != 1 {
			t.Fatalf("payload was not frozen once: calls=%d result=%+v %v", changing.calls, res, err)
		}
	}
}

func TestAuditInvalidPayloadFailsBeforeInsertion(t *testing.T) {
	_, repo := setupAuditChainTestDB(t)
	ctx := context.Background()
	for _, value := range []any{math.NaN(), math.Inf(1), func() {}, json.RawMessage(`{"a":1,"a":2}`), json.RawMessage(`{"bad":`)} {
		before := currentMaxSeq(t, repo)
		if err := repo.Append(ctx, "audit-test", "invalid", fmt.Sprint(time.Now().UnixNano()), map[string]any{"x": value}); err == nil {
			t.Fatalf("invalid payload accepted: %T", value)
		}
		if after := currentMaxSeq(t, repo); after != before {
			t.Fatal("invalid payload inserted a row")
		}
	}
}

// The historical fixture deliberately retains the original v1 encoder. It
// never calls the current production canonicalizer to manufacture old hashes.
func auditV1JSON(v any) []byte {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b := []byte("{")
		for i, k := range keys {
			if i > 0 {
				b = append(b, ',')
			}
			key, _ := json.Marshal(k)
			b = append(b, key...)
			b = append(b, ':')
			b = append(b, auditV1JSON(x[k])...)
		}
		return append(b, '}')
	case []any:
		b := []byte("[")
		for i, y := range x {
			if i > 0 {
				b = append(b, ',')
			}
			b = append(b, auditV1JSON(y)...)
		}
		return append(b, ']')
	default:
		b, err := json.Marshal(v)
		if err != nil {
			panic(err)
		}
		return b
	}
}
func auditV1Hash(v any) string { h := sha256.Sum256(auditV1JSON(v)); return hex.EncodeToString(h[:]) }
func appendHistoricalAuditFixture(t *testing.T, repo *AuditChainRepository, payload map[string]any, storedHash string) int64 {
	t.Helper()
	ctx := context.Background()
	tx, err := repo.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	prev, seq, err := reserveAuditChainSequence(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	chain := audit_chain.ChainHash(prev, storedHash, seq)
	signature := audit_chain.Sign(chain, repo.key)
	if _, err = tx.Exec(ctx, `INSERT INTO audit_chain(seq,tenant_id,event_type,event_id,payload_json,prev_hash,payload_hash,chain_hash,signature) VALUES($1,'audit-test','audit_op',$2,$3,NULLIF($4,''),$5,$6,$7)`, seq, fmt.Sprint(time.Now().UnixNano()), payload, prev, storedHash, chain, signature); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return seq
}

func TestAuditHistoricalCatalogStructVerifiesWithoutRewritingRows(t *testing.T) {
	_, repo := setupAuditChainTestDB(t)
	ctx := context.Background()
	result := CatalogSnapshotResult{Created: 2, Updated: 1, Verified: 3, TotalSeen: 3, VerificationFailures: []CatalogProbeFailure{}, RemovedIDs: []string{}, SyncedAt: time.Date(2026, 10, 8, 11, 29, 40, 783227000, time.UTC)}
	original := map[string]any{"provider_id": "provider-test", "result": result}
	storedHash := auditV1Hash(original)
	seq := appendHistoricalAuditFixture(t, repo, original, storedHash)
	var before []byte
	if err := repo.db.QueryRow(ctx, `SELECT row_to_json(a)::text FROM audit_chain a WHERE seq=$1`, seq).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, verify := range []func(context.Context, int64, int64) (*VerifyResult, error){repo.Verify, repo.VerifyByRecordedAlgorithm} {
		res, err := verify(ctx, seq, seq)
		if err != nil || !res.OK {
			t.Fatalf("historical struct mismatch: %+v %v", res, err)
		}
	}
	var after []byte
	if err := repo.db.QueryRow(ctx, `SELECT row_to_json(a)::text FROM audit_chain a WHERE seq=$1`, seq).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("verification rewrote historical row")
	}
	encode, _ := json.Marshal(original)
	for _, kind := range []string{"changed-counter", "changed-provider", "unknown-field", "missing-zero-field", "null-array", "missing-nested-field", "extra-optional-empty", "large-counter-rounding"} {
		t.Run(kind, func(t *testing.T) {
			var changed map[string]any
			if err := json.Unmarshal(encode, &changed); err != nil {
				t.Fatal(err)
			}
			r := changed["result"].(map[string]any)
			switch kind {
			case "changed-counter":
				r["created"] = 3
			case "changed-provider":
				changed["provider_id"] = "another-provider"
			case "unknown-field":
				r["unrecorded"] = true
			case "missing-zero-field":
				delete(r, "pending")
			case "null-array":
				r["removed_model_ids"] = nil
			case "missing-nested-field":
				r["verification_failures"] = []any{map[string]any{"model_id": "m", "upstream_model_id": "u"}}
			case "extra-optional-empty":
				r["not_found_model_ids"] = []any{}
			case "large-counter-rounding":
				r["total_seen"] = json.Number("9007199254740993")
			}
			bad := appendHistoricalAuditFixture(t, repo, changed, storedHash)
			for _, verify := range []func(context.Context, int64, int64) (*VerifyResult, error){repo.Verify, repo.VerifyByRecordedAlgorithm} {
				res, err := verify(ctx, bad, bad)
				if err != nil || res.OK || res.Detail != "payload_hash mismatch" {
					t.Fatalf("tampered history accepted: %+v %v", res, err)
				}
			}
		})
	}
}

func TestAuditLegacyScientificFloatUsesExactSemanticCompatibility(t *testing.T) {
	_, repo := setupAuditChainTestDB(t)
	ctx := context.Background()
	for _, value := range []float64{1e21, 1e-7, 0.1} {
		original := map[string]any{"number": value}
		seq := appendHistoricalAuditFixture(t, repo, original, auditV1Hash(original))
		res, err := repo.Verify(ctx, seq, seq)
		if err != nil || !res.OK {
			t.Fatalf("exact legacy float rejected: %+v %v", res, err)
		}
	}
	large := map[string]any{"number": int64(9007199254740993)}
	seq := appendHistoricalAuditFixture(t, repo, large, auditV1Hash(large))
	res, err := repo.Verify(ctx, seq, seq)
	if err != nil || !res.OK {
		t.Fatalf("precise legacy integer rejected: %+v %v", res, err)
	}
	tampered := map[string]any{"number": json.Number("9007199254740992")}
	seq = appendHistoricalAuditFixture(t, repo, tampered, auditV1Hash(large))
	res, err = repo.Verify(ctx, seq, seq)
	if err != nil || res.OK {
		t.Fatalf("neighbor integer tampering accepted: %+v %v", res, err)
	}
}
