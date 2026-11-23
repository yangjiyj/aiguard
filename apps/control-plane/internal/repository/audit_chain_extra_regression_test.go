package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestAuditHeaderConflictOnceFreezesAllIdempotencyChecks(t *testing.T) {
	_, repo := setupAuditChainTestDB(t)
	ctx := context.Background()
	id := "freeze-once-" + fmt.Sprint(time.Now().UnixNano())
	changing := &auditChangingJSON{}
	if err := repo.AppendHeaderContractConflictOnce(ctx, "audit-test", id, map[string]any{"detail": changing}); err != nil {
		t.Fatal(err)
	}
	if changing.calls != 1 {
		t.Fatalf("critical audit reread caller after freezing: %d", changing.calls)
	}
	seq := currentMaxSeq(t, repo)
	replay := &auditChangingJSON{}
	if err := repo.AppendHeaderContractConflictOnce(ctx, "audit-test", id, map[string]any{"detail": replay}); err != nil || replay.calls != 1 || currentMaxSeq(t, repo) != seq {
		t.Fatalf("snapshot replay: calls=%d %v", replay.calls, err)
	}
}

func TestAuditHistoricalNonemptyCatalogNestedSchemaIsStrict(t *testing.T) {
	_, repo := setupAuditChainTestDB(t)
	ctx := context.Background()
	original := map[string]any{"provider_id": "provider-test", "result": CatalogSnapshotResult{
		Created: 1, VerificationFailed: 1, TotalSeen: 2, NotFoundModelIDs: []string{"not-found"},
		VerificationFailures: []CatalogProbeFailure{{ModelID: "m", UpstreamModelID: "u", Reason: ""}}, RemovedIDs: []string{"first", "second"}, SyncedAt: time.Date(2026, 10, 8, 11, 29, 40, 0, time.UTC),
	}}
	storedHash := auditV1Hash(original)
	seq := appendHistoricalAuditFixture(t, repo, original, storedHash)
	res, err := repo.Verify(ctx, seq, seq)
	if err != nil || !res.OK {
		t.Fatalf("nonempty original: %+v %v", res, err)
	}
	raw, _ := json.Marshal(original)
	for _, kind := range []string{"missing-empty-reason", "unknown-nested-field", "reordered-array", "changed-time-string", "fractional-counter", "negative-counter", "unknown-top-field"} {
		t.Run(kind, func(t *testing.T) {
			var changed map[string]any
			_ = json.Unmarshal(raw, &changed)
			r := changed["result"].(map[string]any)
			failure := r["verification_failures"].([]any)[0].(map[string]any)
			switch kind {
			case "missing-empty-reason":
				delete(failure, "reason")
			case "unknown-nested-field":
				failure["extra"] = true
			case "reordered-array":
				r["removed_model_ids"] = []any{"second", "first"}
			case "changed-time-string":
				r["synced_at"] = "2026-10-08T11:29:41Z"
			case "fractional-counter":
				r["created"] = 1.5
			case "negative-counter":
				r["created"] = -1
			case "unknown-top-field":
				changed["action"] = "different"
			}
			bad := appendHistoricalAuditFixture(t, repo, changed, storedHash)
			for _, verify := range []func(context.Context, int64, int64) (*VerifyResult, error){repo.Verify, repo.VerifyByRecordedAlgorithm} {
				res, err := verify(ctx, bad, bad)
				if err != nil || res.OK || res.Detail != "payload_hash mismatch" {
					t.Fatalf("nested/schema tampering accepted: %+v %v", res, err)
				}
			}
		})
	}
}

func TestAuditLegacyFloatCompatibilityRejectsDecimalAndIntegerRounding(t *testing.T) {
	_, repo := setupAuditChainTestDB(t)
	ctx := context.Background()
	for _, pair := range []struct {
		original any
		changed  json.Number
	}{
		{0.1, json.Number("0.10000000000000001")},
		{float64(9007199254740992), json.Number("9007199254740993")},
		{1e-7, json.Number("0.00000010000000001")},
	} {
		t.Run(string(pair.changed), func(t *testing.T) {
			stored := auditV1Hash(map[string]any{"number": pair.original})
			seq := appendHistoricalAuditFixture(t, repo, map[string]any{"number": pair.changed}, stored)
			for _, verify := range []func(context.Context, int64, int64) (*VerifyResult, error){repo.Verify, repo.VerifyByRecordedAlgorithm} {
				res, err := verify(ctx, seq, seq)
				if err != nil || res.OK || res.Detail != "payload_hash mismatch" {
					t.Fatalf("rounded legacy candidate accepted: %+v %v", res, err)
				}
			}
		})
	}
}
