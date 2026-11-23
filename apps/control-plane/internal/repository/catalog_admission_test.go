package repository

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func catalogAdmissionProbe() *ModelProtocolProbeRecord {
	now := time.Now().UTC()
	return &ModelProtocolProbeRecord{
		SourceVersion:        "catalog-admission-regression",
		ProviderConfigDigest: VerifiedModelSyncProviderConfigDigest("openai", "", ""),
		VerifiedAt:           now, ExpiresAt: now.Add(time.Hour),
		Endpoints: []ModelEndpointProbeResult{{EndpointType: "chat", State: "supported"}},
	}
}

func TestCatalogSnapshotOnlyManagesVerifiedSelectedModels(t *testing.T) {
	for _, selectFailed := range []bool{false, true} {
		t.Run(fmt.Sprintf("select_failed=%v", selectFailed), func(t *testing.T) {
			db := catalogSnapshotTestDB(t)
			ctx := context.Background()
			seedStatus(t, db, "ta", "p1", "existing-manual", "existing-manual", "active", "active", "active")
			repo := NewModelRepository(db)
			provider := &Provider{ID: "p1", TenantID: "ta", ProviderType: "openai", Status: "active"}
			apply := func(items []CatalogSnapshotModel) CatalogSnapshotResult {
				token, err := repo.BeginCatalogSync(ctx, "ta", "p1")
				if err != nil {
					t.Fatal(err)
				}
				result, err := repo.ApplyCatalogSnapshot(ctx, CatalogSnapshotInput{
					TenantID: "ta", Provider: provider, CredentialID: "c-p1", LeaseToken: token, Models: items,
				})
				if err != nil {
					t.Fatal(err)
				}
				return result
			}
			items := make([]CatalogSnapshotModel, 49)
			for i := range items {
				id := fmt.Sprintf("catalog-model-%02d", i)
				items[i] = CatalogSnapshotModel{ID: id, Name: id, Approved: selectFailed}
				if i < 7 {
					items[i].Approved = true
					items[i].Probe = catalogAdmissionProbe()
					items[i].HealthObservedAt = time.Now()
				} else if selectFailed {
					items[i].ProbeFailure = "not_deployed"
				}
			}
			result := apply(items)
			if result.Created != 7 || result.Verified != 7 || result.Pending != 0 {
				t.Fatalf("49 catalog entries must admit only 7 verified models: %+v", result)
			}
			if selectFailed && result.VerificationFailed != 42 {
				t.Fatalf("missing failed verification results: %+v", result)
			}
			var managed, candidates int
			if err := db.QueryRow(ctx, `SELECT count(*) FROM models WHERE provider_id='p1' AND id<>'existing-manual'`).Scan(&managed); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(ctx, `SELECT count(*) FROM model_catalog_entries WHERE provider_id='p1' AND model_id IS NULL`).Scan(&candidates); err != nil {
				t.Fatal(err)
			}
			if managed != 7 || candidates != 42 {
				t.Fatalf("managed=%d catalog-only=%d", managed, candidates)
			}
			for i := range items {
				items[i].Approved = false
				items[i].Probe = nil
				items[i].ProbeFailure = ""
			}
			refreshed := apply(items)
			if refreshed.Created != 0 || refreshed.Pending != 0 {
				t.Fatalf("inventory refresh admitted models: %+v", refreshed)
			}
			if err := db.QueryRow(ctx, `SELECT count(*) FROM models WHERE provider_id='p1' AND status='active' AND id<>'existing-manual'`).Scan(&managed); err != nil {
				t.Fatal(err)
			}
			if managed != 7 {
				t.Fatalf("inventory refresh changed managed models: %d", managed)
			}
		})
	}
}

func TestCatalogSnapshotRejectsUnsupportedProbeAdmission(t *testing.T) {
	db := catalogSnapshotTestDB(t)
	seedStatus(t, db, "ta", "p1", "existing-manual", "existing-manual", "active", "active", "active")
	repo := NewModelRepository(db)
	token, err := repo.BeginCatalogSync(context.Background(), "ta", "p1")
	if err != nil {
		t.Fatal(err)
	}
	proof := catalogAdmissionProbe()
	proof.Endpoints[0].State = "unsupported"
	result, err := repo.ApplyCatalogSnapshot(context.Background(), CatalogSnapshotInput{
		TenantID: "ta", Provider: &Provider{ID: "p1", TenantID: "ta", ProviderType: "openai", Status: "active"},
		CredentialID: "c-p1", LeaseToken: token, Models: []CatalogSnapshotModel{{ID: "not-deployed", Approved: true, Probe: proof}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Created != 0 || result.Verified != 0 || result.VerificationFailed != 1 {
		t.Fatalf("unsupported proof admitted model: %+v", result)
	}
}
