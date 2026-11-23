package repository

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNativeProtocolProbeBindsCredentialAndProviderConfigurationInTransaction(t *testing.T) {
	db := verifiedModelsTestDB(t)
	for _, change := range []string{"unchanged", "ciphertext", "credential-id", "provider-url", "provider-type", "disabled"} {
		t.Run(change, func(t *testing.T) {
			resetVerifiedModelsData(t, db)
			seedVerifiedProvider(t, db, "tenant-a", "provider-a")
			seedVerifiedModel(t, db, "model-a", "provider-a", "native", "native", "Native", nil, "pending")
			ctx := context.Background()
			if _, err := db.Exec(ctx, `UPDATE providers SET provider_type='gemini',base_url='https://native.fixture' WHERE id='provider-a'`); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			record := ModelProtocolProbeRecord{CredentialID: verifiedCredentialID("provider-a"), SecretCiphertext: "test-ciphertext", ProviderConfigDigest: VerifiedModelSyncProviderConfigDigest("gemini", "https://native.fixture", "api_key"), SourceVersion: "native-fixture", VerifiedAt: now, ExpiresAt: now.Add(time.Hour), Endpoints: []ModelEndpointProbeResult{{EndpointType: "chat", State: "supported"}}}
			changes := map[string]string{"ciphertext": `UPDATE provider_credentials SET secret_ciphertext='rotated'`, "credential-id": `UPDATE provider_credentials SET id='rotated'`, "provider-url": `UPDATE providers SET base_url='https://changed.fixture'`, "provider-type": `UPDATE providers SET provider_type='bedrock'`, "disabled": `UPDATE providers SET status='disabled'`}
			if query := changes[change]; query != "" {
				if _, err := db.Exec(ctx, query); err != nil {
					t.Fatal(err)
				}
			}
			err := NewModelRepository(db).RecordProtocolProbe(ctx, "tenant-a", "provider-a", "model-a", map[string]interface{}{"protocols": map[string]interface{}{"chat_completions": true}}, record)
			want := 0
			if change == "unchanged" {
				want = 1
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrVerifiedModelSyncConflict) {
				t.Fatalf("changed identity accepted: %v", err)
			}
			var facts int
			if err := db.QueryRow(ctx, `SELECT count(*) FROM model_endpoint_capability_facts`).Scan(&facts); err != nil || facts != want {
				t.Fatalf("facts=%d want=%d err=%v", facts, want, err)
			}
			var status string
			if err := db.QueryRow(ctx, `SELECT status FROM models WHERE id='model-a'`).Scan(&status); err != nil || status != "pending" {
				t.Fatalf("probe changed pending admission status %s %v", status, err)
			}
		})
	}
}

func TestNativeFactTransactionHoldsCredentialLockAgainstRotation(t *testing.T) {
	db := verifiedModelsTestDB(t)
	resetVerifiedModelsData(t, db)
	seedVerifiedProvider(t, db, "tenant-a", "provider-a")
	seedVerifiedModel(t, db, "model-a", "provider-a", "native", "native", "Native", nil, "active")
	ctx := context.Background()
	now := time.Now().UTC()
	record := ModelProtocolProbeRecord{CredentialID: verifiedCredentialID("provider-a"), SecretCiphertext: "test-ciphertext", ProviderConfigDigest: VerifiedModelSyncProviderConfigDigest("azure", "", "api_key"), SourceVersion: "native-lock-fixture", VerifiedAt: now, ExpiresAt: now.Add(time.Hour), Endpoints: []ModelEndpointProbeResult{{EndpointType: "chat", State: "supported"}}}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = recordModelProtocolProbeTx(ctx, tx, "tenant-a", "provider-a", "model-a", []byte(`{"protocols":{"chat_completions":true}}`), record); err != nil {
		t.Fatal(err)
	}
	concurrent, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err = db.Exec(concurrent, `UPDATE provider_credentials SET secret_ciphertext='rotated' WHERE provider_id='provider-a'`); err == nil {
		t.Fatal("rotation bypassed in-flight fact transaction lock")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `UPDATE provider_credentials SET secret_ciphertext='rotated' WHERE provider_id='provider-a'`); err != nil {
		t.Fatal(err)
	}
}

func TestNativeAdmissionRollsBackMappingAndFactsOnChangedIdentityOrPersistenceFailure(t *testing.T) {
	db := verifiedModelsTestDB(t)
	ctx := context.Background()
	for _, kind := range []string{"success", "rotated-credential", "provider-url", "concurrent-mapping", "fact-write-failed", "new-rotated"} {
		t.Run(kind, func(t *testing.T) {
			resetVerifiedModelsData(t, db)
			seedVerifiedProvider(t, db, "tenant-a", "provider-a")
			if _, err := db.Exec(ctx, `UPDATE providers SET provider_type='gemini',base_url='https://native.fixture' WHERE id='provider-a'`); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			record := ModelProtocolProbeRecord{CredentialID: verifiedCredentialID("provider-a"), SecretCiphertext: "test-ciphertext", ProviderConfigDigest: VerifiedModelSyncProviderConfigDigest("gemini", "https://native.fixture", "api_key"), SourceVersion: "new-native-proof", VerifiedAt: now, ExpiresAt: now.Add(time.Hour), Endpoints: []ModelEndpointProbeResult{{EndpointType: "chat", State: "supported"}}}
			snapshot := NativeModelAdmissionSnapshot{ModelName: "public-native", ProbedDeployment: "new-deployment"}
			model := &Model{ProviderID: "provider-a", ModelName: "public-native", ModelLabel: "Native", UpstreamModelID: "new-deployment", Status: "active", Capabilities: map[string]interface{}{"protocols": map[string]interface{}{"chat_completions": true}}}
			repo := NewModelRepository(db)
			if kind != "new-rotated" {
				seedVerifiedModel(t, db, "existing", "provider-a", "public-native", "old-deployment", "Native", nil, "active")
				old := record
				old.SourceVersion = "old-proof"
				old.VerifiedAt = now.Add(-time.Hour)
				if err := repo.RecordProtocolProbe(ctx, "tenant-a", "provider-a", "existing", model.Capabilities, old); err != nil {
					t.Fatal(err)
				}
				snapshot.ExistingModelID = "existing"
				snapshot.ExistingDeployment = "old-deployment"
				snapshot.ExistingStatus = "active"
			}
			switch kind {
			case "rotated-credential", "new-rotated":
				if _, err := db.Exec(ctx, `UPDATE provider_credentials SET secret_ciphertext='rotated'`); err != nil {
					t.Fatal(err)
				}
			case "provider-url":
				if _, err := db.Exec(ctx, `UPDATE providers SET base_url='https://changed.fixture'`); err != nil {
					t.Fatal(err)
				}
			case "concurrent-mapping":
				if _, err := db.Exec(ctx, `UPDATE models SET upstream_model_id='concurrent-deployment' WHERE id='existing'`); err != nil {
					t.Fatal(err)
				}
			case "fact-write-failed":
				if _, err := db.Exec(ctx, `ALTER TABLE model_endpoint_capability_facts ADD CONSTRAINT reject_native_fixture CHECK(source_version<>'new-native-proof')`); err != nil {
					t.Fatal(err)
				}
			}
			created, err := repo.UpsertNativeVerifiedModel(ctx, "tenant-a", model, record, snapshot)
			if kind == "fact-write-failed" {
				if _, dropErr := db.Exec(ctx, `ALTER TABLE model_endpoint_capability_facts DROP CONSTRAINT reject_native_fixture`); dropErr != nil {
					t.Fatal(dropErr)
				}
			}
			if kind == "success" {
				if err != nil || created || model.ID != "existing" {
					t.Fatalf("valid atomic update failed created=%v err=%v", created, err)
				}
			} else if err == nil {
				t.Fatal("changed/unpersisted proof admitted mapping")
			}
			var count int
			if err := db.QueryRow(ctx, `SELECT count(*) FROM models`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if kind == "new-rotated" {
				if count != 0 {
					t.Fatal("failed new admission left an active model")
				}
				return
			}
			var deployment, version, state string
			if err := db.QueryRow(ctx, `SELECT upstream_model_id,status FROM models WHERE id='existing'`).Scan(&deployment, &state); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(ctx, `SELECT source_version FROM model_endpoint_capability_facts WHERE model_id='existing' AND endpoint_type='chat'`).Scan(&version); err != nil {
				t.Fatal(err)
			}
			expectedDeployment, expectedProof := "old-deployment", "old-proof"
			if kind == "success" {
				expectedDeployment, expectedProof = "new-deployment", "new-native-proof"
			}
			if kind == "concurrent-mapping" {
				expectedDeployment = "concurrent-deployment"
			}
			if deployment != expectedDeployment || version != expectedProof || state != "active" {
				t.Fatalf("partial native admission leaked deployment=%s proof=%s status=%s", deployment, version, state)
			}
		})
	}
}

func TestConcurrentNativeAdmissionsUsePreProbeMappingCAS(t *testing.T) {
	db := verifiedModelsTestDB(t)
	ctx := context.Background()
	resetVerifiedModelsData(t, db)
	seedVerifiedProvider(t, db, "tenant-a", "provider-a")
	seedVerifiedModel(t, db, "existing", "provider-a", "public-native", "old-deployment", "Native", nil, "active")
	now := time.Now().UTC()
	snapshot := NativeModelAdmissionSnapshot{ModelName: "public-native", ExistingModelID: "existing", ExistingDeployment: "old-deployment", ExistingStatus: "active"}
	record := ModelProtocolProbeRecord{CredentialID: verifiedCredentialID("provider-a"), SecretCiphertext: "test-ciphertext", ProviderConfigDigest: VerifiedModelSyncProviderConfigDigest("azure", "", "api_key"), SourceVersion: "native-cas", VerifiedAt: now, ExpiresAt: now.Add(time.Hour), Endpoints: []ModelEndpointProbeResult{{EndpointType: "chat", State: "supported"}}}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, deployment := range []string{"deployment-a", "deployment-b"} {
		wait.Add(1)
		go func(deployment string) {
			defer wait.Done()
			<-start
			own := snapshot
			own.ProbedDeployment = deployment
			_, err := NewModelRepository(db).UpsertNativeVerifiedModel(ctx, "tenant-a", &Model{ProviderID: "provider-a", ModelName: "public-native", UpstreamModelID: deployment, Status: "active", Capabilities: map[string]interface{}{"protocols": map[string]interface{}{"chat_completions": true}}}, record, own)
			results <- err
		}(deployment)
	}
	close(start)
	wait.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrVerifiedModelSyncConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("mapping CAS allowed stale evidence success=%d conflicts=%d", success, conflict)
	}
}
