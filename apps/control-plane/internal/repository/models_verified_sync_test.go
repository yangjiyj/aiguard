package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/testcontainer"
)

func TestRecordProtocolProbePersistsFactsAndPreservesUnrelatedCapabilities(t *testing.T) {
	db := verifiedModelsTestDB(t)
	resetVerifiedModelsData(t, db)
	seedVerifiedProvider(t, db, "tenant-a", "provider-a")
	seedVerifiedModel(t, db, "model-a", "provider-a", "gpt-5.5", "gpt-5.5", "GPT 5.5", map[string]interface{}{
		"routing":   map[string]interface{}{"fallback_provider_id": "keep-route"},
		"protocols": map[string]interface{}{"stream": true},
	}, "active")

	now := time.Now().UTC().Truncate(time.Second)
	record := ModelProtocolProbeRecord{
		SourceVersion:        "probe-test-v1",
		ProviderConfigDigest: "sha256:test",
		VerifiedAt:           now,
		ExpiresAt:            now.Add(30 * 24 * time.Hour),
		Endpoints: []ModelEndpointProbeResult{
			{EndpointType: "chat", State: "supported"},
			{EndpointType: "responses", State: "supported"},
		},
	}
	capabilities := map[string]interface{}{
		"modality": map[string]interface{}{"type": "text", "source": "default"},
		"protocols": map[string]interface{}{
			"chat_completions": true,
			"responses_native": true,
			"metadata":         map[string]interface{}{"verified": true, "source": "create_model_probe", "version": "probe-test-v1"},
		},
	}
	repo := NewModelRepository(db)
	if err := repo.RecordProtocolProbe(context.Background(), "tenant-a", "provider-a", "model-a", capabilities, record); err != nil {
		t.Fatal(err)
	}

	var encoded []byte
	if err := db.QueryRow(context.Background(), "SELECT capabilities_json FROM models WHERE id='model-a'").Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	routing, _ := got["routing"].(map[string]interface{})
	protocols, _ := got["protocols"].(map[string]interface{})
	if routing["fallback_provider_id"] != "keep-route" || protocols["stream"] != true || protocols["chat_completions"] != true || protocols["responses_native"] != true {
		t.Fatalf("merged capabilities = %#v", got)
	}
	for _, endpoint := range []string{"chat", "responses"} {
		var state, source string
		if err := db.QueryRow(context.Background(), "SELECT state,source FROM model_endpoint_capability_effective WHERE model_id='model-a' AND endpoint_type=$1", endpoint).Scan(&state, &source); err != nil {
			t.Fatal(err)
		}
		if state != "supported" || source != "probe" {
			t.Fatalf("%s state/source = %s/%s", endpoint, state, source)
		}
	}
}

func TestRecordProtocolProbeMessagesPersistsRealCapabilityFacts(t *testing.T) {
	db := verifiedModelsTestDB(t)
	resetVerifiedModelsData(t, db)
	seedVerifiedProvider(t, db, "tenant-a", "provider-a")
	seedVerifiedProvider(t, db, "tenant-b", "provider-b")
	seedVerifiedModel(t, db, "claude-model", "provider-a", "claude-test", "claude-upstream", "Claude", map[string]interface{}{
		"routing":   map[string]interface{}{"fallback_provider_id": "keep-route"},
		"protocols": map[string]interface{}{"stream": true},
	}, "active")
	now := time.Now().UTC().Truncate(time.Second)
	record := ModelProtocolProbeRecord{
		SourceVersion: "claude-native-probe", ProviderConfigDigest: "sha256:claude-test",
		VerifiedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		Endpoints: []ModelEndpointProbeResult{
			{EndpointType: "chat", State: "unknown", ErrorKind: "upstream_error"},
			{EndpointType: "responses", State: "unknown", ErrorKind: "upstream_error"},
			{EndpointType: "messages", State: "supported"},
		},
	}
	capabilities := map[string]interface{}{"protocols": map[string]interface{}{"anthropic_messages": true}}
	repo := NewModelRepository(db)
	if err := repo.RecordProtocolProbe(context.Background(), "tenant-a", "provider-a", "claude-model", capabilities, record); err != nil {
		t.Fatal(err)
	}
	var state, source, sourceVersion, digest string
	if err := db.QueryRow(context.Background(), `SELECT state,source,source_version,provider_config_digest FROM model_endpoint_capability_effective WHERE tenant_id='tenant-a' AND model_id='claude-model' AND endpoint_type='messages'`).Scan(&state, &source, &sourceVersion, &digest); err != nil {
		t.Fatal(err)
	}
	if state != "supported" || source != "probe" || sourceVersion != record.SourceVersion || digest != record.ProviderConfigDigest {
		t.Fatalf("messages capability binding = %s/%s/%s/%s", state, source, sourceVersion, digest)
	}
	var stored []byte
	var status string
	if err := db.QueryRow(context.Background(), `SELECT capabilities_json,status FROM models WHERE id='claude-model'`).Scan(&stored, &status); err != nil {
		t.Fatal(err)
	}
	var merged map[string]interface{}
	if err := json.Unmarshal(stored, &merged); err != nil {
		t.Fatal(err)
	}
	protocols := merged["protocols"].(map[string]interface{})
	if status != "active" || protocols["anthropic_messages"] != true || protocols["stream"] != true || merged["routing"].(map[string]interface{})["fallback_provider_id"] != "keep-route" {
		t.Fatalf("Messages probe did not preserve model/routing: %s %s", status, stored)
	}
	for _, foreign := range [][2]string{{"tenant-b", "provider-a"}, {"tenant-a", "provider-b"}} {
		if err := repo.RecordProtocolProbe(context.Background(), foreign[0], foreign[1], "claude-model", capabilities, record); err == nil {
			t.Fatal("cross-tenant or foreign provider probe accepted")
		}
	}
	for _, invalid := range []ModelEndpointProbeResult{{EndpointType: "arbitrary", State: "supported"}, {EndpointType: "messages", State: "healthy"}} {
		bad := record
		bad.Endpoints = []ModelEndpointProbeResult{invalid}
		if err := repo.RecordProtocolProbe(context.Background(), "tenant-a", "provider-a", "claude-model", capabilities, bad); err == nil {
			t.Fatalf("invalid endpoint accepted: %#v", invalid)
		}
	}
}

func TestMergeVerifiedProviderModels(t *testing.T) {
	db := verifiedModelsTestDB(t)
	repo := &verifiedModelSyncTestRepository{ModelRepository: NewModelRepository(db), db: db}
	ctx := context.Background()

	t.Run("merges verified models and never disables models outside the batch", func(t *testing.T) {
		resetVerifiedModelsData(t, db)
		seedVerifiedProvider(t, db, "tenant-a", "provider-azure")
		seedVerifiedProvider(t, db, "tenant-a", "provider-other")
		seedVerifiedProvider(t, db, "tenant-b", "provider-tenant-b")
		seedVerifiedModel(t, db, "existing-active", "provider-azure", "gpt-5.5", "old-deployment", "Old label", map[string]interface{}{"manual_route": "keep-me", "modality": "old"}, "active")
		seedVerifiedModel(t, db, "existing-disabled", "provider-azure", "gpt-5.4", "old-disabled", "Disabled label", map[string]interface{}{"manual_guard": true}, "disabled")
		for i := 0; i < 334; i++ {
			seedVerifiedModel(t, db, fmt.Sprintf("stale-%03d", i), "provider-azure", fmt.Sprintf("stale-%03d", i), "", "Stale", nil, "active")
		}
		seedVerifiedModel(t, db, "other-sentinel", "provider-other", "other-active", "other-upstream", "Other sentinel", map[string]interface{}{"keep": true}, "active")
		seedVerifiedModel(t, db, "tenant-b-sentinel", "provider-tenant-b", "tenant-b-active", "tenant-b-upstream", "Tenant B sentinel", map[string]interface{}{"keep": true}, "active")

		desired := verifiedDesiredModels()
		result, err := repo.MergeVerifiedProviderModels(ctx, "tenant-a", "provider-azure", verifiedCredentialID("provider-azure"), desired)
		if err != nil {
			t.Fatalf("MergeVerifiedProviderModels() error = %v", err)
		}
		wantResult := VerifiedModelSyncResult{Created: 2, Updated: 1, Reactivated: 1}
		if result != wantResult {
			t.Fatalf("result = %+v, want %+v", result, wantResult)
		}
		// 334 个不在本次提交里的已启用模型保持启用：提交是追加/更新，不是整组替换。
		assertProviderStatusCounts(t, db, "provider-azure", 338, 0)
		assertVerifiedModel(t, db, "provider-azure", "gpt-5.5", "azure-gpt-55", "GPT 5.5 verified", map[string]interface{}{"manual_route": "keep-me", "modality": "old"}, "active")
		assertVerifiedModel(t, db, "provider-azure", "gpt-5.4", "azure-gpt-54", "GPT 5.4 verified", map[string]interface{}{"manual_guard": true, "vision": true}, "active")
		assertVerifiedModel(t, db, "provider-azure", "gpt-5.3-codex", "azure-gpt-53-codex", "GPT 5.3 Codex verified", map[string]interface{}{"coding": true}, "active")
		assertVerifiedModel(t, db, "provider-azure", "gpt-5.6-sol", "azure-gpt-56-sol", "GPT 5.6 Sol verified", map[string]interface{}{"reasoning": "high"}, "active")
		assertVerifiedModel(t, db, "provider-other", "other-active", "other-upstream", "Other sentinel", map[string]interface{}{"keep": true}, "active")
		assertVerifiedModel(t, db, "provider-tenant-b", "tenant-b-active", "tenant-b-upstream", "Tenant B sentinel", map[string]interface{}{"keep": true}, "active")

		// Idempotent re-sync still counts every already-active desired row as Updated,
		// even when its persisted values are unchanged. It must not create duplicates.
		second, err := repo.MergeVerifiedProviderModels(ctx, "tenant-a", "provider-azure", verifiedCredentialID("provider-azure"), desired)
		if err != nil {
			t.Fatalf("second MergeVerifiedProviderModels() error = %v", err)
		}
		if want := (VerifiedModelSyncResult{Updated: 4}); second != want {
			t.Fatalf("second result = %+v, want %+v", second, want)
		}
		assertProviderStatusCounts(t, db, "provider-azure", 338, 0)
		var total, distinct int
		if err := db.QueryRow(ctx, `SELECT count(*), count(DISTINCT model_name) FROM models WHERE provider_id=$1`, "provider-azure").Scan(&total, &distinct); err != nil {
			t.Fatal(err)
		}
		if total != 338 || distinct != 338 {
			t.Fatalf("provider model rows total=%d distinct=%d, want 338/338", total, distinct)
		}
	})

	t.Run("database error rolls back every write", func(t *testing.T) {
		resetVerifiedModelsData(t, db)
		seedVerifiedProvider(t, db, "tenant-a", "provider-azure")
		seedVerifiedModel(t, db, "old-active", "provider-azure", "old-active", "old-upstream", "Old active", nil, "active")
		seedVerifiedModel(t, db, "old-disabled", "provider-azure", "old-disabled", "old-disabled-upstream", "Old disabled", nil, "disabled")
		_, err := repo.MergeVerifiedProviderModels(ctx, "tenant-a", "provider-azure", verifiedCredentialID("provider-azure"), []VerifiedProviderModel{
			{CatalogID: "a-good", DeploymentName: "good-upstream", ModelLabel: "Good", Capabilities: map[string]interface{}{"ok": true}},
			{CatalogID: "z-too-long", DeploymentName: strings.Repeat("x", 256), ModelLabel: "Too long"},
		})
		if err == nil {
			t.Fatal("expected VARCHAR(255) database error")
		}
		assertModelAbsent(t, db, "provider-azure", "a-good")
		assertVerifiedModel(t, db, "provider-azure", "old-active", "old-upstream", "Old active", map[string]interface{}{}, "active")
		assertVerifiedModel(t, db, "provider-azure", "old-disabled", "old-disabled-upstream", "Old disabled", map[string]interface{}{}, "disabled")
	})

	t.Run("rejects cross tenant provider with zero writes", func(t *testing.T) {
		resetVerifiedModelsData(t, db)
		seedVerifiedProvider(t, db, "tenant-b", "provider-tenant-b")
		seedVerifiedModel(t, db, "tenant-b-sentinel", "provider-tenant-b", "sentinel", "upstream", "Sentinel", nil, "active")
		_, err := repo.MergeVerifiedProviderModels(ctx, "tenant-a", "provider-tenant-b", verifiedCredentialID("provider-tenant-b"), []VerifiedProviderModel{{CatalogID: "gpt-5.5", DeploymentName: "azure-gpt-55", ModelLabel: "GPT 5.5"}})
		if err == nil {
			t.Fatal("expected tenant/provider ownership error")
		}
		requireVerifiedModelSyncConflict(t, err)
		assertVerifiedModel(t, db, "provider-tenant-b", "sentinel", "upstream", "Sentinel", map[string]interface{}{}, "active")
		assertModelAbsent(t, db, "provider-tenant-b", "gpt-5.5")
	})

	t.Run("rejects stale credential proof after rotation with zero writes", func(t *testing.T) {
		resetVerifiedModelsData(t, db)
		seedVerifiedProvider(t, db, "tenant-a", "provider-azure")
		seedVerifiedModel(t, db, "sentinel", "provider-azure", "sentinel", "old-upstream", "Sentinel", nil, "active")
		if _, err := db.Exec(ctx, `UPDATE provider_credentials SET status='rotated',rotated_at=NOW() WHERE id=$1`, verifiedCredentialID("provider-azure")); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO provider_credentials(id,provider_id,credential_name,secret_ciphertext,kms_key_ref,status,created_at) VALUES('cred-new','provider-azure','new','new-ciphertext','new-key','active',NOW()+INTERVAL '1 second')`); err != nil {
			t.Fatal(err)
		}
		_, err := repo.MergeVerifiedProviderModels(ctx, "tenant-a", "provider-azure", verifiedCredentialID("provider-azure"), []VerifiedProviderModel{{CatalogID: "gpt-5.5", DeploymentName: "new-upstream", ModelLabel: "New"}})
		if err == nil {
			t.Fatal("expected stale credential proof error")
		}
		requireVerifiedModelSyncConflict(t, err)
		assertVerifiedModel(t, db, "provider-azure", "sentinel", "old-upstream", "Sentinel", map[string]interface{}{}, "active")
		assertModelAbsent(t, db, "provider-azure", "gpt-5.5")
	})

	for _, tc := range []struct {
		name               string
		expectedCredential string
		providerType       string
		providerStatus     string
	}{
		{name: "empty expected credential", expectedCredential: "", providerType: "azure", providerStatus: "active"},
		{name: "wrong expected credential", expectedCredential: "cred-wrong", providerType: "azure", providerStatus: "active"},
		{name: "disabled provider", expectedCredential: verifiedCredentialID("provider-azure"), providerType: "azure", providerStatus: "disabled"},
		{name: "non azure provider", expectedCredential: verifiedCredentialID("provider-azure"), providerType: "openai", providerStatus: "active"},
	} {
		t.Run("rejects "+tc.name+" with zero writes", func(t *testing.T) {
			resetVerifiedModelsData(t, db)
			seedVerifiedProvider(t, db, "tenant-a", "provider-azure")
			seedVerifiedModel(t, db, "sentinel", "provider-azure", "sentinel", "old-upstream", "Sentinel", nil, "active")
			if _, err := db.Exec(ctx, `UPDATE providers SET provider_type=$2,status=$3 WHERE id=$1`, "provider-azure", tc.providerType, tc.providerStatus); err != nil {
				t.Fatal(err)
			}
			_, err := repo.MergeVerifiedProviderModels(ctx, "tenant-a", "provider-azure", tc.expectedCredential, []VerifiedProviderModel{{CatalogID: "gpt-5.5", DeploymentName: "new-upstream", ModelLabel: "New"}})
			if err == nil {
				t.Fatal("expected provider or credential validation error")
			}
			requireVerifiedModelSyncConflict(t, err)
			assertVerifiedModel(t, db, "provider-azure", "sentinel", "old-upstream", "Sentinel", map[string]interface{}{}, "active")
			assertModelAbsent(t, db, "provider-azure", "gpt-5.5")
		})
	}

	t.Run("selects newest active credential when multiple are active", func(t *testing.T) {
		resetVerifiedModelsData(t, db)
		seedVerifiedProvider(t, db, "tenant-a", "provider-azure")
		seedVerifiedModel(t, db, "sentinel", "provider-azure", "sentinel", "old-upstream", "Sentinel", nil, "active")
		if _, err := db.Exec(ctx, `INSERT INTO provider_credentials(id,provider_id,credential_name,secret_ciphertext,kms_key_ref,status,created_at) VALUES('cred-latest','provider-azure','latest','latest-ciphertext','latest-key','active',NOW()+INTERVAL '1 second')`); err != nil {
			t.Fatal(err)
		}
		_, err := repo.MergeVerifiedProviderModels(ctx, "tenant-a", "provider-azure", verifiedCredentialID("provider-azure"), []VerifiedProviderModel{{CatalogID: "gpt-5.5", DeploymentName: "new-upstream", ModelLabel: "New"}})
		if err == nil {
			t.Fatal("expected older active credential proof to be rejected")
		}
		requireVerifiedModelSyncConflict(t, err)
		assertVerifiedModel(t, db, "provider-azure", "sentinel", "old-upstream", "Sentinel", map[string]interface{}{}, "active")
		result, err := repo.MergeVerifiedProviderModels(ctx, "tenant-a", "provider-azure", "cred-latest", []VerifiedProviderModel{{CatalogID: "gpt-5.5", DeploymentName: "new-upstream", ModelLabel: "New"}})
		if err != nil {
			t.Fatal(err)
		}
		if want := (VerifiedModelSyncResult{Created: 1}); result != want {
			t.Fatalf("result=%+v want=%+v", result, want)
		}
	})

	t.Run("verifying models one by one keeps every earlier model enabled", func(t *testing.T) {
		resetVerifiedModelsData(t, db)
		seedVerifiedProvider(t, db, "tenant-a", "provider-azure")
		for i, item := range []VerifiedProviderModel{
			{CatalogID: "gpt-5.5", DeploymentName: "azure-gpt-55", ModelLabel: "gpt-5.5"},
			{CatalogID: "gpt-5.4", DeploymentName: "azure-gpt-54", ModelLabel: "gpt-5.4"},
			{CatalogID: "gpt-5.3-codex", DeploymentName: "azure-gpt-53-codex", ModelLabel: "gpt-5.3-codex"},
		} {
			result, err := repo.MergeVerifiedProviderModels(ctx, "tenant-a", "provider-azure", verifiedCredentialID("provider-azure"), []VerifiedProviderModel{item})
			if err != nil {
				t.Fatalf("round %d: %v", i, err)
			}
			if want := (VerifiedModelSyncResult{Created: 1}); result != want {
				t.Fatalf("round %d result=%+v want=%+v", i, result, want)
			}
			assertProviderStatusCounts(t, db, "provider-azure", i+1, 0)
		}
	})

	t.Run("manually disabled models outside the batch stay disabled", func(t *testing.T) {
		resetVerifiedModelsData(t, db)
		seedVerifiedProvider(t, db, "tenant-a", "provider-azure")
		seedVerifiedModel(t, db, "manual-off", "provider-azure", "manual-off", "manual-off-upstream", "Manual off", nil, "disabled")
		if _, err := repo.MergeVerifiedProviderModels(ctx, "tenant-a", "provider-azure", verifiedCredentialID("provider-azure"), []VerifiedProviderModel{{CatalogID: "gpt-5.5", DeploymentName: "azure-gpt-55", ModelLabel: "gpt-5.5"}}); err != nil {
			t.Fatal(err)
		}
		assertVerifiedModel(t, db, "provider-azure", "manual-off", "manual-off-upstream", "Manual off", map[string]interface{}{}, "disabled")
	})

	t.Run("canonicalizes identical desired duplicates", func(t *testing.T) {
		resetVerifiedModelsData(t, db)
		seedVerifiedProvider(t, db, "tenant-a", "provider-azure")
		item := VerifiedProviderModel{CatalogID: "gpt-5.5", DeploymentName: "azure-gpt-55", ModelLabel: "GPT 5.5", Capabilities: map[string]interface{}{"text": true}}
		result, err := repo.MergeVerifiedProviderModels(ctx, "tenant-a", "provider-azure", verifiedCredentialID("provider-azure"), []VerifiedProviderModel{item, item})
		if err != nil {
			t.Fatal(err)
		}
		if want := (VerifiedModelSyncResult{Created: 1}); result != want {
			t.Fatalf("result=%+v want=%+v", result, want)
		}
		assertProviderStatusCounts(t, db, "provider-azure", 1, 0)
	})

	for _, tc := range []struct {
		name   string
		second VerifiedProviderModel
	}{
		{name: "deployment conflict", second: VerifiedProviderModel{CatalogID: "gpt-5.5", DeploymentName: "different", ModelLabel: "GPT 5.5", Capabilities: map[string]interface{}{"text": true}}},
		{name: "label conflict", second: VerifiedProviderModel{CatalogID: "gpt-5.5", DeploymentName: "azure-gpt-55", ModelLabel: "Different", Capabilities: map[string]interface{}{"text": true}}},
		{name: "capabilities conflict", second: VerifiedProviderModel{CatalogID: "gpt-5.5", DeploymentName: "azure-gpt-55", ModelLabel: "GPT 5.5", Capabilities: map[string]interface{}{"text": false}}},
	} {
		t.Run("rejects "+tc.name+" with zero writes", func(t *testing.T) {
			resetVerifiedModelsData(t, db)
			seedVerifiedProvider(t, db, "tenant-a", "provider-azure")
			first := VerifiedProviderModel{CatalogID: "gpt-5.5", DeploymentName: "azure-gpt-55", ModelLabel: "GPT 5.5", Capabilities: map[string]interface{}{"text": true}}
			_, err := repo.MergeVerifiedProviderModels(ctx, "tenant-a", "provider-azure", verifiedCredentialID("provider-azure"), []VerifiedProviderModel{first, tc.second})
			if err == nil {
				t.Fatal("expected conflicting duplicate error")
			}
			requireVerifiedModelSyncConflict(t, err)
			assertModelAbsent(t, db, "provider-azure", "gpt-5.5")
		})
	}

	t.Run("rejects empty desired set", func(t *testing.T) {
		resetVerifiedModelsData(t, db)
		seedVerifiedProvider(t, db, "tenant-a", "provider-azure")
		seedVerifiedModel(t, db, "sentinel", "provider-azure", "sentinel", "upstream", "Sentinel", nil, "active")
		_, err := repo.MergeVerifiedProviderModels(ctx, "tenant-a", "provider-azure", verifiedCredentialID("provider-azure"), nil)
		if err == nil {
			t.Fatal("expected empty desired set error")
		}
		requireVerifiedModelSyncConflict(t, err)
		assertVerifiedModel(t, db, "provider-azure", "sentinel", "upstream", "Sentinel", map[string]interface{}{}, "active")
	})

	t.Run("duplicate existing rows fail closed and roll back", func(t *testing.T) {
		resetVerifiedModelsData(t, db)
		seedVerifiedProvider(t, db, "tenant-a", "provider-azure")
		seedVerifiedModel(t, db, "duplicate-1", "provider-azure", "gpt-5.5", "old-1", "Old 1", nil, "active")
		seedVerifiedModel(t, db, "duplicate-2", "provider-azure", "gpt-5.5", "old-2", "Old 2", nil, "disabled")
		_, err := repo.MergeVerifiedProviderModels(ctx, "tenant-a", "provider-azure", verifiedCredentialID("provider-azure"), []VerifiedProviderModel{{CatalogID: "gpt-5.5", DeploymentName: "new", ModelLabel: "New"}})
		if err == nil {
			t.Fatal("expected duplicate existing model error")
		}
		requireVerifiedModelSyncConflict(t, err)
		assertVerifiedModel(t, db, "provider-azure", "gpt-5.5", "old-1", "Old 1", map[string]interface{}{}, "active")
		var disabled int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM models WHERE provider_id=$1 AND model_name=$2 AND upstream_model_id=$3 AND status='disabled'`, "provider-azure", "gpt-5.5", "old-2").Scan(&disabled); err != nil {
			t.Fatal(err)
		}
		if disabled != 1 {
			t.Fatalf("disabled duplicate count=%d want=1", disabled)
		}
	})

	t.Run("duplicate stale rows fail closed and roll back", func(t *testing.T) {
		resetVerifiedModelsData(t, db)
		seedVerifiedProvider(t, db, "tenant-a", "provider-azure")
		seedVerifiedModel(t, db, "desired", "provider-azure", "gpt-5.5", "old-upstream", "Old desired", nil, "active")
		seedVerifiedModel(t, db, "stale-duplicate-1", "provider-azure", "stale-duplicate", "stale-1", "Stale 1", nil, "active")
		seedVerifiedModel(t, db, "stale-duplicate-2", "provider-azure", "stale-duplicate", "stale-2", "Stale 2", nil, "disabled")
		_, err := repo.MergeVerifiedProviderModels(ctx, "tenant-a", "provider-azure", verifiedCredentialID("provider-azure"), []VerifiedProviderModel{{CatalogID: "gpt-5.5", DeploymentName: "new-upstream", ModelLabel: "New desired"}})
		if err == nil {
			t.Fatal("expected duplicate stale model error")
		}
		requireVerifiedModelSyncConflict(t, err)
		assertVerifiedModel(t, db, "provider-azure", "gpt-5.5", "old-upstream", "Old desired", map[string]interface{}{}, "active")
		var active, disabled int
		if err := db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status='active'),count(*) FILTER (WHERE status='disabled') FROM models WHERE provider_id=$1 AND model_name=$2`, "provider-azure", "stale-duplicate").Scan(&active, &disabled); err != nil {
			t.Fatal(err)
		}
		if active != 1 || disabled != 1 {
			t.Fatalf("stale duplicate active/disabled=%d/%d want=1/1", active, disabled)
		}
	})

	t.Run("provider soft delete and verified replacement share a deadlock free lock order", func(t *testing.T) {
		resetVerifiedModelsData(t, db)
		seedVerifiedProvider(t, db, "tenant-a", "provider-azure")
		for i := 0; i < 200; i++ {
			seedVerifiedModel(t, db, fmt.Sprintf("delete-race-%03d", i), "provider-azure", fmt.Sprintf("delete-race-%03d", i), "", "Delete race", nil, "active")
		}
		if _, err := db.Exec(ctx, `
            CREATE OR REPLACE FUNCTION verified_models_pause_deactivate() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                PERFORM pg_advisory_xact_lock(987654321);
                RETURN NEW;
            END $$;
            CREATE TRIGGER verified_models_pause_deactivate
            BEFORE UPDATE OF status ON models
            FOR EACH ROW
            WHEN (NEW.status = 'inactive')
            EXECUTE FUNCTION verified_models_pause_deactivate()
        `); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = db.Exec(context.Background(), `DROP TRIGGER IF EXISTS verified_models_pause_deactivate ON models; DROP FUNCTION IF EXISTS verified_models_pause_deactivate()`)
		}()

		gateConn, err := db.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer gateConn.Release()
		gateTx, err := gateConn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		gateReleased := false
		defer func() {
			if !gateReleased {
				_ = gateTx.Rollback(context.Background())
			}
		}()
		if _, err := gateTx.Exec(ctx, `SELECT pg_advisory_xact_lock(987654321)`); err != nil {
			t.Fatal(err)
		}

		opCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		deleteDone := make(chan error, 1)
		replaceDone := make(chan error, 1)
		go func() {
			deleteDone <- NewProviderRepository(db).Delete(opCtx, "tenant-a", "provider-azure")
		}()

		waitForCondition(t, db, 5*time.Second, "provider delete to wait at advisory gate", `
            SELECT EXISTS(
                SELECT 1 FROM pg_locks
                WHERE locktype='advisory' AND NOT granted
            )
        `)

		go func() {
			_, replaceErr := repo.MergeVerifiedProviderModels(opCtx, "tenant-a", "provider-azure", verifiedCredentialID("provider-azure"), verifiedDesiredModels())
			replaceDone <- replaceErr
		}()
		waitForCondition(t, db, 5*time.Second, "replacement to wait on provider or model lock", `
            SELECT EXISTS(
                SELECT 1 FROM pg_stat_activity
                WHERE datname=current_database()
                  AND wait_event_type='Lock'
                  AND query ILIKE '%FOR UPDATE%'
                  AND query NOT ILIKE '%DELETE FROM models%'
            )
        `)

		if err := gateTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		gateReleased = true

		var deleteErr, replaceErr error
		select {
		case deleteErr = <-deleteDone:
		case <-time.After(12 * time.Second):
			t.Fatal("provider delete timed out")
		}
		select {
		case replaceErr = <-replaceDone:
		case <-time.After(12 * time.Second):
			t.Fatal("verified replacement timed out")
		}
		if deleteErr != nil {
			t.Fatalf("provider delete failed: %v", deleteErr)
		}
		if replaceErr == nil {
			t.Fatal("expected verified replacement to reject the deleted provider")
		}
		requireVerifiedModelSyncConflict(t, replaceErr)
		if strings.Contains(replaceErr.Error(), "40P01") || strings.Contains(strings.ToLower(replaceErr.Error()), "deadlock") || strings.Contains(strings.ToLower(replaceErr.Error()), "deadline") {
			t.Fatalf("verified replacement hit lock-order failure: %v", replaceErr)
		}
		var providerStatus, credentialStatus string
		var activeModels, inactiveModels int
		if err := db.QueryRow(ctx, `
            SELECT
                (SELECT status FROM providers WHERE id='provider-azure'),
                (SELECT status FROM provider_credentials WHERE provider_id='provider-azure' ORDER BY created_at DESC LIMIT 1),
                (SELECT count(*) FROM models WHERE provider_id='provider-azure' AND status='active'),
                (SELECT count(*) FROM models WHERE provider_id='provider-azure' AND status='inactive')
        `).Scan(&providerStatus, &credentialStatus, &activeModels, &inactiveModels); err != nil {
			t.Fatal(err)
		}
		if providerStatus != "deleted" || credentialStatus != "revoked" || activeModels != 0 || inactiveModels != 200 {
			t.Fatalf("provider/credential/active/inactive=%s/%s/%d/%d want=deleted/revoked/0/200", providerStatus, credentialStatus, activeModels, inactiveModels)
		}
	})

	t.Run("capabilities marshal error rolls back", func(t *testing.T) {
		resetVerifiedModelsData(t, db)
		seedVerifiedProvider(t, db, "tenant-a", "provider-azure")
		seedVerifiedModel(t, db, "sentinel", "provider-azure", "sentinel", "upstream", "Sentinel", nil, "active")
		_, err := repo.MergeVerifiedProviderModels(ctx, "tenant-a", "provider-azure", verifiedCredentialID("provider-azure"), []VerifiedProviderModel{
			{CatalogID: "a-good", DeploymentName: "good", ModelLabel: "Good"},
			{CatalogID: "z-bad", DeploymentName: "bad", ModelLabel: "Bad", Capabilities: map[string]interface{}{"unsupported": func() {}}},
		})
		if err == nil {
			t.Fatal("expected capabilities marshal error")
		}
		assertModelAbsent(t, db, "provider-azure", "a-good")
		assertVerifiedModel(t, db, "provider-azure", "sentinel", "upstream", "Sentinel", map[string]interface{}{}, "active")
	})
}

func requireVerifiedModelSyncConflict(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrVerifiedModelSyncConflict) {
		t.Fatalf("error=%v want ErrVerifiedModelSyncConflict", err)
	}
}

func TestCanonicalVerifiedProviderModelsConflictIsTyped(t *testing.T) {
	first := VerifiedProviderModel{CatalogID: "same", DeploymentName: "one"}
	second := VerifiedProviderModel{CatalogID: "same", DeploymentName: "two"}
	_, err := canonicalVerifiedProviderModels([]VerifiedProviderModel{first, second})
	if !errors.Is(err, ErrVerifiedModelSyncConflict) {
		t.Fatalf("error=%v want ErrVerifiedModelSyncConflict", err)
	}
}

func verifiedDesiredModels() []VerifiedProviderModel {
	return []VerifiedProviderModel{
		{CatalogID: "gpt-5.5", DeploymentName: "azure-gpt-55", ModelLabel: "GPT 5.5 verified", Capabilities: map[string]interface{}{"modality": "text"}},
		{CatalogID: "gpt-5.4", DeploymentName: "azure-gpt-54", ModelLabel: "GPT 5.4 verified", Capabilities: map[string]interface{}{"vision": true}},
		{CatalogID: "gpt-5.3-codex", DeploymentName: "azure-gpt-53-codex", ModelLabel: "GPT 5.3 Codex verified", Capabilities: map[string]interface{}{"coding": true}},
		{CatalogID: "gpt-5.6-sol", DeploymentName: "azure-gpt-56-sol", ModelLabel: "GPT 5.6 Sol verified", Capabilities: map[string]interface{}{"reasoning": "high"}},
	}
}

func verifiedModelsTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("real PostgreSQL required: docker binary unavailable: %v", err)
	}
	if out, err := exec.CommandContext(ctx, "docker", "info").CombinedOutput(); err != nil {
		t.Fatalf("real PostgreSQL required: docker daemon unavailable: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, "docker", "image", "inspect", "postgres:16-alpine").CombinedOutput(); err != nil {
		t.Fatalf("real PostgreSQL required: postgres:16-alpine image unavailable: %v: %s", err, strings.TrimSpace(string(out)))
	}

	name := fmt.Sprintf("jjdguard-verified-models-%d", time.Now().UnixNano())
	label := "jjdguard.verified-models.test-id=" + name
	run := func(timeout time.Duration, args ...string) (string, error) {
		t.Helper()
		cmdCtx, cmdCancel := context.WithTimeout(context.Background(), timeout)
		defer cmdCancel()
		out, err := exec.CommandContext(cmdCtx, "docker", args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	cleanup := func() error {
		out, err := run(10*time.Second, "ps", "-aq", "--filter", "label="+label)
		if err != nil {
			return fmt.Errorf("list labeled containers: %w: %s", err, out)
		}
		for _, id := range strings.Fields(out) {
			if removed, removeErr := run(10*time.Second, "rm", "-fv", id); removeErr != nil {
				return fmt.Errorf("remove labeled container %s: %w: %s", id, removeErr, removed)
			}
		}
		return nil
	}
	reapOrphanTestContainers(t)
	runArgs := append([]string{"run", "--pull=never", "--rm", "-d", "--name", name, "--label", label}, testcontainer.LabelArgs("verified-models")...)
	runArgs = append(runArgs, "-p", "127.0.0.1::5432", "-e", "POSTGRES_PASSWORD=test", "-e", "POSTGRES_DB=test", "postgres:16-alpine")
	out, err := run(20*time.Second, runArgs...)
	if err != nil {
		_ = cleanup()
		t.Fatalf("start temporary PostgreSQL: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Errorf("cleanup temporary PostgreSQL: %v", err)
		}
	})
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := run(2*time.Second, "exec", name, "pg_isready", "-U", "postgres", "-d", "test"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("temporary PostgreSQL readiness timeout")
		}
		time.Sleep(100 * time.Millisecond)
	}
	portOut, err := run(5*time.Second, "port", name, "5432/tcp")
	if err != nil {
		t.Fatalf("discover temporary PostgreSQL port: %v: %s", err, portOut)
	}
	parts := strings.Split(portOut, ":")
	port, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		t.Fatalf("parse temporary PostgreSQL port %q: %v", portOut, err)
	}
	db, err := pgxpool.New(context.Background(), fmt.Sprintf("postgres://postgres:test@127.0.0.1:%d/test?sslmode=disable", port))
	if err != nil {
		t.Fatalf("open temporary PostgreSQL pool: %v", err)
	}
	t.Cleanup(db.Close)
	pingDeadline := time.Now().Add(20 * time.Second)
	for {
		if pingErr := db.Ping(context.Background()); pingErr == nil {
			break
		} else if time.Now().After(pingDeadline) {
			t.Fatalf("published temporary PostgreSQL port did not become ready: %v", pingErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := db.Exec(context.Background(), `
CREATE TABLE tenants (id VARCHAR(64) PRIMARY KEY, name VARCHAR(255) NOT NULL, edition VARCHAR(32) NOT NULL DEFAULT 'cloud', status VARCHAR(32) NOT NULL DEFAULT 'active', config_json JSONB DEFAULT '{}', created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE providers (id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id), name VARCHAR(255) NOT NULL, provider_type VARCHAR(64) NOT NULL, base_url VARCHAR(512), auth_mode VARCHAR(64) DEFAULT 'api_key', is_default BOOLEAN DEFAULT FALSE, status VARCHAR(32) NOT NULL DEFAULT 'active', created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE provider_credentials (id VARCHAR(64) PRIMARY KEY, provider_id VARCHAR(64) NOT NULL REFERENCES providers(id), credential_name VARCHAR(255), secret_ciphertext TEXT, kms_key_ref VARCHAR(255), status VARCHAR(32) NOT NULL DEFAULT 'active', rotated_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE routing_policies (id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id), scope_type VARCHAR(32) NOT NULL, scope_ref VARCHAR(255), layer VARCHAR(32) NOT NULL, strategy VARCHAR(32) NOT NULL, config_json JSONB NOT NULL DEFAULT '{}', enabled BOOLEAN NOT NULL DEFAULT TRUE, schema_version INTEGER NOT NULL DEFAULT 1, config_version BIGINT NOT NULL DEFAULT 1);
CREATE TABLE models (id VARCHAR(64) PRIMARY KEY, provider_id VARCHAR(64) NOT NULL REFERENCES providers(id), model_name VARCHAR(255) NOT NULL, model_label VARCHAR(255), upstream_model_id VARCHAR(255), capabilities_json JSONB DEFAULT '{}', pricing_json JSONB DEFAULT '{}', context_window INTEGER, status VARCHAR(32) NOT NULL DEFAULT 'active', created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE request_logs (id VARCHAR(64) PRIMARY KEY, request_id VARCHAR(64) UNIQUE NOT NULL, tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id), provider_id VARCHAR(64) REFERENCES providers(id), model_id VARCHAR(64) REFERENCES models(id), endpoint_type VARCHAR(32), request_status VARCHAR(32), created_at TIMESTAMPTZ DEFAULT NOW(), agent_instance_id varchar(128));
`); err != nil {
		t.Fatalf("create temporary PostgreSQL schema: %v", err)
	}
	capabilityMigration, err := os.ReadFile("../../../../deploy/migrations/149_model_endpoint_capability_facts.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(context.Background(), string(capabilityMigration)); err != nil {
		t.Fatalf("apply capability fact migration: %v", err)
	}
	return db
}

func resetVerifiedModelsData(t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	if _, err := db.Exec(context.Background(), `TRUNCATE request_logs, routing_policies, model_endpoint_capability_overrides, model_endpoint_capability_facts, models, provider_credentials, providers, tenants`); err != nil {
		t.Fatal(err)
	}
}

func seedVerifiedProvider(t *testing.T, db *pgxpool.Pool, tenantID, providerID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1) ON CONFLICT DO NOTHING`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($1,$2,$1,'azure')`, providerID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO provider_credentials(id,provider_id,credential_name,secret_ciphertext,kms_key_ref,status,created_at) VALUES($1,$2,'test','test-ciphertext','test-key','active',NOW())`, verifiedCredentialID(providerID), providerID); err != nil {
		t.Fatal(err)
	}
}

func verifiedCredentialID(providerID string) string {
	return "cred-" + providerID
}

func seedVerifiedModel(t *testing.T, db *pgxpool.Pool, id, providerID, catalogID, deploymentName, label string, capabilities map[string]interface{}, status string) {
	t.Helper()
	if capabilities == nil {
		capabilities = map[string]interface{}{}
	}
	encoded, err := json.Marshal(capabilities)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(context.Background(), `INSERT INTO models(id,provider_id,model_name,model_label,upstream_model_id,capabilities_json,status) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`, id, providerID, catalogID, label, deploymentName, string(encoded), status); err != nil {
		t.Fatal(err)
	}
}

func waitForCondition(t *testing.T, db *pgxpool.Pool, timeout time.Duration, description, query string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var ready bool
		if err := db.QueryRow(context.Background(), query).Scan(&ready); err != nil {
			t.Fatal(err)
		}
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func assertProviderStatusCounts(t *testing.T, db *pgxpool.Pool, providerID string, wantActive, wantDisabled int) {
	t.Helper()
	var active, disabled int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE status='active'), count(*) FILTER (WHERE status='disabled') FROM models WHERE provider_id=$1`, providerID).Scan(&active, &disabled); err != nil {
		t.Fatal(err)
	}
	if active != wantActive || disabled != wantDisabled {
		t.Fatalf("provider %s active/disabled=%d/%d want=%d/%d", providerID, active, disabled, wantActive, wantDisabled)
	}
}

func assertVerifiedModel(t *testing.T, db *pgxpool.Pool, providerID, catalogID, wantDeployment, wantLabel string, wantCapabilities map[string]interface{}, wantStatus string) {
	t.Helper()
	var deployment, label, status string
	var capabilitiesJSON []byte
	if err := db.QueryRow(context.Background(), `SELECT COALESCE(upstream_model_id,''),COALESCE(model_label,''),capabilities_json,status FROM models WHERE provider_id=$1 AND model_name=$2 ORDER BY id LIMIT 1`, providerID, catalogID).Scan(&deployment, &label, &capabilitiesJSON, &status); err != nil {
		t.Fatalf("load model %s/%s: %v", providerID, catalogID, err)
	}
	var capabilities map[string]interface{}
	if err := json.Unmarshal(capabilitiesJSON, &capabilities); err != nil {
		t.Fatal(err)
	}
	if deployment != wantDeployment || label != wantLabel || status != wantStatus || !reflect.DeepEqual(capabilities, wantCapabilities) {
		t.Fatalf("model %s/%s deployment=%q label=%q capabilities=%v status=%q", providerID, catalogID, deployment, label, capabilities, status)
	}
}

func assertModelAbsent(t *testing.T, db *pgxpool.Pool, providerID, catalogID string) {
	t.Helper()
	var count int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM models WHERE provider_id=$1 AND model_name=$2`, providerID, catalogID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("model %s/%s unexpectedly has %d rows", providerID, catalogID, count)
	}
}
