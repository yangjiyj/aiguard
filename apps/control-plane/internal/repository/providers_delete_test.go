package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestProviderRepositoryDeletePreservesHistoricalRequestLogs(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	seedStatus(t, db, "tenant-delete", "provider-delete", "model-delete", "model-delete", "active", "active", "active")
	if _, err := db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,provider_id,model_id,request_status) VALUES('log-delete','request-delete','tenant-delete','provider-delete','model-delete','completed')`); err != nil {
		t.Fatal(err)
	}

	if err := NewProviderRepository(db).Delete(ctx, "tenant-delete", "provider-delete"); err != nil {
		t.Fatalf("delete provider with historical request logs: %v", err)
	}

	var providerStatus, modelStatus, credentialStatus string
	if err := db.QueryRow(ctx, `SELECT status FROM providers WHERE id='provider-delete'`).Scan(&providerStatus); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT status FROM models WHERE id='model-delete'`).Scan(&modelStatus); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT status FROM provider_credentials WHERE provider_id='provider-delete'`).Scan(&credentialStatus); err != nil {
		t.Fatal(err)
	}
	if providerStatus != "deleted" || modelStatus != "inactive" || credentialStatus != "revoked" {
		t.Fatalf("statuses provider=%q model=%q credential=%q", providerStatus, modelStatus, credentialStatus)
	}

	var providerID, modelID string
	if err := db.QueryRow(ctx, `SELECT provider_id,model_id FROM request_logs WHERE id='log-delete'`).Scan(&providerID, &modelID); err != nil {
		t.Fatal(err)
	}
	if providerID != "provider-delete" || modelID != "model-delete" {
		t.Fatalf("historical references changed: provider=%q model=%q", providerID, modelID)
	}
}

func TestProviderRepositoryDeleteIsTenantScoped(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	seedStatus(t, db, "tenant-owner", "provider-owned", "model-owned", "model-owned", "active", "active", "active")

	err := NewProviderRepository(db).Delete(ctx, "tenant-other", "provider-owned")
	if err == nil || err.Error() != "provider not found" {
		t.Fatalf("cross-tenant delete error = %v", err)
	}

	var status string
	if err := db.QueryRow(ctx, `SELECT status FROM providers WHERE id='provider-owned'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("cross-tenant delete changed provider status to %q", status)
	}
}

func TestProviderRepositoryDeleteConvergesDanglingDefaultPolicy(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	tenantID := "tenant-route-default"
	seedStatus(t, db, tenantID, "provider-route-only", "model-route-only", "logical/model", "active", "active", "active")
	if _, err := db.Exec(ctx, `INSERT INTO routing_policies(id,tenant_id,scope_type,scope_ref,layer,strategy,config_json,enabled,schema_version,config_version) VALUES('policy-default-fixed',$1,'tenant',$1,'provider','fixed',$2::jsonb,TRUE,2,1)`, tenantID,
		`{"strategy":"fixed","cost_basis":"none","fixed_provider_id":"provider-route-only","providers":[{"provider_id":"provider-route-only","enabled":true,"priority":1,"weight":0}]}`); err != nil {
		t.Fatal(err)
	}

	if err := NewProviderRepository(db).Delete(ctx, tenantID, "provider-route-only"); err != nil {
		t.Fatalf("delete should converge instead of rejecting: %v", err)
	}
	var policyCount int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM routing_policies WHERE id='policy-default-fixed'`).Scan(&policyCount); err != nil {
		t.Fatal(err)
	}
	if policyCount != 0 {
		t.Fatalf("dangling default policy survived delete: count=%d", policyCount)
	}
}

func TestProviderRepositoryDeletePrunesProviderAndKeepsRedundantOverride(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	tenantID := "tenant-route-prune"
	seedStatus(t, db, tenantID, "provider-prune-gone", "model-prune-gone", "logical/model", "active", "active", "active")
	seedStatus(t, db, tenantID, "provider-prune-keep-1", "model-prune-keep-1", "logical/model", "active", "active", "active")
	seedStatus(t, db, tenantID, "provider-prune-keep-2", "model-prune-keep-2", "logical/model", "active", "active", "active")
	config := `{"strategy":"priority","cost_basis":"none","providers":[` +
		`{"provider_id":"provider-prune-gone","enabled":true,"priority":5,"weight":0},` +
		`{"provider_id":"provider-prune-keep-1","enabled":true,"priority":9,"weight":60},` +
		`{"provider_id":"provider-prune-keep-2","enabled":false,"priority":12,"weight":40}]}`
	if _, err := db.Exec(ctx, `INSERT INTO routing_policies(id,tenant_id,scope_type,scope_ref,layer,strategy,config_json,enabled,schema_version,config_version) VALUES('policy-prune',$1,'model','logical/model','provider','priority',$2::jsonb,TRUE,2,4)`, tenantID, config); err != nil {
		t.Fatal(err)
	}

	if err := NewProviderRepository(db).Delete(ctx, tenantID, "provider-prune-gone"); err != nil {
		t.Fatalf("delete with redundant override: %v", err)
	}
	var configVersion int64
	var configJSON string
	if err := db.QueryRow(ctx, `SELECT config_version, config_json::text FROM routing_policies WHERE id='policy-prune'`).Scan(&configVersion, &configJSON); err != nil {
		t.Fatal(err)
	}
	if configVersion != 5 {
		t.Fatalf("config_version=%d want 5", configVersion)
	}
	if strings.Contains(configJSON, "provider-prune-gone") {
		t.Fatalf("deleted provider still referenced: %s", configJSON)
	}
	var decoded struct {
		Providers []struct {
			ProviderID string `json:"provider_id"`
			Enabled    bool   `json:"enabled"`
			Priority   int    `json:"priority"`
		} `json:"providers"`
	}
	if err := json.Unmarshal([]byte(configJSON), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Providers) != 2 || decoded.Providers[0].ProviderID != "provider-prune-keep-1" || !decoded.Providers[0].Enabled || decoded.Providers[0].Priority != 1 || decoded.Providers[1].ProviderID != "provider-prune-keep-2" || decoded.Providers[1].Priority != 2 {
		t.Fatalf("pruned providers/priorities wrong: %s", configJSON)
	}
}

func TestProviderRepositoryDeleteRemovesOverrideThatLosesRedundancy(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	tenantID := "tenant-route-collapse"
	seedStatus(t, db, tenantID, "provider-collapse-gone", "model-collapse-gone", "logical/model", "active", "active", "active")
	seedStatus(t, db, tenantID, "provider-collapse-keep", "model-collapse-keep", "logical/model", "active", "active", "active")
	config := `{"strategy":"priority","cost_basis":"none","providers":[` +
		`{"provider_id":"provider-collapse-gone","enabled":true,"priority":1,"weight":0},` +
		`{"provider_id":"provider-collapse-keep","enabled":true,"priority":2,"weight":0}]}`
	if _, err := db.Exec(ctx, `INSERT INTO routing_policies(id,tenant_id,scope_type,scope_ref,layer,strategy,config_json,enabled,schema_version,config_version) VALUES('policy-collapse',$1,'model','logical/model','provider','priority',$2::jsonb,TRUE,2,1)`, tenantID, config); err != nil {
		t.Fatal(err)
	}

	if err := NewProviderRepository(db).Delete(ctx, tenantID, "provider-collapse-gone"); err != nil {
		t.Fatalf("delete should collapse override without error: %v", err)
	}
	var policyCount int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM routing_policies WHERE id='policy-collapse'`).Scan(&policyCount); err != nil {
		t.Fatal(err)
	}
	if policyCount != 0 {
		t.Fatalf("override without redundancy survived: count=%d", policyCount)
	}
}

func TestProviderRepositoryDeleteFallsBackFixedDefaultToPriority(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	tenantID := "tenant-route-fallback"
	seedStatus(t, db, tenantID, "provider-fallback-gone", "model-fallback-gone", "logical/model", "active", "active", "active")
	seedStatus(t, db, tenantID, "provider-fallback-keep", "model-fallback-keep", "logical/model", "active", "active", "active")
	config := `{"strategy":"fixed","cost_basis":"none","fixed_provider_id":"provider-fallback-gone","providers":[` +
		`{"provider_id":"provider-fallback-gone","enabled":true,"priority":1,"weight":0},` +
		`{"provider_id":"provider-fallback-keep","enabled":true,"priority":2,"weight":0}]}`
	if _, err := db.Exec(ctx, `INSERT INTO routing_policies(id,tenant_id,scope_type,scope_ref,layer,strategy,config_json,enabled,schema_version,config_version) VALUES('policy-fallback',$1,'tenant',$1,'provider','fixed',$2::jsonb,TRUE,2,1)`, tenantID, config); err != nil {
		t.Fatal(err)
	}

	if err := NewProviderRepository(db).Delete(ctx, tenantID, "provider-fallback-gone"); err != nil {
		t.Fatalf("delete with fixed default: %v", err)
	}
	var strategy, configJSON string
	if err := db.QueryRow(ctx, `SELECT strategy, config_json::text FROM routing_policies WHERE id='policy-fallback'`).Scan(&strategy, &configJSON); err != nil {
		t.Fatal(err)
	}
	if strategy != "priority" || strings.Contains(configJSON, "fixed_provider_id") || strings.Contains(configJSON, "provider-fallback-gone") {
		t.Fatalf("fixed default not converged: strategy=%s config=%s", strategy, configJSON)
	}
}

func TestProviderRepositoryDisableConvergesEnabledV2References(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	tenantID := "tenant-route-disable"
	seedStatus(t, db, tenantID, "provider-disable-target", "model-disable-target", "logical/model", "active", "active", "active")
	seedStatus(t, db, tenantID, "provider-disable-keep", "model-disable-keep", "logical/model", "active", "active", "active")
	config := `{"strategy":"priority","cost_basis":"none","providers":[` +
		`{"provider_id":"provider-disable-target","enabled":true,"priority":1,"weight":0},` +
		`{"provider_id":"provider-disable-keep","enabled":true,"priority":2,"weight":0}]}`
	if _, err := db.Exec(ctx, `INSERT INTO routing_policies(id,tenant_id,scope_type,scope_ref,layer,strategy,config_json,enabled,schema_version,config_version) VALUES('policy-disable',$1,'model','logical/model','provider','priority',$2::jsonb,TRUE,2,1)`, tenantID, config); err != nil {
		t.Fatal(err)
	}

	provider := &Provider{ID: "provider-disable-target", TenantID: tenantID, Name: "目标上游", ProviderType: "openai", BaseURL: "https://example.invalid", AuthMode: "bearer", Status: "disabled"}
	if err := NewProviderRepository(db).UpdateWithCredential(ctx, provider, nil); err != nil {
		t.Fatalf("disable provider: %v", err)
	}
	var policyCount int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM routing_policies WHERE id='policy-disable'`).Scan(&policyCount); err != nil {
		t.Fatal(err)
	}
	if policyCount != 0 {
		t.Fatalf("override should collapse to direct routing after disable: count=%d", policyCount)
	}
	var status string
	if err := db.QueryRow(ctx, `SELECT status FROM providers WHERE id='provider-disable-target'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "disabled" {
		t.Fatalf("provider status=%q", status)
	}
}

func TestProviderRepositoryActiveUpdateKeepsRoutingPolicies(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	tenantID := "tenant-route-rename"
	seedStatus(t, db, tenantID, "provider-rename", "model-rename", "logical/model", "active", "active", "active")
	config := `{"strategy":"priority","cost_basis":"none","providers":[{"provider_id":"provider-rename","enabled":true,"priority":1,"weight":0}]}`
	if _, err := db.Exec(ctx, `INSERT INTO routing_policies(id,tenant_id,scope_type,scope_ref,layer,strategy,config_json,enabled,schema_version,config_version) VALUES('policy-rename',$1,'model','logical/model','provider','priority',$2::jsonb,TRUE,2,1)`, tenantID, config); err != nil {
		t.Fatal(err)
	}

	provider := &Provider{ID: "provider-rename", TenantID: tenantID, Name: "改名后的上游", ProviderType: "openai", BaseURL: "https://example.invalid", AuthMode: "bearer", Status: "active"}
	if err := NewProviderRepository(db).UpdateWithCredential(ctx, provider, nil); err != nil {
		t.Fatalf("rename provider: %v", err)
	}
	var policyCount int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM routing_policies WHERE id='policy-rename'`).Scan(&policyCount); err != nil {
		t.Fatal(err)
	}
	if policyCount != 1 {
		t.Fatalf("active update must not touch routing policies: count=%d", policyCount)
	}
}

func TestProviderRepositoryDeleteIgnoresDisabledAndOtherTenantPolicies(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	seedStatus(t, db, "tenant-delete-allowed", "provider-delete-allowed", "model-delete-allowed", "logical/model", "active", "active", "active")
	seedStatus(t, db, "tenant-delete-other", "provider-delete-other", "model-delete-other", "other/model", "active", "active", "active")
	config := `{"strategy":"priority","cost_basis":"none","providers":[{"provider_id":"provider-delete-allowed","enabled":true,"priority":1,"weight":0}]}`
	for _, row := range []struct {
		id, tenant string
		enabled    bool
	}{
		{"disabled-same-tenant", "tenant-delete-allowed", false},
		{"enabled-other-tenant", "tenant-delete-other", true},
	} {
		if _, err := db.Exec(ctx, `INSERT INTO routing_policies(id,tenant_id,scope_type,scope_ref,layer,strategy,config_json,enabled,schema_version,config_version) VALUES($1,$2,'model','logical/model','provider','priority',$3::jsonb,$4,2,1)`, row.id, row.tenant, config, row.enabled); err != nil {
			t.Fatal(err)
		}
	}
	if err := NewProviderRepository(db).Delete(ctx, "tenant-delete-allowed", "provider-delete-allowed"); err != nil {
		t.Fatalf("unrelated policies blocked delete: %v", err)
	}
}

func TestProviderRepositoryRestoreIsExplicitTenantScopedAndKeepsModelsInactive(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	seedStatus(t, db, "tenant-restore", "provider-restore", "model-restore", "logical/model", "active", "active", "active")
	if _, err := db.Exec(ctx, `UPDATE provider_credentials SET secret_ciphertext='historical-ciphertext' WHERE provider_id='provider-restore'`); err != nil {
		t.Fatal(err)
	}
	repo := NewProviderRepository(db)
	if err := repo.Delete(ctx, "tenant-restore", "provider-restore"); err != nil {
		t.Fatal(err)
	}
	deleted, err := repo.ListDeleted(ctx, "tenant-restore")
	if err != nil || len(deleted) != 1 || deleted[0].ID != "provider-restore" || !deleted[0].HasCredential || deleted[0].BaseURL != "" {
		t.Fatalf("safe deleted provider listing = %#v err=%v", deleted, err)
	}
	if _, err := repo.Restore(ctx, "tenant-other", "provider-restore"); err == nil {
		t.Fatal("cross-tenant restore unexpectedly succeeded")
	}
	restored, err := repo.Restore(ctx, "tenant-restore", "provider-restore")
	if err != nil || restored == nil || restored.Status != "active" || !restored.HasCredential || restored.BaseURL != "" {
		t.Fatalf("restored provider = %#v err=%v", restored, err)
	}
	var providerStatus, modelStatus, credentialStatus string
	if err := db.QueryRow(ctx, `SELECT p.status,m.status,c.status FROM providers p JOIN models m ON m.provider_id=p.id JOIN provider_credentials c ON c.provider_id=p.id WHERE p.id='provider-restore'`).Scan(&providerStatus, &modelStatus, &credentialStatus); err != nil {
		t.Fatal(err)
	}
	if providerStatus != "active" || modelStatus != "inactive" || credentialStatus != "active" {
		t.Fatalf("restore statuses provider=%s model=%s credential=%s", providerStatus, modelStatus, credentialStatus)
	}
}

func TestModelRoutingCandidateValidationRequiresCompleteOutboundRoute(t *testing.T) {
	tests := []struct {
		name                                                           string
		providerStatus, modelStatus, credentialStatus, capabilityState string
		otherTenant                                                    bool
		wantOK                                                         bool
	}{
		{"eligible", "active", "active", "active", "supported", false, true},
		{"provider disabled", "disabled", "active", "active", "supported", false, false},
		{"credential revoked", "active", "active", "revoked", "supported", false, false},
		{"model inactive", "active", "inactive", "active", "supported", false, false},
		{"protocol unsupported", "active", "active", "active", "unsupported", false, false},
		{"other tenant", "active", "active", "active", "supported", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := statusTestDB(t)
			ctx := context.Background()
			tenantID := "tenant-candidate"
			providerTenant := tenantID
			if tc.otherTenant {
				providerTenant = "tenant-candidate-other"
			}
			seedStatus(t, db, providerTenant, "provider-candidate", "model-candidate", "logical/model", tc.providerStatus, tc.modelStatus, tc.credentialStatus)
			if _, err := db.Exec(ctx, `UPDATE provider_credentials SET secret_ciphertext='test-ciphertext' WHERE provider_id='provider-candidate'`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, `UPDATE model_endpoint_capability_overrides SET state=$1 WHERE model_id='model-candidate' AND endpoint_type='chat'`, tc.capabilityState); err != nil {
				t.Fatal(err)
			}
			err := NewModelRoutingRepository(db).ValidateProviderCandidates(ctx, tenantID, "logical/model", "chat", []string{"provider-candidate"})
			if tc.wantOK && err != nil {
				t.Fatalf("eligible candidate rejected: %v", err)
			}
			if !tc.wantOK && !errors.Is(err, ErrModelRouteUnavailable) {
				t.Fatalf("ineligible candidate error=%v", err)
			}
		})
	}
}
