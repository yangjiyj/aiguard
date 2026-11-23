package repository

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

type verifiedModelSyncTestRepository struct {
	*ModelRepository
	db *pgxpool.Pool
}

func (r *verifiedModelSyncTestRepository) MergeVerifiedProviderModels(
	ctx context.Context,
	tenantID, providerID, expectedCredentialID string,
	desired []VerifiedProviderModel,
) (VerifiedModelSyncResult, error) {
	expectedConfig, _, err := verifiedModelSyncDBExpectations(ctx, r.db, providerID)
	if err != nil {
		return VerifiedModelSyncResult{}, err
	}
	return r.ModelRepository.MergeVerifiedProviderModels(ctx, tenantID, providerID, expectedCredentialID, expectedConfig, desired)
}

func TestMergeVerifiedProviderModelsRejectsStaleProviderConfigSnapshot(t *testing.T) {
	db := verifiedModelsTestDB(t)
	repo := NewModelRepository(db)
	ctx := context.Background()

	for _, tc := range []struct {
		name  string
		query string
	}{
		{name: "base URL changed", query: `UPDATE providers SET base_url='https://changed.example.test' WHERE id='provider-azure'`},
		{name: "auth mode changed", query: `UPDATE providers SET auth_mode='bearer' WHERE id='provider-azure'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetVerifiedModelsData(t, db)
			seedVerifiedProvider(t, db, "tenant-a", "provider-azure")
			seedVerifiedModel(t, db, "sentinel", "provider-azure", "sentinel", "old-upstream", "Sentinel", nil, "active")
			expectedConfig, _, err := verifiedModelSyncDBExpectations(ctx, db, "provider-azure")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, tc.query); err != nil {
				t.Fatal(err)
			}

			_, err = repo.MergeVerifiedProviderModels(
				ctx, "tenant-a", "provider-azure", verifiedCredentialID("provider-azure"),
				expectedConfig,
				[]VerifiedProviderModel{{CatalogID: "gpt-5.5", DeploymentName: "new-upstream", ModelLabel: "New"}},
			)
			if err == nil {
				t.Fatal("expected stale provider config conflict")
			}
			requireVerifiedModelSyncConflict(t, err)
			assertVerifiedModel(t, db, "provider-azure", "sentinel", "old-upstream", "Sentinel", map[string]interface{}{}, "active")
			assertModelAbsent(t, db, "provider-azure", "gpt-5.5")
		})
	}
}

// 验证期间别人新启用了模型，提交仍然成功且不会把那个模型停掉。
func TestMergeVerifiedProviderModelsKeepsModelsEnabledConcurrently(t *testing.T) {
	db := verifiedModelsTestDB(t)
	repo := NewModelRepository(db)
	ctx := context.Background()
	resetVerifiedModelsData(t, db)
	seedVerifiedProvider(t, db, "tenant-a", "provider-azure")
	seedVerifiedModel(t, db, "sentinel", "provider-azure", "sentinel", "old-upstream", "Sentinel", nil, "active")
	expectedConfig, _, err := verifiedModelSyncDBExpectations(ctx, db, "provider-azure")
	if err != nil {
		t.Fatal(err)
	}

	seedVerifiedModel(t, db, "concurrent", "provider-azure", "concurrent", "concurrent-upstream", "Concurrent", nil, "active")
	result, err := repo.MergeVerifiedProviderModels(
		ctx, "tenant-a", "provider-azure", verifiedCredentialID("provider-azure"),
		expectedConfig,
		[]VerifiedProviderModel{{CatalogID: "gpt-5.5", DeploymentName: "new-upstream", ModelLabel: "New"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if want := (VerifiedModelSyncResult{Created: 1}); result != want {
		t.Fatalf("result=%+v want=%+v", result, want)
	}
	assertVerifiedModel(t, db, "provider-azure", "sentinel", "old-upstream", "Sentinel", map[string]interface{}{}, "active")
	assertVerifiedModel(t, db, "provider-azure", "concurrent", "concurrent-upstream", "Concurrent", map[string]interface{}{}, "active")
	assertVerifiedModel(t, db, "provider-azure", "gpt-5.5", "new-upstream", "New", map[string]interface{}{}, "active")
}

func verifiedModelSyncDBExpectations(ctx context.Context, db *pgxpool.Pool, providerID string) (string, string, error) {
	var providerType, baseURL, authMode string
	if err := db.QueryRow(ctx, `
SELECT provider_type, COALESCE(base_url, ''), COALESCE(auth_mode, '')
FROM providers
WHERE id=$1
`, providerID).Scan(&providerType, &baseURL, &authMode); err != nil {
		return "", "", fmt.Errorf("load provider expectation: %w", err)
	}
	rows, err := db.Query(ctx, `
SELECT id, model_name, COALESCE(upstream_model_id, ''), status
FROM models
WHERE provider_id=$1
`, providerID)
	if err != nil {
		return "", "", fmt.Errorf("load model expectations: %w", err)
	}
	defer rows.Close()
	models := make([]*Model, 0)
	for rows.Next() {
		model := &Model{ProviderID: providerID}
		if err := rows.Scan(&model.ID, &model.ModelName, &model.UpstreamModelID, &model.Status); err != nil {
			return "", "", fmt.Errorf("scan model expectation: %w", err)
		}
		models = append(models, model)
	}
	if err := rows.Err(); err != nil {
		return "", "", fmt.Errorf("iterate model expectations: %w", err)
	}
	return VerifiedModelSyncProviderConfigDigest(providerType, baseURL, authMode), VerifiedModelSyncActiveSetDigest(models, providerID), nil
}
