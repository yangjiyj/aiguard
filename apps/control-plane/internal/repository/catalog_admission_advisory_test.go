package repository

import (
	"context"
	"errors"
	"testing"
)

// 管理员启用待准入模型不要求探测通过；只有上游已下架才拒绝。
func TestAdministratorCanEnablePendingModelWithoutProbeProof(t *testing.T) {
	db, tenant, _, _, _, _ := employeeKeyFixture(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	provider := tenant + "_admission"
	exec(`INSERT INTO providers(id,tenant_id,name,provider_type,base_url,auth_mode,status) VALUES($1,$2,'admission','custom','https://fixture.invalid','api_key','active')`, provider, tenant)
	exec(`INSERT INTO models(id,provider_id,model_name,status) VALUES($1,$2,'never-probed','pending'),($3,$2,'delisted','pending')`, provider+"_pending", provider, provider+"_removed")
	exec(`INSERT INTO model_catalog_entries(provider_id,upstream_model_id,model_id,display_name,description,present,restore_status,first_seen_at,last_seen_at,removed_at) VALUES($1,'delisted',$2,'delisted','',false,'none',now(),now(),now())`, provider, provider+"_removed")
	t.Cleanup(func() {
		db.Exec(ctx, `DELETE FROM model_catalog_entries WHERE provider_id=$1`, provider)
		db.Exec(ctx, `DELETE FROM models WHERE provider_id=$1`, provider)
		db.Exec(ctx, `DELETE FROM providers WHERE id=$1`, provider)
	})
	repo := NewModelRepository(db)
	if err := repo.UpdateCatalogModelStatus(ctx, tenant, provider+"_pending", "active"); err != nil {
		t.Fatalf("pending model without probe proof must be enableable: %v", err)
	}
	if err := repo.UpdateCatalogModelStatus(ctx, tenant, provider+"_removed", "active"); !errors.Is(err, ErrCatalogModelUnavailable) {
		t.Fatalf("delisted model must stay blocked: %v", err)
	}
}
