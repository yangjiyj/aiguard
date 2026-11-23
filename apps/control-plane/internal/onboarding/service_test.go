package onboarding

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestInitializeNilServiceIsNoOp(t *testing.T) {
	var service *Service
	if err := service.Initialize(context.Background(), "tenant", "actor"); err != nil {
		t.Fatalf("nil service Initialize() error = %v", err)
	}
}

func TestStableSuffixIsDeterministicAndBounded(t *testing.T) {
	first := stableSuffix("tenant-a")
	if len(first) != 20 || first != stableSuffix("tenant-a") || first == stableSuffix("tenant-b") {
		t.Fatalf("unexpected suffixes: %q %q", first, stableSuffix("tenant-b"))
	}
}

func TestInitializeFreshInstallIsIdempotentAndUpgradeIsNoOp(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID, actorID := "init_t_"+suffix, "init_u_"+suffix
	upgradeTenant, upgradeActor := "upgrade_t_"+suffix, "upgrade_u_"+suffix

	for _, fixture := range [][2]string{{tenantID, actorID}, {upgradeTenant, upgradeActor}} {
		// is_test=TRUE：Cleanup 未跑完(进程被中断)时残留的 fixture 不会出现在
		// 「组织管理 > 单位列表」里(List 查询 WHERE is_test = FALSE)。
		// 这类残留还带 platform_admin 用户，会被 unit_not_empty(409) 挡住无法手动删除。
		if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',TRUE)`, fixture[0]); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `
			INSERT INTO users(id,tenant_id,username,password_hash,role,status,department_assignment_mode,department_assignment_source)
			VALUES($1,$2,$1,'x','platform_admin','active','emergency','local')
		`, fixture[1], fixture[0]); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, fixture := range [][2]string{{tenantID, actorID}, {upgradeTenant, upgradeActor}} {
			_, _ = db.Exec(context.Background(), `DELETE FROM billing_tariff_rules WHERE tenant_id=$1`, fixture[0])
			_, _ = db.Exec(context.Background(), `DELETE FROM billing_tariff_plans WHERE tenant_id=$1`, fixture[0])
			_, _ = db.Exec(context.Background(), `DELETE FROM tenant_identity_defaults WHERE tenant_id=$1`, fixture[0])
			_, _ = db.Exec(context.Background(), `DELETE FROM deployment_initializations WHERE tenant_id=$1`, fixture[0])
			_, _ = db.Exec(context.Background(), `DELETE FROM audit_operations WHERE tenant_id=$1`, fixture[0])
			_, _ = db.Exec(context.Background(), `DELETE FROM model_policies WHERE tenant_id=$1`, fixture[0])
			_, _ = db.Exec(context.Background(), `DELETE FROM projects WHERE tenant_id=$1`, fixture[0])
			_, _ = db.Exec(context.Background(), `DELETE FROM users WHERE tenant_id=$1`, fixture[0])
			_, _ = db.Exec(context.Background(), `DELETE FROM teams WHERE tenant_id=$1`, fixture[0])
			_, _ = db.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, fixture[0])
		}
	})
	if _, err := db.Exec(ctx, `
		INSERT INTO deployment_initializations(tenant_id,initialization_key,status,fresh_install)
		VALUES($1,$2,'pending',TRUE)
	`, tenantID, InitializationKey); err != nil {
		t.Fatal(err)
	}

	service := NewService(db)
	if err := service.Initialize(ctx, upgradeTenant, upgradeActor); err != nil {
		t.Fatalf("upgrade no-op: %v", err)
	}
	if err := service.Initialize(ctx, tenantID, actorID); err != nil {
		t.Fatalf("first initialize: %v", err)
	}
	if err := service.Initialize(ctx, tenantID, actorID); err != nil {
		t.Fatalf("idempotent initialize: %v", err)
	}

	status, err := service.GetStatus(ctx, tenantID)
	if err != nil || status == nil || status.State != "completed" || status.AttemptCount != 1 {
		t.Fatalf("status = %+v, err=%v", status, err)
	}
	var teamMode, projectID, defaultDepartmentID string
	var fallbackSourceTypes []string
	if err := db.QueryRow(ctx, `SELECT model_access_mode FROM teams WHERE tenant_id=$1 AND system_key='chat_default'`, tenantID).Scan(&teamMode); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT id FROM projects WHERE tenant_id=$1 AND system_key='chat_default'`, tenantID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT default_department_id,fallback_source_types FROM tenant_identity_defaults WHERE tenant_id=$1`, tenantID).Scan(&defaultDepartmentID, &fallbackSourceTypes); err != nil {
		t.Fatal(err)
	}
	if teamMode != "all_active" || projectID == "" || defaultDepartmentID == "" {
		t.Fatalf("initialized mode=%q project=%q department=%q", teamMode, projectID, defaultDepartmentID)
	}
	wantFallbacks := map[string]bool{"oidc": true, "ldap": true, "ad": true}
	for _, sourceType := range fallbackSourceTypes {
		delete(wantFallbacks, sourceType)
	}
	if len(wantFallbacks) != 0 {
		t.Fatalf("Chat identity fallback missing source types: got=%v missing=%v", fallbackSourceTypes, wantFallbacks)
	}
}
