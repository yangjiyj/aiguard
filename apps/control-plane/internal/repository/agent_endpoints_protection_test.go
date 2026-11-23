package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 批次 2B：端侧策略包重建读租户的 endpoint.rule.* 防护项（只读这一组，别的租户、别的项不读）。
func TestEndpointProtectionSettingsReadsOnlyEndpointRulesOfTheTenant(t *testing.T) {
	dsn := os.Getenv("AGENT_OPERATION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AGENT_OPERATION_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("endpoint_protection_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	if _, err := db.Exec(ctx, `
		CREATE TABLE protection_settings (tenant_id text NOT NULL, item_key text NOT NULL, action text NOT NULL,
			params_json jsonb NOT NULL DEFAULT '{}'::jsonb, PRIMARY KEY (tenant_id, item_key));
		INSERT INTO protection_settings VALUES
			('tenant-a','endpoint.rule.builtin_env_files','block','{}'),
			('tenant-a','agent.ssh_private_key','block','{}'),
			('tenant-b','endpoint.rule.builtin_destructive_rm','confirm','{}');
	`); err != nil {
		t.Fatal(err)
	}
	settings, err := endpointProtectionSettings(ctx, db, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(settings) != 1 || settings.ActionFor("endpoint.rule.builtin_env_files") != protection.ActionBlock {
		t.Fatalf("settings=%+v", settings)
	}
	if settings.ActionFor("endpoint.rule.builtin_destructive_rm") != protection.ActionAlertAllow {
		t.Fatalf("another tenant's setting leaked: %+v", settings)
	}
}
