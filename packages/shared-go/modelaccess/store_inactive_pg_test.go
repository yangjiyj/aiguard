package modelaccess

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 客户现场回归：部门为「默认开放全部模型」时，已删除供应商下的停用模型
// 不能出现在部门授权清单里（现场 116 个模型里 109 个停用，门户全部列出）。
func TestReadAccessAllActiveDepartmentExcludesInactiveModels(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("需要隔离 PostgreSQL（CONTENT_LOGS_TEST_DATABASE_URL）")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "ma_inactive_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	// 只复制列定义（不带外键/检查约束），测试只关心授权清单的口径。
	for _, table := range []string{"users", "teams", "providers", "models", "team_models", "user_model_policies", "user_model_extra_grants"} {
		if _, err := admin.Exec(ctx, "CREATE TABLE "+schema+"."+table+" (LIKE public."+table+" INCLUDING DEFAULTS)"); err != nil {
			t.Fatal(err)
		}
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
	defer db.Close()

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	const tenant = "tenant_t"
	exec(`INSERT INTO teams (id,tenant_id,name,path,model_access_mode,model_access_configured) VALUES ('team_chat',$1,'Chat 默认部门','/team_chat','all_active',true)`, tenant)
	exec(`INSERT INTO users (id,tenant_id,username,email,role,status,department_id,department_assignment_mode) VALUES ('user_a',$1,'a@example.com','a@example.com','user','active','team_chat','automatic')`, tenant)
	exec(`INSERT INTO providers (id,tenant_id,name,provider_type,base_url,status) VALUES ('prov_live',$1,'fasthub','anthropic','https://upstream.invalid','active'),('prov_gone',$1,'旧供应商','openai','https://old.invalid','deleted')`, tenant)
	exec(`INSERT INTO models (id,provider_id,model_name,status) VALUES
		('m1','prov_live','anthropic/claude-sonnet-5-5','active'),
		('m2','prov_live','anthropic/claude-opus-4-8','active'),
		('m3','prov_live','anthropic/claude-retired','inactive'),
		('m4','prov_gone','gpt-5.5','inactive'),
		('m5','prov_gone','upgrade-probe-x','active')`)

	access, err := ReadAccess(ctx, db, tenant, "user_a")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"anthropic/claude-opus-4-8", "anthropic/claude-sonnet-5-5"}
	if strings.Join(access.DepartmentModels, ",") != strings.Join(want, ",") {
		t.Fatalf("部门授权清单=%v，应只有有效供应商下的有效模型 %v", access.DepartmentModels, want)
	}
	if strings.Join(access.EffectiveModels, ",") != strings.Join(want, ",") {
		t.Fatalf("有效模型=%v，应为 %v", access.EffectiveModels, want)
	}
	for _, name := range []string{"gpt-5.5", "upgrade-probe-x", "anthropic/claude-retired"} {
		if access.Allows(name) {
			t.Fatalf("停用模型 %s 不应被授权", name)
		}
	}
}
