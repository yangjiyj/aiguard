package permission

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 已 seed 过旧矩阵的库里 admin/tenant_owner/tenant_admin 仍有 billing_currency:write 行：
// 矩阵改动不会让旧行自行消失，SeedBuiltinRoles 必须幂等收回，且不动 platform_admin 与其他资源。
func TestSeedBuiltinRolesRevokesSupersededCurrencyGrants(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// 模拟旧版本种下的授权。
	for _, role := range []string{"admin", "tenant_owner", "tenant_admin"} {
		if _, err = db.Exec(ctx, `INSERT INTO system_permissions(id,name,code,role_name,resource,action,is_system) VALUES($1,$2,$2,$3,'billing_currency','write',TRUE) ON CONFLICT (code) DO NOTHING`, "legacy_cur_"+role, role+".billing_currency.write", role); err != nil {
			t.Fatal(err)
		}
	}
	// 非内置（is_system=false）的自定义授权不应被误删。
	if _, err = db.Exec(ctx, `INSERT INTO system_permissions(id,name,code,role_name,resource,action,is_system) VALUES('custom_cur_keep','custom.billing_currency.write','custom.billing_currency.write','custom_role','billing_currency','write',FALSE) ON CONFLICT (code) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM system_permissions WHERE id='custom_cur_keep'`)
	})
	for i := 0; i < 2; i++ { // 幂等：连跑两次
		if err = SeedBuiltinRoles(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	var others, platform, custom, settingsRead int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM system_permissions WHERE is_system AND resource='billing_currency' AND action='write' AND role_name<>'platform_admin'`).Scan(&others); err != nil || others != 0 {
		t.Fatalf("旧授权应被收回：%d %v", others, err)
	}
	if err = db.QueryRow(ctx, `SELECT count(*) FROM system_permissions WHERE is_system AND resource='billing_currency' AND action='write' AND role_name='platform_admin'`).Scan(&platform); err != nil || platform != 1 {
		t.Fatalf("platform_admin 授权应保留：%d %v", platform, err)
	}
	if err = db.QueryRow(ctx, `SELECT count(*) FROM system_permissions WHERE id='custom_cur_keep'`).Scan(&custom); err != nil || custom != 1 {
		t.Fatalf("非内置授权不应被误删：%d %v", custom, err)
	}
	if err = db.QueryRow(ctx, `SELECT count(*) FROM system_permissions WHERE is_system AND resource='billing_settings' AND action='read' AND role_name IN ('admin','tenant_owner','tenant_admin','platform_admin')`).Scan(&settingsRead); err != nil || settingsRead != 4 {
		t.Fatalf("设置读取授权应保持：%d %v", settingsRead, err)
	}
}
