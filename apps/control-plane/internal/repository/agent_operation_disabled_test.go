package repository

// Low-1：GetPolicy 的 SQL 带 enabled=true，被停用的策略被读成「未配置」（N2 之后会被当成默认值展示）。
// 要能区分三种状态：
//   - 已配置且启用：返回策略，Disabled=false；
//   - 已停用：返回被停用的那条策略，Enabled=false（页面显示「已停用」，不显示默认值）；
//   - 未配置：ErrAgentOperationNotFound。
// 同一范围同时存在停用行与启用行时（停用后重新保存会新建一行），以启用行为准。
// 需要真实 Postgres（CONTENT_LOGS_TEST_DATABASE_URL，未设置时跳过）。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setupOperationPolicyDB(t *testing.T) (*AgentOperationRepository, *pgxpool.Pool, string) {
	t.Helper()
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	tenantID := fmt.Sprintf("tenant_opol_%d", time.Now().UnixNano())
	if _, err := db.Exec(context.Background(), `INSERT INTO tenants (id, name, edition, status) VALUES ($1,$1,'enterprise','active')`, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec(context.Background(), `DELETE FROM agent_destructive_policies WHERE tenant_id=$1`, tenantID)
		db.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenantID)
	})
	return NewAgentOperationRepository(db), db, tenantID
}

func insertPolicyRow(t *testing.T, db *pgxpool.Pool, tenantID, id, mode, action string, enabled bool) {
	t.Helper()
	if _, err := db.Exec(context.Background(), `
		INSERT INTO agent_destructive_policies (id, tenant_id, scope_type, scope_ref, mode, action, version, enabled)
		VALUES ($1,$2,'tenant','',$3,$4,3,$5)`, id, tenantID, mode, action, enabled); err != nil {
		t.Fatal(err)
	}
}

func TestGetPolicyDistinguishesDisabledFromNotConfigured(t *testing.T) {
	repo, db, tenantID := setupOperationPolicyDB(t)
	ctx := context.Background()

	// 未配置
	if _, err := repo.GetPolicy(ctx, tenantID, "tenant", ""); !errors.Is(err, ErrAgentOperationNotFound) {
		t.Fatalf("没有任何行应是未配置：%v", err)
	}

	// 已停用：返回被停用的那条，Disabled=true，而不是「未配置」。
	insertPolicyRow(t, db, tenantID, "adp_disabled_"+tenantID[len(tenantID)-8:], "strict", "block", false)
	p, err := repo.GetPolicy(ctx, tenantID, "tenant", "")
	if err != nil {
		t.Fatalf("已停用的策略不应被读成未配置：%v", err)
	}
	if !p.Disabled || p.Mode != "strict" || p.Action != "block" || p.Version != 3 {
		t.Fatalf("应原样返回被停用的策略且 Disabled=true：%+v", p)
	}
}

func TestGetPolicyPrefersTheEnabledRowWhenBothExist(t *testing.T) {
	repo, db, tenantID := setupOperationPolicyDB(t)
	insertPolicyRow(t, db, tenantID, "adp_old_"+tenantID[len(tenantID)-8:], "strict", "block", false)
	insertPolicyRow(t, db, tenantID, "adp_new_"+tenantID[len(tenantID)-8:], "light", "alert_allow", true)
	p, err := repo.GetPolicy(context.Background(), tenantID, "tenant", "")
	if err != nil || p.Disabled || p.Mode != "light" {
		t.Fatalf("同一范围既有停用行又有启用行时以启用行为准：%+v err=%v", p, err)
	}
}

func TestGetPolicyEnabledRowIsReportedAsEnabled(t *testing.T) {
	repo, db, tenantID := setupOperationPolicyDB(t)
	insertPolicyRow(t, db, tenantID, "adp_on_"+tenantID[len(tenantID)-8:], "audit", "record", true)
	p, err := repo.GetPolicy(context.Background(), tenantID, "tenant", "")
	if err != nil || p.Disabled {
		t.Fatalf("启用的策略 Disabled=false：%+v err=%v", p, err)
	}
}
