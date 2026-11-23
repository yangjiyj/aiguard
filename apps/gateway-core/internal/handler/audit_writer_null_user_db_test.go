package handler

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// chat-portal (G1) 回归守护：portal 发放的无归属 key 走数据面时 envelope.UserID 为空串。
// request_logs.user_id / security_events.user_id 都带外键 REFERENCES users(id)，
// 空串是非 NULL 值会撞 23503——留痕/安全事件整链静默丢失（审计产品不可接受）。
// 写侧必须 NULLIF 落 NULL（同 mcp_proxy_audit.go 的既有姿势）。
// DB 驱动测试，需 CONTENT_LOGS_TEST_DATABASE_URL，否则 t.Skip。
func setupAuditWriterNullUserFixture(t *testing.T) (*pgxpool.Pool, context.Context, string, string, string, string) {
	t.Helper()
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set; skipping DB-backed audit writer test")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}

	ns := fmt.Sprintf("awnu_%d", time.Now().UnixNano())
	tenantID := "tenant_" + ns
	projectID := "proj_" + ns
	providerID := "prov_" + ns
	modelID := "model_" + ns

	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, is_test) VALUES ($1, $2, TRUE)`, tenantID, ns); err != nil {
		db.Close()
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`, projectID, tenantID, ns); err != nil {
		db.Close()
		t.Fatalf("seed project: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO providers (id, tenant_id, name, provider_type, status) VALUES ($1, $2, $3, 'openai', 'active')`, providerID, tenantID, ns); err != nil {
		db.Close()
		t.Fatalf("seed provider: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO models (id, provider_id, model_name, model_label, status) VALUES ($1, $2, 'test-model', 'Test Model', 'active')`, modelID, providerID); err != nil {
		db.Close()
		t.Fatalf("seed model: %v", err)
	}

	t.Cleanup(func() {
		c := context.Background()
		db.Exec(c, `DELETE FROM security_events WHERE tenant_id = $1`, tenantID)
		db.Exec(c, `DELETE FROM content_logs WHERE tenant_id = $1`, tenantID)
		db.Exec(c, `DELETE FROM request_logs WHERE tenant_id = $1`, tenantID)
		db.Exec(c, `DELETE FROM models WHERE id = $1`, modelID)
		db.Exec(c, `DELETE FROM providers WHERE id = $1`, providerID)
		db.Exec(c, `DELETE FROM projects WHERE id = $1`, projectID)
		db.Exec(c, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})
	return db, ctx, tenantID, projectID, providerID, modelID
}

func TestAuditWriterHandlesEmptyUserID(t *testing.T) {
	db, ctx, tenantID, projectID, providerID, modelID := setupAuditWriterNullUserFixture(t)

	w := &RealAuditWriter{db: &realDBExecutor{pool: db}}
	envelope := &modelrouter.RequestEnvelope{
		RequestID:    "req_awnu_" + tenantID,
		TenantID:     tenantID,
		ProjectID:    projectID,
		UserID:       "", // 无归属 key：数据面 envelope.UserID 为空串
		ClientID:     "key_awnu",
		ProviderID:   providerID,
		ModelID:      modelID,
		EndpointType: "chat",
	}

	// 1. EnsureRequestLog：留痕行必须落下，user_id 落 NULL 而非空串
	w.EnsureRequestLog(ctx, envelope)
	var userIDIsNull bool
	if err := db.QueryRow(ctx, `SELECT user_id IS NULL FROM request_logs WHERE request_id = $1`, envelope.RequestID).Scan(&userIDIsNull); err != nil {
		t.Fatalf("EnsureRequestLog left no request_logs row (empty user_id must not break audit trail): %v", err)
	}
	if !userIDIsNull {
		t.Fatal("request_logs.user_id should be NULL for ownerless key")
	}

	// 2. FinalizeRequestLog（upsert 路径）：同一请求终态化不得因空 user_id 失败
	w.FinalizeRequestLog(ctx, envelope, nil, "success", 200, 5, nil)
	var status string
	if err := db.QueryRow(ctx, `SELECT request_status, user_id IS NULL FROM request_logs WHERE request_id = $1`, envelope.RequestID).Scan(&status, &userIDIsNull); err != nil {
		t.Fatalf("query finalized request log: %v", err)
	}
	if status != "success" || !userIDIsNull {
		t.Fatalf("finalized row = (status %q, user_id NULL %v), want (success, true)", status, userIDIsNull)
	}

	// 3. WriteSecurityEvent：安全事件行必须落下（user_id 外键同款问题）
	w.WriteSecurityEvent(ctx, envelope, nil, "audit", "test summary")
	if err := db.QueryRow(ctx, `SELECT user_id IS NULL FROM security_events WHERE request_id = $1`, envelope.RequestID).Scan(&userIDIsNull); err != nil {
		t.Fatalf("WriteSecurityEvent left no security_events row: %v", err)
	}
	if !userIDIsNull {
		t.Fatal("security_events.user_id should be NULL for ownerless key")
	}

	// 4. WriteContentLog：内容留证 CTE 里也内联 request_logs 插入，同样不得挂
	w.WriteContentLog(ctx, envelope, "user", "测试内容", 3)
	var contentCount int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM content_logs WHERE tenant_id = $1`, tenantID).Scan(&contentCount); err != nil {
		t.Fatalf("query content_logs: %v", err)
	}
	if contentCount != 1 {
		t.Fatalf("content_logs count = %d, want 1", contentCount)
	}
}
