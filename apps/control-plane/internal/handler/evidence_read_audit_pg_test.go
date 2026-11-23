package handler

// Low-2 的会话类出口（GetSessionContent / ExportSessionContent）依赖具体的 ContentLogRepository，需要真实 Postgres。
// 空会话也会以 200 返回，足以验证「读取成功才留痕」「导出出口没有漏包审计」。
// CONTENT_LOGS_TEST_DATABASE_URL 未设置时跳过。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type auditEnabledSystemRepo struct{ capturingSystemRepo }

func (r *auditEnabledSystemRepo) GetBool(_ context.Context, key string) (bool, error) {
	return key == "content_audit_enabled", nil
}

func TestSessionContentExitsWriteTheReadAuditOnPostgres(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	cases := []struct {
		name, route, path, kind string
		build                   func(*Dependencies) http.HandlerFunc
	}{
		{"session content", "/admin/v1/audit/content/{session_id}", "/admin/v1/audit/content/sess_pg_1", "session_content", GetSessionContent},
		{"session export", "/admin/v1/audit/content/{session_id}/export", "/admin/v1/audit/content/sess_pg_1/export", "session_export", ExportSessionContent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sys := &auditEnabledSystemRepo{}
			deps := &Dependencies{
				SystemRepo:        sys,
				ContentLogRepo:    repository.NewContentLogRepository(pool),
				SecurityEventRepo: repository.NewSecurityEventRepository(pool),
			}
			router := chi.NewRouter()
			router.Get(tc.route, tc.build(deps))
			rec := httptest.NewRecorder()
			req := evidenceUserCtx(httptest.NewRequest(http.MethodGet, tc.path+"?from=2026-01-01T00:00:00Z&to=2026-12-31T00:00:00Z", nil), "security_officer")
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("读取应成功：%d %s", rec.Code, rec.Body.String())
			}
			if len(sys.auditOps) != 1 {
				t.Fatalf("一次读取应恰好一条审计，实际 %d", len(sys.auditOps))
			}
			d := sys.auditOps[0].ActionDetail
			if d["kind"] != tc.kind || d["evidence_id"] != "sess_pg_1" || d["role"] != "security_officer" || d["tenant_id"] != "tenant_a" {
				t.Fatalf("审计详情不对：%v", d)
			}
		})
	}
}

func (r *auditEnabledSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, r.Get, keys)
}
