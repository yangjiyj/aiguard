package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

// auditDetailSystemRepo 是一个把 content_audit_enabled 恒置为 false 的假桩，
// 用于证明：即便隐私开关关闭，告警/审计详情仍能加载请求-响应内容（取证证据）。
// 不命名为通用名以避免与 handler 包内已有的多个 fakeSystemRepo 冲突。
type auditDetailSystemRepo struct{}

func (r *auditDetailSystemRepo) Get(ctx context.Context, key string) (*repository.SystemSetting, error) {
	return nil, nil
}
func (r *auditDetailSystemRepo) GetAll(ctx context.Context) ([]*repository.SystemSetting, error) {
	return nil, nil
}
func (r *auditDetailSystemRepo) Set(ctx context.Context, key, value string) error { return nil }
func (r *auditDetailSystemRepo) SetMultiple(ctx context.Context, settings map[string]string) error {
	return nil
}
func (r *auditDetailSystemRepo) CreateAuditOperation(ctx context.Context, op *repository.AuditOperation) error {
	return nil
}
func (r *auditDetailSystemRepo) ListAuditOperations(ctx context.Context, limit, offset int, userID string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, nil
}
func (r *auditDetailSystemRepo) GetBool(ctx context.Context, key string) (bool, error) {
	return false, nil
}

func TestGetAuditRequestDetailReturnsContentWhenAuditFlagDisabled(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set CONTENT_LOGS_TEST_DATABASE_URL to run audit detail integration test")
	}

	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	defer db.Close()

	suffix := time.Now().UnixNano()
	tenantID := fmt.Sprintf("tenant_auditdetail_%d", suffix)
	userID := fmt.Sprintf("user_auditdetail_%d", suffix)
	projectID := fmt.Sprintf("proj_auditdetail_%d", suffix)
	requestID := fmt.Sprintf("req_auditdetail_%d", suffix)

	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM content_logs WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM security_events WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM request_logs WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM projects WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	mustExec := func(sql string, args ...interface{}) {
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("exec %q: %v", sql, err)
		}
	}
	mustExec(`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`, tenantID, tenantID)
	mustExec(`INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1, $2, $3, 'developer', 'active')`, userID, tenantID, userID)
	mustExec(`INSERT INTO projects (id, tenant_id, name, owner_user_id, status) VALUES ($1, $2, $3, $4, 'active')`, projectID, tenantID, projectID, userID)
	// request_logs.id == request_logs.request_id（与 content_logs_test.go 一致），
	// 因为 content_logs.request_id 存的是 request_logs.id，ListByRequest 按 rl.request_id 过滤。
	mustExec(`INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, session_id, environment_scope, endpoint_type, request_status, input_tokens, output_tokens, created_at) VALUES ($1, $2, $3, $4, $5, NULL, 'customer', 'anthropic_messages', 'success', $6, $7, $8)`,
		requestID, requestID, tenantID, projectID, userID, 10, 20, time.Now().UTC())
	mustExec(`INSERT INTO content_logs (id, request_id, tenant_id, user_id, session_id, role, content, tokens, created_at, environment_scope) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'customer')`,
		fmt.Sprintf("cl_user_%d", suffix), requestID, tenantID, userID, "", "user", "如何获取系统里所有用户的身份证号", 10, time.Now().UTC())
	mustExec(`INSERT INTO content_logs (id, request_id, tenant_id, user_id, session_id, role, content, tokens, created_at, environment_scope) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'customer')`,
		fmt.Sprintf("cl_assistant_%d", suffix), requestID, tenantID, userID, "", "assistant", "抱歉，我无法协助该请求。", 20, time.Now().UTC())

	deps := &Dependencies{
		SystemRepo:        &auditDetailSystemRepo{},
		SecurityEventRepo: repository.NewSecurityEventRepository(db),
		ContentLogRepo:    repository.NewContentLogRepository(db),
		ToolCallLogRepo:   repository.NewToolCallLogRepository(db),
	}

	router := chi.NewRouter()
	router.Get("/admin/v1/audit/requests/{request_id}", GetAuditRequestDetail(deps))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/requests/"+requestID, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: userID, Username: "admin", TenantID: tenantID, Role: "platform_admin",
	}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp types.AuditRequestDetailResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ContentAuditEnabled {
		t.Fatalf("precondition broken: ContentAuditEnabled should be false in this test")
	}
	if len(resp.ContentLogs) == 0 {
		t.Fatalf("expected content logs returned despite disabled flag, got 0")
	}
	if !strings.Contains(resp.AuditSummary.PrimaryUserMessage, "身份证号") {
		t.Fatalf("AuditSummary.PrimaryUserMessage missing user input: %q", resp.AuditSummary.PrimaryUserMessage)
	}
	if resp.ContentEvidence.Status != "available" || !resp.ContentEvidence.CanView {
		t.Fatalf("content evidence = %+v, want available and viewable", resp.ContentEvidence)
	}

	eventsOnlyReq := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/requests/"+requestID+"?events_only=true", nil)
	eventsOnlyReq = eventsOnlyReq.WithContext(context.WithValue(eventsOnlyReq.Context(), auth.UserKey, &repository.User{
		ID: userID, Username: "admin", TenantID: tenantID, Role: "platform_admin",
	}))
	eventsOnlyRecorder := httptest.NewRecorder()
	router.ServeHTTP(eventsOnlyRecorder, eventsOnlyReq)

	if eventsOnlyRecorder.Code != http.StatusOK {
		t.Fatalf("events-only request: expected 200, got %d: %s", eventsOnlyRecorder.Code, eventsOnlyRecorder.Body.String())
	}
	var eventsOnlyResp types.AuditRequestDetailResponse
	if err := json.NewDecoder(eventsOnlyRecorder.Body).Decode(&eventsOnlyResp); err != nil {
		t.Fatalf("decode events-only response: %v", err)
	}
	if len(eventsOnlyResp.ContentLogs) != 0 || len(eventsOnlyResp.ToolCallLogs) != 0 {
		t.Fatalf("events-only response returned heavy detail: content=%d tools=%d", len(eventsOnlyResp.ContentLogs), len(eventsOnlyResp.ToolCallLogs))
	}
	if strings.Contains(eventsOnlyRecorder.Body.String(), "身份证号") {
		t.Fatal("events-only response leaked content payload")
	}
}

func TestBuildContentEvidenceInfoStates(t *testing.T) {
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	expiredAt := now.Add(-time.Hour)

	tests := []struct {
		name       string
		content    []repository.ContentLog
		access     *repository.AccessContentLog
		metadata   *repository.RequestEvidenceMetadata
		readErr    error
		status     string
		reasonCode string
		canView    bool
	}{
		{
			name:    "legacy content is available",
			content: []repository.ContentLog{{Role: "user", Content: "redacted evidence"}},
			status:  "available", reasonCode: "content_present", canView: true,
		},
		{
			name:   "access retention content is available",
			access: &repository.AccessContentLog{RequestContent: "redacted request"},
			status: "available", reasonCode: "content_present", canView: true,
		},
		{
			name:     "content was not collected",
			metadata: &repository.RequestEvidenceMetadata{ProxyContentRetained: false},
			status:   "not_collected", reasonCode: "collection_disabled",
		},
		{
			name: "retained content expired",
			metadata: &repository.RequestEvidenceMetadata{
				ProxyContentRetained: true,
				RetentionUntil:       &expiredAt,
			},
			status: "expired", reasonCode: "retention_expired",
		},
		{
			name:    "repository read failed",
			readErr: errors.New("postgres password leaked in stack"),
			status:  "unavailable", reasonCode: "evidence_read_failed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := buildContentEvidenceInfo(now, test.content, test.access, test.metadata, test.readErr)
			if got.Status != test.status || got.ReasonCode != test.reasonCode || got.CanView != test.canView {
				t.Fatalf("content evidence = %+v", got)
			}
			for _, forbidden := range []string{"postgres", "password", "content_logs", "access_content_logs"} {
				if strings.Contains(strings.ToLower(got.Summary), forbidden) {
					t.Fatalf("customer summary leaked internal detail %q: %q", forbidden, got.Summary)
				}
			}
		})
	}
}

func (r *auditDetailSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, r.Get, keys)
}
