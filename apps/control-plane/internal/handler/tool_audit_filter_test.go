package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestParseToolCallFilterDefaultsToTwentyFourHoursAndSkipTotal(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/tools/high-risk?skip_total=true&limit=25", nil)

	filter, err := parseToolCallFilter(req, "tenant-1")
	if err != nil {
		t.Fatalf("parse filter: %v", err)
	}
	if !filter.SkipTotal {
		t.Fatal("expected skip_total=true to be parsed")
	}
	if filter.Limit != 25 || filter.RiskLevel != "high+" {
		t.Fatalf("unexpected filter defaults: %#v", filter)
	}
	window := filter.EndDate.Sub(filter.StartDate)
	if window < 23*time.Hour || window > 25*time.Hour {
		t.Fatalf("default window = %s, want about 24h", window)
	}
}

func TestParseToolCallFilterHonorsExplicitWindow(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/tools/high-risk?from=2026-06-20T01:00:00Z&to=2026-06-20T02:30:00Z", nil)

	filter, err := parseToolCallFilter(req, "tenant-1")
	if err != nil {
		t.Fatalf("parse filter: %v", err)
	}
	if filter.StartDate.Format(time.RFC3339) != "2026-06-20T01:00:00Z" || filter.EndDate.Format(time.RFC3339) != "2026-06-20T02:30:00Z" {
		t.Fatalf("unexpected explicit window: %#v", filter)
	}
}
func TestParseToolCallFilterHonorsAgentTypeAndAllRisk(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/tools/high-risk?agent_type=workbuddy&risk_level=all", nil)

	filter, err := parseToolCallFilter(req, "tenant-1")
	if err != nil {
		t.Fatalf("parse filter: %v", err)
	}
	if filter.AgentType != "workbuddy" {
		t.Fatalf("agent_type = %q, want workbuddy", filter.AgentType)
	}
	if filter.RiskLevel != "" {
		t.Fatalf("risk_level = %q, want empty all-risk scope", filter.RiskLevel)
	}
}

func TestParseToolCallFilterHonorsTenantScopedRequestID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/tools/high-risk?request_id=req-mcp-123&risk_level=all", nil)

	filter, err := parseToolCallFilter(req, "tenant-1")
	if err != nil {
		t.Fatalf("parse filter: %v", err)
	}
	if filter.TenantID != "tenant-1" || filter.RequestID != "req-mcp-123" {
		t.Fatalf("request filter lost tenant/request binding: %#v", filter)
	}
}

func TestParseToolCallFilterCapsPageAndForwardsDecisionDispositionAndServerFilters(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/tools/high-risk?limit=500&raw_decision=confirm&effective_decision=audit&server=filesystem&disposition_status=accepted&keyword=%E5%BC%82%E5%B8%B8", nil)

	filter, err := parseToolCallFilter(req, "tenant-1")
	if err != nil {
		t.Fatalf("parse filter: %v", err)
	}
	if filter.Limit != 100 {
		t.Fatalf("limit = %d, want hard cap 100", filter.Limit)
	}
	if filter.RawDecision != "confirm" || filter.EffectiveDecision != "audit" || filter.Server != "filesystem" || filter.DispositionStatus != "accepted" {
		t.Fatalf("linked filters were not forwarded: %#v", filter)
	}
	if filter.Keyword != "异常" {
		t.Fatalf("keyword = %q, want two-rune Chinese query", filter.Keyword)
	}
}

func TestListHighRiskToolCallsReturnsStoredLogsWhenAuditFlagDisabled(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	defer db.Close()

	suffix := time.Now().UnixNano()
	tenantID := fmt.Sprintf("tenant_toolaudit_disabled_%d", suffix)
	userID := fmt.Sprintf("user_toolaudit_disabled_%d", suffix)
	requestID := fmt.Sprintf("req_toolaudit_disabled_%d", suffix)
	logID := fmt.Sprintf("tc_toolaudit_disabled_%d", suffix)
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM tool_call_logs WHERE tenant_id = $1`, tenantID)
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
	mustExec(`
		INSERT INTO tool_call_logs (
			id, request_id, session_id, tenant_id, user_id, tool_name, tool_type, risk_level,
			parameters, result, status, matched_policy_id, matched_policy_name, mode, created_at
		) VALUES ($1, $2, 'sess-disabled', $3, $4, 'bash.exec', 'system', 'critical', '{}'::jsonb, '', 'blocked',
			'pol_block', '阻断策略', 'block', NOW())
	`, logID, requestID, tenantID, userID)

	deps := &Dependencies{
		SystemRepo:      &auditDetailSystemRepo{},
		ToolCallLogRepo: repository.NewToolCallLogRepository(db),
	}
	router := chi.NewRouter()
	router.Get("/admin/v1/audit/tools/high-risk", ListHighRiskToolCalls(deps))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/tools/high-risk?risk_level=all&limit=20&from=2026-01-01T00:00:00.000Z&to=2999-01-01T00:00:00.000Z", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.SessionKey, &repository.Session{
		UserID: userID, Username: userID, TenantID: tenantID, Role: "platform_admin",
	}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Data  []repository.ToolCallLog `json:"data"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Total != 1 || len(body.Data) != 1 || body.Data[0].ID != logID {
		t.Fatalf("expected one stored blocked log, total=%d data=%+v", body.Total, body.Data)
	}
}
