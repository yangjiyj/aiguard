package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type blockTraceAlertReader struct {
	filter repository.AlertOccurrenceFilter
	called bool
	err    error
}

// 2.9.22 起命中原文给有内容证据权限的角色（用户 11-17 定）：桩照真实投影，只在 IncludeRaw 时带原文，
// 用来同时验证“有权限才取原文”和“无权限时接口层再清一遍”。
func (reader *blockTraceAlertReader) List(_ context.Context, filter repository.AlertOccurrenceFilter) (*repository.AlertOccurrencePage, error) {
	reader.filter, reader.called = filter, true
	if reader.err != nil {
		return nil, reader.err
	}
	item := repository.AlertOccurrence{
		ID: "finding-one", EventID: "evt-one", RequestID: "request-one", ProjectID: "project-one",
		RuleID: "rule-one", RuleName: "密码明文检测", Severity: "high", RedactedEvidence: "pass****996",
		AgentEndpointEvidence: &repository.AgentEndpointEvidence{LocalDecision: map[string]any{"body": "RAW_LOCAL_DECISION"}},
	}
	if filter.IncludeRaw {
		item.RawEvidence, item.MatchedTextPreview, item.EvidenceContext = "RAW_ALERT_SECRET", "RAW_PREVIEW_SECRET", "RAW_CONTEXT_SECRET"
	}
	return &repository.AlertOccurrencePage{Items: []repository.AlertOccurrence{item}, Total: 1}, nil
}

func blockTraceTestDependencies(t *testing.T) (*Dependencies, *pgxpool.Pool, *blockTraceAlertReader) {
	t.Helper()
	dsn := os.Getenv("SECURITY_BLOCK_RECORDS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SECURITY_BLOCK_RECORDS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := pgx.Identifier{fmt.Sprintf("block_trace_handler_%d", time.Now().UnixNano())}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = strings.Trim(schema, `"`)
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close(); _, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); admin.Close() })
	for _, stmt := range []string{
		`CREATE TABLE projects(id TEXT PRIMARY KEY,name TEXT)`,
		`CREATE TABLE users(id TEXT PRIMARY KEY,username TEXT)`,
		`CREATE TABLE rules(id TEXT PRIMARY KEY,name TEXT,rule_type TEXT,rule_set_id TEXT,scope_json JSONB DEFAULT '{}')`,
		`CREATE TABLE rule_sets(id TEXT PRIMARY KEY,tenant_id TEXT,source_type TEXT,published BOOLEAN DEFAULT TRUE)`,
		`CREATE TABLE models(id TEXT PRIMARY KEY,model_name TEXT)`,
		`CREATE TABLE request_logs(id TEXT,request_id TEXT,tenant_id TEXT,project_id TEXT,model_id TEXT,agent_type TEXT,
		 endpoint_type TEXT,source_ip TEXT,request_status TEXT,upstream_status_code INT,trace_id TEXT,
		 created_at TIMESTAMPTZ DEFAULT now(),session_id TEXT,input_tokens INT,output_tokens INT,
		 latency_ms INT,proxy_content_retained BOOL,content_evidence_retention_until TIMESTAMPTZ)`,
		`CREATE TABLE security_events(id TEXT,tenant_id TEXT,request_id TEXT,project_id TEXT,user_id TEXT,event_type TEXT,severity TEXT,
		 rule_id TEXT,action_taken TEXT,matched_summary JSONB,created_at TIMESTAMPTZ DEFAULT now(),evidence_ref TEXT,agent_instance_id TEXT)`,
		`CREATE TABLE content_logs(id TEXT,tenant_id TEXT,request_id TEXT,role TEXT,content TEXT,tokens INT,created_at TIMESTAMPTZ DEFAULT now(),environment_scope TEXT DEFAULT 'customer')`,
		`CREATE TABLE access_content_logs(id TEXT,tenant_id TEXT,request_id TEXT,created_at TIMESTAMPTZ DEFAULT now(),request_content_redacted TEXT,
		 response_content_redacted TEXT,conversation_id TEXT,file_metadata_json JSONB,environment_scope TEXT DEFAULT 'customer')`,
		`CREATE TABLE tool_call_logs(id TEXT,tenant_id TEXT,request_id TEXT,operation_id TEXT,event_type TEXT,public_event_id TEXT,
		 trace_id TEXT,created_at TIMESTAMPTZ DEFAULT now(),tool_name TEXT,tool_type TEXT,status TEXT)`,
		`INSERT INTO projects VALUES('project-one','研发一部'); INSERT INTO users VALUES('user-one','张三'); INSERT INTO rules(id,name,rule_type) VALUES('rule-one','密码明文检测','secret')`,
		`INSERT INTO request_logs(id,request_id,tenant_id,project_id,request_status,upstream_status_code,trace_id,input_tokens,output_tokens)
		 VALUES('log-one','request-one','tenant-a','project-one','security_blocked',403,'trace-one',12,0)`,
		`INSERT INTO security_events(id,tenant_id,request_id,project_id,user_id,event_type,severity,rule_id,action_taken,matched_summary)
		 VALUES('evt-one','tenant-a','request-one','project-one','user-one','security_check','high','rule-one','block',
		 '{"block":{"block_id":"evt-one","detail":"pass****996","rule_name":"密码明文检测"},"raw_evidence":"RAW_EVENT_SECRET"}'),
		 ('evt-foreign','tenant-b','request-one','project-one','user-one','security_check','high','rule-one','block','{}'),
		 ('evt-other-request','tenant-a','request-two','project-one','user-one','security_check','high','rule-one','block','{}')`,
		`INSERT INTO content_logs(id,tenant_id,request_id,role,content,tokens) VALUES('content-one','tenant-a','log-one','user','PRIVATE_PROMPT_BODY',12)`,
		`INSERT INTO tool_call_logs(id,tenant_id,request_id,operation_id,event_type,tool_name,tool_type,status)
		 VALUES('tool-one','tenant-a','request-one','operation-one','tool_attempt_blocked','delete_file','function','blocked')`,
	} {
		if _, err := db.Exec(ctx, stmt); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	alerts := &blockTraceAlertReader{}
	return &Dependencies{SecurityEventRepo: repository.NewSecurityEventRepository(db), AlertOccurrenceRepo: alerts}, db, alerts
}

func serveBlockTrace(deps *Dependencies, role, tenant, blockID string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/admin/v1/security/block-records/"+blockID+"/trace", nil)
	r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{ID: "user-one", TenantID: tenant, Role: role}))
	r = r.WithContext(context.WithValue(r.Context(), auth.SessionKey, &repository.Session{UserID: "user-one", TenantID: tenant}))
	if mutate != nil {
		mutate(r)
	}
	router := chi.NewRouter()
	router.Get("/admin/v1/security/block-records/{block_id}/trace", GetSecurityBlockTrace(deps))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

// 留存正文、端点本地决策始终不返回；命中原文（2.9.22 起入库）给有内容证据权限的平台管理员。
func TestGetSecurityBlockTraceAssociatesRealRequestAndNeverReturnsBodies(t *testing.T) {
	deps, _, alerts := blockTraceTestDependencies(t)
	w := serveBlockTrace(deps, "platform_admin", "tenant-a", "evt-one", nil)
	if w.Code != 200 {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	var trace securityBlockTrace
	if err := json.Unmarshal(w.Body.Bytes(), &trace); err != nil {
		t.Fatal(err)
	}
	if trace.Block.BlockID != "evt-one" || trace.Audit.Request.RequestID != "request-one" || trace.Audit.Request.RecordID != "log-one" || trace.AlertsStatus != "available" {
		t.Fatalf("trace: %+v", trace)
	}
	if !alerts.called || alerts.filter.TenantID != "tenant-a" || alerts.filter.RequestID != "request-one" || !alerts.filter.IncludeRaw || !alerts.filter.IncludeSuppressed {
		t.Fatalf("alert scope: %+v", alerts.filter)
	}
	if len(trace.Audit.SecurityEvents) != 1 || trace.Audit.SecurityEvents[0].ID != "evt-one" || len(trace.Audit.ContentRecords) != 1 || len(trace.Audit.ToolRecords) != 1 || trace.Audit.ContentEvidence.Status != "available" || !trace.Audit.ContentEvidence.CanView {
		t.Fatalf("audit: %+v", trace.Audit)
	}
	for _, link := range []struct{ value, path string }{{trace.Audit.DetailURL, "/security/alerts"}, {trace.Audit.RetentionURL, "/audit/access-retention"}} {
		parsed, err := url.Parse(link.value)
		if err != nil || parsed.Path != link.path || parsed.Host != "" || parsed.Query().Get("request_id") != "request-one" {
			t.Fatalf("safe links: %+v", trace.Audit)
		}
	}
	for _, forbidden := range []string{"PRIVATE_PROMPT_BODY", "RAW_LOCAL_DECISION", "evt-foreign", "evt-other-request"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("trace leaked %s", forbidden)
		}
	}
	for _, raw := range []string{"RAW_EVENT_SECRET", "RAW_ALERT_SECRET", "RAW_PREVIEW_SECRET", "RAW_CONTEXT_SECRET"} {
		if !strings.Contains(w.Body.String(), raw) {
			t.Fatalf("有内容证据权限的角色应看到命中原文 %s", raw)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("sensitive metadata must not be cached")
	}
}

func TestGetSecurityBlockTraceFailsClosedForIdentityTenantAndDepartment(t *testing.T) {
	deps, _, _ := blockTraceTestDependencies(t)
	cases := []struct {
		role, tenant string
		change       func(*http.Request)
		want         int
	}{
		{"platform_admin", "tenant-b", nil, 404},
		{"dept_manager", "tenant-a", nil, 404},
		{"platform_admin", "tenant-a", func(r *http.Request) { auth.GetUser(r.Context()).DepartmentAssignmentMode = "emergency" }, 404},
		{"platform_admin", "tenant-a", func(r *http.Request) {
			*r = *r.WithContext(context.WithValue(r.Context(), auth.SessionKey, (*repository.Session)(nil)))
		}, 401},
		{"platform_admin", "tenant-a", func(r *http.Request) { auth.GetSession(r.Context()).TenantID = "tenant-b" }, 401},
	}
	for _, tc := range cases {
		w := serveBlockTrace(deps, tc.role, tc.tenant, "evt-one", tc.change)
		if w.Code != tc.want {
			t.Fatalf("role=%s tenant=%s got=%d want=%d %s", tc.role, tc.tenant, w.Code, tc.want, w.Body.String())
		}
	}
}

func TestGetSecurityBlockTraceDistinguishesUnavailableAndMissingEvidence(t *testing.T) {
	deps, db, alerts := blockTraceTestDependencies(t)
	alerts.err = errors.New("alert component failed")
	if _, err := db.Exec(context.Background(), `DROP TABLE content_logs`); err != nil {
		t.Fatal(err)
	}
	w := serveBlockTrace(deps, "platform_admin", "tenant-a", "evt-one", nil)
	var trace securityBlockTrace
	if w.Code != 200 {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &trace); err != nil {
		t.Fatal(err)
	}
	if trace.Audit.Request == nil || trace.Audit.Request.RecordID != "log-one" || trace.AlertsStatus != "unavailable" || trace.Alerts != nil || trace.Audit.Status != "unavailable" || trace.Audit.ContentEvidence.Status != "unavailable" {
		t.Fatalf("component failure must not look uncollected: %+v", trace)
	}
}

func TestBlockTraceContentEvidenceKeepsContentRoleGate(t *testing.T) {
	metadata := &repository.BlockAuditMetadata{Request: &repository.BlockRequestMetadata{}, HasContent: true}
	got := blockTraceContentEvidence(metadata, false)
	if got.Status != "restricted" || got.CanView || got.ReasonCode != "content_permission_required" {
		t.Fatalf("content gate: %+v", got)
	}
	missing := blockTraceContentEvidence(&repository.BlockAuditMetadata{}, true)
	if missing.Status != "unavailable" || missing.ReasonCode != "request_record_missing" {
		t.Fatalf("missing != uncollected: %+v", missing)
	}
}
