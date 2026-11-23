package handler

import (
	"context"
	"encoding/json"
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
)

// 告警命中原文入库（2.9.22）后的读取侧：能看原文的角色与“内容证据”权限一致
// （canReadFullTenantContentEvidence），其余能读安全事件的角色（这里用按部门授权的 dept_manager）
// 拿到的摘要里没有 raw_evidence、evidence_context。需要 ALERT_RAW_EVIDENCE_TEST_DATABASE_URL 指向
// 按正式流程迁移到最新的库。

const (
	rawVisibilityHit     = "RAW_HIT_sk-proj-Ab3dEf9"
	rawVisibilityContext = "CTX_BEFORE " + rawVisibilityHit + " CTX_AFTER"
)

type rawVisibilitySystemRepo struct{ auditDetailSystemRepo }

func (*rawVisibilitySystemRepo) GetBool(_ context.Context, key string) (bool, error) {
	return key == "content_audit_enabled", nil
}

type rawVisibilityAlertReader struct {
	filters []repository.AlertOccurrenceFilter
}

func (r *rawVisibilityAlertReader) List(_ context.Context, f repository.AlertOccurrenceFilter) (*repository.AlertOccurrencePage, error) {
	r.filters = append(r.filters, f)
	item := repository.AlertOccurrence{ID: "occ", EventID: "evt", RuleName: "密钥", RedactedEvidence: "sk****f9"}
	if f.IncludeRaw && f.CanReadEvidence {
		item.RawEvidence, item.MatchedTextPreview, item.EvidenceContext = rawVisibilityHit, "sk****f9", rawVisibilityContext
	}
	return &repository.AlertOccurrencePage{Items: []repository.AlertOccurrence{item}, Total: 1}, nil
}

type rawVisibilityFixture struct {
	deps                  *Dependencies
	alerts                *rawVisibilityAlertReader
	tenant, project       string
	eventID, requestID    string
	sessionID, adminID    string
	managerID, department string
}

func setupRawVisibilityFixture(t *testing.T) *rawVisibilityFixture {
	t.Helper()
	dsn := os.Getenv("ALERT_RAW_EVIDENCE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ALERT_RAW_EVIDENCE_TEST_DATABASE_URL not set; skipping raw evidence visibility test")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	ns := fmt.Sprintf("rawvis%d", time.Now().UnixNano())
	f := &rawVisibilityFixture{
		tenant: "tenant_" + ns, project: "proj_" + ns, eventID: "evt_" + ns, requestID: "req_" + ns,
		sessionID: "sess_" + ns, adminID: "admin_" + ns, managerID: "mgr_" + ns, department: "dept_" + ns,
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%v: %s", err, query)
		}
	}
	finding := map[string]any{
		"type": "secret", "category": "openai_key", "severity": "high", "rule_name": "OpenAI 密钥",
		"matched_location": "content[11:34]", "content_source": "user", "evidence_kind": "literal",
		"redacted_evidence": "sk****f9", "matched_text_preview": "sk****f9",
		"raw_evidence": rawVisibilityHit, "evidence_context": rawVisibilityContext,
		"raw_evidence_sha256": "aa", "evidence_context_sha256": "bb", "evidence_identity_sha256": "",
		"raw_evidence_truncated": true,
	}
	summary, _ := json.Marshal(map[string]any{
		"source": "gateway", "stage": "input", "action_taken": "block", "category": "openai_key",
		"rule_name": "OpenAI 密钥", "findings": []any{finding}, "primary_finding": finding, "findings_count": 1,
		"block": map[string]any{"block_id": f.eventID, "layer": "input_content", "reason": "输入内容命中安全规则",
			"rule_name": "OpenAI 密钥", "category": "openai_key", "detail": "sk****f9"},
	})
	audit, _ := json.Marshal(map[string]any{"action_taken": "block", "findings": []any{finding}})
	exec(`INSERT INTO tenants (id, name, is_test) VALUES ($1, $1, TRUE)`, f.tenant)
	exec(`INSERT INTO teams (id, tenant_id, name, path) VALUES ($1, $2, $1, $3)`, f.department, f.tenant, "/"+f.department)
	exec(`INSERT INTO projects (id, tenant_id, name, team_id) VALUES ($1, $2, $1, $3)`, f.project, f.tenant, f.department)
	for id, role := range map[string]string{f.adminID: "platform_admin", f.managerID: "dept_manager"} {
		exec(`INSERT INTO users (id, tenant_id, username, role, department_id, department_assignment_mode) VALUES ($1, $2, $1, $3, $4, 'manual')`, id, f.tenant, role, f.department)
	}
	exec(`INSERT INTO request_logs (id, request_id, tenant_id, project_id, session_id, request_status, environment_scope, input_audit_result, created_at)
		VALUES ($1, $2, $3, $4, $5, 'security_blocked', 'customer', $6::jsonb, now())`, "log_"+ns, f.requestID, f.tenant, f.project, f.sessionID, string(audit))
	exec(`INSERT INTO content_logs (id, tenant_id, request_id, session_id, role, content, environment_scope, created_at)
		VALUES ($1, $2, $3, $4, 'user', '请帮我调用接口', 'customer', now())`, "cl_"+ns, f.tenant, "log_"+ns, f.sessionID)
	exec(`INSERT INTO security_events (id, request_id, tenant_id, project_id, event_type, severity, action_taken, matched_summary, created_at)
		VALUES ($1, $2, $3, $4, 'security_check', 'high', 'block', $5::jsonb, now())`, f.eventID, f.requestID, f.tenant, f.project, string(summary))
	// 收件箱里带原文的旧正文（07～09 月旧事件、或 2.9.22 之前写入的行）：matched 是整份安全事件摘要，primary_finding
	// 是主命中。2.9.22 起告警桥写入的正文已去掉原文（storedAlertBody），读取侧剔除仍要兜住旧行。
	inboxBody, _ := json.Marshal(map[string]any{
		"event_id": f.eventID, "rule_name": "OpenAI 密钥", "category": "openai_key", "action": "block",
		"primary_finding": finding, "matched": json.RawMessage(summary),
	})
	exec(`INSERT INTO alert_inbox (id, tenant_id, severity, type, title, body_json, target_url, created_at)
		VALUES ($1, $2, 'high', 'security_event', '命中 OpenAI 密钥', $3::jsonb, '/security-events/'||$4, now())`, "inbox_"+ns, f.tenant, string(inboxBody), f.eventID)
	t.Cleanup(func() {
		c := context.Background()
		for _, q := range []string{
			`DELETE FROM alert_inbox WHERE tenant_id = $1`,
			`DELETE FROM security_events WHERE tenant_id = $1`, `DELETE FROM content_logs WHERE tenant_id = $1`,
			`DELETE FROM request_logs WHERE tenant_id = $1`, `DELETE FROM audit_operations WHERE tenant_id = $1`,
			`DELETE FROM users WHERE tenant_id = $1`, `DELETE FROM projects WHERE tenant_id = $1`,
			`DELETE FROM teams WHERE tenant_id = $1`, `DELETE FROM tenants WHERE id = $1`,
		} {
			_, _ = db.Exec(c, q, f.tenant)
		}
		db.Close()
	})
	f.alerts = &rawVisibilityAlertReader{}
	f.deps = &Dependencies{
		SecurityEventRepo:   repository.NewSecurityEventRepository(db),
		RequestLogRepo:      repository.NewRequestLogRepository(db),
		ContentLogRepo:      repository.NewContentLogRepository(db),
		TeamMemberRepo:      repository.NewTeamMemberRepository(db),
		AlertInboxRepo:      repository.NewAlertInboxRepository(db),
		AlertOccurrenceRepo: f.alerts,
		SystemRepo:          &rawVisibilitySystemRepo{},
	}
	return f
}

func (f *rawVisibilityFixture) serve(t *testing.T, role, pattern, target string, h http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	userID := f.adminID
	if role == "dept_manager" {
		userID = f.managerID
	}
	user := &repository.User{ID: userID, TenantID: f.tenant, Role: role, DepartmentID: f.department}
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, user))
	r = r.WithContext(context.WithValue(r.Context(), auth.SessionKey, &repository.Session{UserID: userID, TenantID: f.tenant}))
	router := chi.NewRouter()
	router.Get(pattern, h)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("%s %s: status=%d body=%s", role, target, w.Code, w.Body.String())
	}
	return w
}

func assertRawVisible(t *testing.T, name string, body string, visible bool) {
	t.Helper()
	for _, raw := range []string{rawVisibilityHit, "CTX_BEFORE", "CTX_AFTER"} {
		if got := strings.Contains(body, raw); got != visible {
			t.Fatalf("%s: 原文 %q 可见=%v，期望 %v：%s", name, raw, got, visible, body)
		}
	}
}

func TestAuditEventsRawEvidenceFollowsContentEvidencePermission(t *testing.T) {
	f := setupRawVisibilityFixture(t)
	path := "/admin/v1/audit/events"
	admin := f.serve(t, "platform_admin", path, path, ListSecurityEvents(f.deps)).Body.String()
	assertRawVisible(t, "平台管理员", admin, true)
	manager := f.serve(t, "dept_manager", path, path, ListSecurityEvents(f.deps)).Body.String()
	assertRawVisible(t, "部门负责人", manager, false)
	if !strings.Contains(manager, f.eventID) || !strings.Contains(manager, "sk****f9") {
		t.Fatalf("剔除原文后其余字段照旧返回: %s", manager)
	}
}

func TestSecurityBlockRecordRawEvidenceFollowsContentEvidencePermission(t *testing.T) {
	f := setupRawVisibilityFixture(t)
	detail := "/admin/v1/security/block-records/" + f.eventID
	for _, tc := range []struct {
		role    string
		visible bool
	}{{"platform_admin", true}, {"dept_manager", false}} {
		one := f.serve(t, tc.role, "/admin/v1/security/block-records/{block_id}", detail, GetSecurityBlockRecord(f.deps)).Body.String()
		assertRawVisible(t, tc.role+" 阻断记录详情", one, tc.visible)
		// 列表不带命中原文和前后文（只在详情返回），减小列表响应；有权限的角色也一样。
		list := f.serve(t, tc.role, "/admin/v1/security/block-records", "/admin/v1/security/block-records", ListSecurityBlockRecords(f.deps)).Body.String()
		assertRawVisible(t, tc.role+" 阻断记录列表", list, false)
		if strings.Contains(list, `"raw_evidence"`) || strings.Contains(list, `"evidence_context"`) || strings.Contains(list, `"raw_evidence_truncated"`) || !strings.Contains(list, f.eventID) {
			t.Fatalf("%s: 列表不返回原文字段、照旧列出阻断记录: %s", tc.role, list)
		}
		if !strings.Contains(one, `"detail":"sk****f9"`) {
			t.Fatalf("%s: 命中内容展示值不变: %s", tc.role, one)
		}
		if strings.Contains(one, `"raw_evidence_truncated":true`) != tc.visible {
			t.Fatalf("%s: 截断标记与原文同权限返回: %s", tc.role, one)
		}
	}
	var record repository.SecurityBlockRecord
	body := f.serve(t, "platform_admin", "/admin/v1/security/block-records/{block_id}", detail, GetSecurityBlockRecord(f.deps)).Body.Bytes()
	if err := json.Unmarshal(body, &record); err != nil || record.RawEvidence != rawVisibilityHit || record.EvidenceContext != rawVisibilityContext || !record.RawEvidenceTruncated {
		t.Fatalf("有权限角色拿到阻断命中原文和前后文: %+v %v", record, err)
	}
}

func TestSecurityBlockTraceRawEvidenceFollowsContentEvidencePermission(t *testing.T) {
	f := setupRawVisibilityFixture(t)
	target := "/admin/v1/security/block-records/" + f.eventID + "/trace"
	pattern := "/admin/v1/security/block-records/{block_id}/trace"
	admin := f.serve(t, "platform_admin", pattern, target, GetSecurityBlockTrace(f.deps)).Body.String()
	assertRawVisible(t, "平台管理员阻断溯源", admin, true)
	if last := f.alerts.filters[len(f.alerts.filters)-1]; !last.IncludeRaw || !last.CanReadEvidence {
		t.Fatalf("有权限角色的命中明细应带原文: %+v", last)
	}
	var adminTrace securityBlockTrace
	if err := json.Unmarshal([]byte(admin), &adminTrace); err != nil || adminTrace.Block == nil || !adminTrace.Block.RawEvidenceTruncated {
		t.Fatalf("有权限角色的溯源阻断记录带截断标记: %v %s", err, admin)
	}
	manager := f.serve(t, "dept_manager", pattern, target, GetSecurityBlockTrace(f.deps)).Body.String()
	assertRawVisible(t, "部门负责人阻断溯源", manager, false)
	if strings.Contains(manager, `"raw_evidence_truncated"`) {
		t.Fatalf("无权限角色的溯源不带截断标记: %s", manager)
	}
	if last := f.alerts.filters[len(f.alerts.filters)-1]; last.IncludeRaw {
		t.Fatalf("无权限角色不取原文: %+v", last)
	}
}

func TestAuditExportRawEvidenceFollowsContentEvidencePermission(t *testing.T) {
	f := setupRawVisibilityFixture(t)
	target := "/admin/v1/audit/export?format=json"
	admin := f.serve(t, "platform_admin", "/admin/v1/audit/export", target, ExportAuditLogs(f.deps)).Body.String()
	assertRawVisible(t, "平台管理员审计导出", admin, true)
	manager := f.serve(t, "dept_manager", "/admin/v1/audit/export", target, ExportAuditLogs(f.deps)).Body.String()
	assertRawVisible(t, "部门负责人审计导出", manager, false)
	if !strings.Contains(manager, f.requestID) {
		t.Fatalf("剔除原文后导出记录照旧: %s", manager)
	}
}

func TestSessionExportRawEvidenceFollowsContentEvidencePermission(t *testing.T) {
	f := setupRawVisibilityFixture(t)
	pattern := "/admin/v1/audit/content/{session_id}/export"
	target := "/admin/v1/audit/content/" + f.sessionID + "/export?format=text"
	admin := f.serve(t, "platform_admin", pattern, target, ExportSessionContent(f.deps)).Body.String()
	assertRawVisible(t, "平台管理员会话导出", admin, true)
	if !strings.Contains(admin, "命中证据（原文，不脱敏）") {
		t.Fatalf("会话导出标签: %s", admin)
	}
	manager := f.serve(t, "dept_manager", pattern, target, ExportSessionContent(f.deps)).Body.String()
	assertRawVisible(t, "部门负责人会话导出", manager, false)

	events := "/admin/v1/audit/content/" + f.sessionID + "/events"
	eventsPattern := "/admin/v1/audit/content/{session_id}/events"
	assertRawVisible(t, "平台管理员会话告警", f.serve(t, "platform_admin", eventsPattern, events, GetSessionSecurityEvents(f.deps)).Body.String(), true)
	assertRawVisible(t, "部门负责人会话告警", f.serve(t, "dept_manager", eventsPattern, events, GetSessionSecurityEvents(f.deps)).Body.String(), false)
}

// 门户集成（共享密钥调用，没有登录用户）按约定只拿脱敏摘要，不含原文。
func TestPortalAuditEventsNeverReturnRawEvidence(t *testing.T) {
	f := setupRawVisibilityFixture(t)
	r := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/audit-events", nil)
	r.Header.Set(portalIntegrationTenantHeader, f.tenant)
	w := httptest.NewRecorder()
	ListPortalAuditEvents(f.deps)(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), f.eventID) {
		t.Fatalf("门户事件: %d %s", w.Code, w.Body.String())
	}
	assertRawVisible(t, "门户集成", w.Body.String(), false)
}

// 收件箱正文（body_json）里的 matched、primary_finding 带命中原文：列表（不带筛选的旧路径和带筛选的路径）、
// 折叠视图、折叠明细、导出都按内容证据权限剔除，与 /audit/events 同口径。
func TestAlertInboxRawEvidenceFollowsContentEvidencePermission(t *testing.T) {
	f := setupRawVisibilityFixture(t)
	// 折叠视图按租户报表时区（默认 Asia/Shanghai）分日：用前后各一天的范围，跨过 UTC 与本地日期不一致的时段。
	from, to := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02"), time.Now().UTC().AddDate(0, 0, 1).Format("2006-01-02")
	for _, tc := range []struct {
		role    string
		visible bool
	}{{"platform_admin", true}, {"dept_manager", false}} {
		for _, target := range []string{"/admin/v1/alerts/inbox", "/admin/v1/alerts/inbox?severity=high"} {
			body := f.serve(t, tc.role, "/admin/v1/alerts/inbox", target, ListAlertInboxW8(f.deps)).Body.String()
			assertRawVisible(t, tc.role+" "+target, body, tc.visible)
			if !strings.Contains(body, f.eventID) {
				t.Fatalf("%s %s: 剔除原文后其余正文照旧: %s", tc.role, target, body)
			}
		}
		folded := f.serve(t, tc.role, "/admin/v1/alerts/inbox/folded", "/admin/v1/alerts/inbox/folded?from="+from+"&to="+to, ListAlertInboxFolded(f.deps))
		assertRawVisible(t, tc.role+" 折叠视图", folded.Body.String(), tc.visible)
		var page struct {
			Groups []struct {
				Key, Type, Severity string
				DayStart            time.Time `json:"day_start"`
				DayEnd              time.Time `json:"day_end"`
			} `json:"groups"`
		}
		if err := json.Unmarshal(folded.Body.Bytes(), &page); err != nil || len(page.Groups) != 1 {
			t.Fatalf("%s 折叠视图分组: %v %s", tc.role, err, folded.Body.String())
		}
		g := page.Groups[0]
		items := fmt.Sprintf("/admin/v1/alerts/inbox/folded/items?key=%s&type=%s&severity=%s&day_start=%s&day_end=%s",
			g.Key, g.Type, g.Severity, g.DayStart.UTC().Format(time.RFC3339), g.DayEnd.UTC().Format(time.RFC3339))
		assertRawVisible(t, tc.role+" 折叠明细", f.serve(t, tc.role, "/admin/v1/alerts/inbox/folded/items", items, ListAlertInboxFoldedItems(f.deps)).Body.String(), tc.visible)
		export := f.serve(t, tc.role, "/admin/v1/alerts/inbox/export", "/admin/v1/alerts/inbox/export?format=csv", ExportAlertInbox(f.deps)).Body.String()
		assertRawVisible(t, tc.role+" 收件箱导出", export, tc.visible)
		if !strings.Contains(export, f.eventID) {
			t.Fatalf("%s: 导出照旧带告警正文其余字段: %s", tc.role, export)
		}
	}
}

// 阻断记录导出：有内容证据权限的角色多一列“命中原文”，其他角色没有这一列；“命中内容”列照旧是打码展示值。
func TestSecurityBlockRecordExportRawColumnFollowsContentEvidencePermission(t *testing.T) {
	f := setupRawVisibilityFixture(t)
	target := "/admin/v1/security/block-records/export?format=csv"
	admin := f.serve(t, "platform_admin", "/admin/v1/security/block-records/export", target, ExportSecurityBlockRecords(f.deps)).Body.String()
	if !strings.Contains(admin, "命中原文") || !strings.Contains(admin, rawVisibilityHit) || !strings.Contains(admin, "sk****f9") {
		t.Fatalf("有权限角色导出应带“命中原文”列: %s", admin)
	}
	manager := f.serve(t, "dept_manager", "/admin/v1/security/block-records/export", target, ExportSecurityBlockRecords(f.deps)).Body.String()
	if strings.Contains(manager, "命中原文") || strings.Contains(manager, rawVisibilityHit) || !strings.Contains(manager, f.eventID) {
		t.Fatalf("无权限角色导出不带“命中原文”列: %s", manager)
	}
}
