package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// staticAccessContentRepo 是 access_content_logs 的假桩：单条与批量各返回一份固定数据。
type staticAccessContentRepo struct {
	item  *repository.AccessContentLog
	batch []repository.AccessContentLog
}

func (r *staticAccessContentRepo) GetAccessContentLog(context.Context, string, string) (*repository.AccessContentLog, error) {
	return r.item, nil
}

func (r *staticAccessContentRepo) GetAccessContentLogs(context.Context, string, []string) ([]repository.AccessContentLog, error) {
	return r.batch, nil
}

func (r *staticAccessContentRepo) ResolveUploadedFileBytes(context.Context, string, []string) (map[string]repository.ResolvedUploadedFile, error) {
	return map[string]repository.ResolvedUploadedFile{}, nil
}

// staticSecurityEventReader 是 security_events 的假桩。
type staticSecurityEventReader struct {
	events []*repository.SecurityEvent
}

func (r staticSecurityEventReader) ListByRequestScoped(context.Context, string, string, time.Time, time.Time, string) ([]*repository.SecurityEvent, error) {
	return r.events, nil
}

func accessRetentionRawRequest(t *testing.T, target string, role string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	user := &repository.User{ID: "user_admin", Username: "admin", TenantID: "tenant_default", Role: role, DepartmentAssignmentMode: "manual"}
	ctx := context.WithValue(req.Context(), auth.UserKey, user)
	ctx = context.WithValue(ctx, auth.SessionKey, &repository.Session{UserID: user.ID, TenantID: user.TenantID})
	return req.WithContext(ctx)
}

func decodeRawRetentionResponse(t *testing.T, body []byte) accessRetentionRawResponse {
	t.Helper()
	var out accessRetentionRawResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode raw retention response: %v (%s)", err, body)
	}
	return out
}

func serveRawRetention(t *testing.T, deps *Dependencies, target string) *httptest.ResponseRecorder {
	t.Helper()
	router := chi.NewRouter()
	router.Get("/admin/v1/audit/access-retention/{request_id}/content", GetAccessRetentionContent(deps))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, accessRetentionRawRequest(t, target, "platform_admin"))
	return recorder
}

// TestAccessRetentionRawSplitsSectionsAndPassesToolCallsThrough 覆盖写入侧 v3 的工具轮留证：
// 请求正文里的【工具】段与响应正文里的工具调用都要还原成带 role 的分段，而不是一整块文本。
func TestAccessRetentionRawSplitsSectionsAndPassesToolCallsThrough(t *testing.T) {
	retentionUntil := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	toolCallsJSON := `[{"id":"digest-1","name":"Read","kind":"invocation_proposed","stage":"request","arguments_preview":"{\"file_path\":\"/etc/hosts\"}"}]`
	repo := &staticAccessContentRepo{item: &repository.AccessContentLog{
		RequestID:            "req_raw_1",
		RequestContent:       "帮我看下 hosts\n\n【工具】[tool_use:Read] {\"file_path\":\"/etc/hosts\"}\n\n【工具】127.0.0.1 localhost",
		ResponseContent:      "已经看完\n\n【工具】[tool_use:Bash] {\"command\":\"cat /etc/hosts\"}",
		ToolCallMetadataJSON: []byte(toolCallsJSON),
		DecoderVersion:       "v3",
		RetentionUntil:       &retentionUntil,
		CreatedAt:            time.Unix(10, 0),
	}}

	recorder := serveRawRetention(t, &Dependencies{AccessContentRepo: repo}, "/admin/v1/audit/access-retention/req_raw_1/content?view=raw")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeRawRetentionResponse(t, recorder.Body.Bytes())

	if response.DecoderVersion != "v3" {
		t.Fatalf("decoder_version=%q", response.DecoderVersion)
	}
	if response.RetentionUntil != "2026-12-01T00:00:00Z" {
		t.Fatalf("retention_until=%q", response.RetentionUntil)
	}
	want := []retentionRawSection{
		{RequestID: "req_raw_1", Direction: "request", Role: "user", Content: "帮我看下 hosts"},
		{RequestID: "req_raw_1", Direction: "request", Role: "tool", Content: `[tool_use:Read] {"file_path":"/etc/hosts"}`},
		{RequestID: "req_raw_1", Direction: "request", Role: "tool", Content: "127.0.0.1 localhost"},
		{RequestID: "req_raw_1", Direction: "response", Role: "assistant", Content: "已经看完"},
		{RequestID: "req_raw_1", Direction: "response", Role: "tool", Content: `[tool_use:Bash] {"command":"cat /etc/hosts"}`},
	}
	if len(response.Sections) != len(want) {
		t.Fatalf("sections=%#v", response.Sections)
	}
	for index := range want {
		if response.Sections[index] != want[index] {
			t.Fatalf("sections[%d]=%#v, want %#v", index, response.Sections[index], want[index])
		}
	}
	if len(response.ToolCalls) != 1 || string(response.ToolCalls[0]) != strings.TrimSuffix(strings.TrimPrefix(toolCallsJSON, "["), "]") {
		t.Fatalf("tool_calls must pass through verbatim: %#v", response.ToolCalls)
	}
	if len(response.EvidenceFallback) != 0 {
		t.Fatalf("evidence_fallback must be an empty array when bodies exist: %#v", response.EvidenceFallback)
	}
	if !strings.Contains(string(recorder.Body.Bytes()), `"evidence_fallback":[]`) {
		t.Fatalf("evidence_fallback must serialize as [] and not null: %s", recorder.Body.String())
	}
}

// TestAccessRetentionRawFallsBackToSecurityEventEvidence 覆盖正文全空的兜底：
// 编码 agent 只留下命中片段时，把 security_events 里未脱标识的原文摆出来，并标注来源角色。
func TestAccessRetentionRawFallsBackToSecurityEventEvidence(t *testing.T) {
	repo := &staticAccessContentRepo{item: &repository.AccessContentLog{
		RequestID: "req_gap_1",
		CreatedAt: time.Unix(10, 0),
	}}
	events := staticSecurityEventReader{events: []*repository.SecurityEvent{{
		ID:          "evt_1",
		RequestID:   "req_gap_1",
		RuleName:    "openai_key",
		Severity:    "high",
		ActionTaken: "audit",
		MatchedSummary: map[string]interface{}{
			"findings": []interface{}{
				map[string]interface{}{
					"rule_name":        "openai_key",
					"category":         "secret",
					"severity":         "high",
					"content_source":   "tool_result",
					"message_role":     "tool",
					"message_index":    float64(165),
					"raw_evidence":     "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz",
					"evidence_context": "cat .env",
				},
				// 没有留到原文片段的 finding 不进兜底——摆空条目只会稀释信号。
				map[string]interface{}{"rule_name": "no_evidence"},
			},
		},
	}}}

	deps := &Dependencies{AccessContentRepo: repo, RetentionSecurityEventReader: events}
	recorder := serveRawRetention(t, deps, "/admin/v1/audit/access-retention/req_gap_1/content?view=raw")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeRawRetentionResponse(t, recorder.Body.Bytes())

	if len(response.Sections) != 0 {
		t.Fatalf("no retained body must yield no sections: %#v", response.Sections)
	}
	if len(response.EvidenceFallback) != 1 {
		t.Fatalf("evidence_fallback=%#v", response.EvidenceFallback)
	}
	entry := response.EvidenceFallback[0]
	if entry.EventID != "evt_1" || entry.RuleName != "openai_key" || entry.Category != "secret" || entry.Severity != "high" {
		t.Fatalf("entry=%#v", entry)
	}
	if entry.ContentSource != "tool_result" || entry.MessageRole != "tool" || entry.MessageIndex != 165 {
		t.Fatalf("entry source must be preserved verbatim: %#v", entry)
	}
	if entry.RawEvidence != "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz" || entry.EvidenceContext != "cat .env" {
		t.Fatalf("raw evidence must not be re-projected: %#v", entry)
	}
}

// TestAccessRetentionRawUsesContentLogsWhenRequestBodyMissing 覆盖主链路回退：
// 反向代理请求只写 content_logs，access_content_logs 没有该请求时仍要能看到分段原文。
func TestAccessRetentionRawUsesContentLogsWhenRequestBodyMissing(t *testing.T) {
	reader := perRequestContentLogReader{
		"req_reverse_1": {
			{ID: "cl_sys", RequestID: "req_reverse_1", Role: "system", Content: "你是一个安全助手"},
			{ID: "cl_user", RequestID: "req_reverse_1", Role: "user", Content: "帮我看看这个配置"},
			{ID: "cl_tool", RequestID: "req_reverse_1", Role: "tool", Content: "配置片段"},
			{ID: "cl_assistant", RequestID: "req_reverse_1", Role: "assistant", Content: "看完了"},
		},
	}
	deps := &Dependencies{AccessContentRepo: &nilAccessContentRepo{}, ContentLogReader: reader}

	recorder := serveRawRetention(t, deps, "/admin/v1/audit/access-retention/req_reverse_1/content?view=raw")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeRawRetentionResponse(t, recorder.Body.Bytes())

	want := []retentionRawSection{
		{RequestID: "req_reverse_1", Direction: "request", Role: "system", Content: "你是一个安全助手"},
		{RequestID: "req_reverse_1", Direction: "request", Role: "user", Content: "帮我看看这个配置"},
		{RequestID: "req_reverse_1", Direction: "request", Role: "tool", Content: "配置片段"},
		{RequestID: "req_reverse_1", Direction: "response", Role: "assistant", Content: "看完了"},
	}
	if len(response.Sections) != len(want) {
		t.Fatalf("sections=%#v", response.Sections)
	}
	for index := range want {
		if response.Sections[index] != want[index] {
			t.Fatalf("sections[%d]=%#v, want %#v", index, response.Sections[index], want[index])
		}
	}
}

// TestAccessRetentionRawStitchesMembersInRequestOrder 多成员时按请求时间顺序拼接，每段带 request_id。
func TestAccessRetentionRawStitchesMembersInRequestOrder(t *testing.T) {
	repo := &staticAccessContentRepo{batch: []repository.AccessContentLog{
		{RequestID: "req_b", RequestContent: "后一轮", ResponseContent: "后一轮答", CreatedAt: time.Unix(20, 0)},
		{RequestID: "req_a", RequestContent: "前一轮", ResponseContent: "前一轮答", CreatedAt: time.Unix(10, 0)},
	}}

	target := "/admin/v1/audit/access-retention/req_b/content?view=raw&members=req_a"
	recorder := serveRawRetention(t, &Dependencies{AccessContentRepo: repo}, target)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeRawRetentionResponse(t, recorder.Body.Bytes())

	want := []retentionRawSection{
		{RequestID: "req_a", Direction: "request", Role: "user", Content: "前一轮"},
		{RequestID: "req_a", Direction: "response", Role: "assistant", Content: "前一轮答"},
		{RequestID: "req_b", Direction: "request", Role: "user", Content: "后一轮"},
		{RequestID: "req_b", Direction: "response", Role: "assistant", Content: "后一轮答"},
	}
	if len(response.Sections) != len(want) {
		t.Fatalf("sections=%#v", response.Sections)
	}
	for index := range want {
		if response.Sections[index] != want[index] {
			t.Fatalf("sections[%d]=%#v, want %#v", index, response.Sections[index], want[index])
		}
	}
}

// TestAccessRetentionRawStaysBehindFullTenantEvidenceGate 权限门不变：部门级读者拿不到未脱标识的原文。
func TestAccessRetentionRawStaysBehindFullTenantEvidenceGate(t *testing.T) {
	deps := &Dependencies{AccessContentRepo: &staticAccessContentRepo{item: &repository.AccessContentLog{
		RequestID:      "req_raw_1",
		RequestContent: "机密正文",
	}}}
	router := chi.NewRouter()
	router.Get("/admin/v1/audit/access-retention/{request_id}/content",
		RequireFullTenantContentEvidence(GetAccessRetentionContent(deps)).ServeHTTP)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, accessRetentionRawRequest(t, "/admin/v1/audit/access-retention/req_raw_1/content?view=raw", "dept_manager"))

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "机密正文") {
		t.Fatalf("department readers must not see raw content: %s", recorder.Body.String())
	}
}
