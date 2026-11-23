package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestEvalIntegrationAPIMiddlewareAllowsBearerSharedSecret(t *testing.T) {
	mw := EvalIntegrationAPIMiddleware("secret-token", &Dependencies{})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/eval-integration/health", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusNoContent, w.Body.String())
	}
}

func TestEvalIntegrationAuditEventsRequireTenantHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/eval-integration/audit-events?eval_run_id=eval-1", nil)
	w := httptest.NewRecorder()

	ListEvalIntegrationAuditEvents(&Dependencies{})(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if !strings.Contains(w.Body.String(), "tenant") {
		t.Fatalf("response should mention tenant requirement, got %s", w.Body.String())
	}
}

func TestEvalIntegrationAuditEventsRejectInvalidLimit(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/eval-integration/audit-events?limit=501", nil)
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant-1")
	w := httptest.NewRecorder()

	ListEvalIntegrationAuditEvents(&Dependencies{})(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestEvalAuditEventFilterDefaultsToBoundedWindowAndSkipTotal(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/eval-integration/audit-events?trace_id=trace-1&skip_total=true", nil)

	filter, err := evalAuditEventFilterFromRequest(req)
	if err != nil {
		t.Fatalf("parse filter: %v", err)
	}
	if !filter.SkipTotal {
		t.Fatal("expected skip_total=true to be parsed")
	}
	if filter.StartTime == nil || filter.EndTime == nil {
		t.Fatalf("expected default 24h window, got %#v", filter)
	}
	window := filter.EndTime.Sub(*filter.StartTime)
	if window < 23*time.Hour || window > 25*time.Hour {
		t.Fatalf("default window = %s, want about 24h", window)
	}
}

func TestEvalIntegrationHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/eval-integration/health", nil)
	w := httptest.NewRecorder()

	GetEvalIntegrationHealth(&Dependencies{})(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "ok") {
		t.Fatalf("health response should include ok status, got %s", w.Body.String())
	}
}

func TestEvalAuditEventResponseFlagsSecurityEventCount(t *testing.T) {
	resp := evalAuditEventResponse(&repository.EvalAuditEvent{
		ID:                 "log-1",
		RequestID:          "req-1",
		TenantID:           "tenant-1",
		CreatedAt:          time.Unix(0, 0).UTC(),
		RequestStatus:      "completed",
		SecurityEventCount: 1,
	}, nil, nil)

	if resp["action"] != "alert" || resp["verdict"] != "flagged" || resp["risk_level"] != "medium" {
		t.Fatalf("security event count should flag list response, got %#v", resp)
	}
}

func TestEvalRawContentRequestedGating(t *testing.T) {
	newReq := func(q string) *http.Request {
		return httptest.NewRequest(http.MethodGet, "/admin/v1/eval-integration/audit-events"+q, nil)
	}
	// env 未开：即便带 include_content 也不返原文（受控默认关）
	if evalRawContentRequested(newReq("?include_content=true")) {
		t.Fatal("env 关闭时不应返原文")
	}
	t.Setenv("EVAL_INTEGRATION_RAW_CONTENT", "true")
	// env 开但调用方未显式请求：不返原文
	if evalRawContentRequested(newReq("")) {
		t.Fatal("未带 include_content 不应返原文")
	}
	// env 开 + 显式请求：返原文
	if !evalRawContentRequested(newReq("?include_content=true")) {
		t.Fatal("env 开且显式请求应返原文")
	}
	if !evalRawContentRequested(newReq("?include_content=1")) {
		t.Fatal("include_content=1 应返原文")
	}
}

func TestEvalEvidencePayloadAttachesMessages(t *testing.T) {
	event := &repository.EvalAuditEvent{SecurityEventCount: 2}
	off := evalEvidencePayload(event, nil, nil)
	if off["raw_content_available"] != false {
		t.Fatalf("无原文应 raw_content_available=false, got %#v", off)
	}
	if _, ok := off["messages"]; ok {
		t.Fatal("无原文不应带 messages 字段")
	}
	msgs := []map[string]interface{}{{"role": "user", "content": "hi"}}
	on := evalEvidencePayload(event, msgs, nil)
	if on["raw_content_available"] != true {
		t.Fatalf("有原文应 raw_content_available=true, got %#v", on)
	}
	if on["redacted"] != true {
		t.Fatal("redacted 应始终为 true(内嵌密钥/PII 仍脱敏)")
	}
	if _, ok := on["messages"]; !ok {
		t.Fatal("有原文应带 messages 字段")
	}
}

func TestEvalFindingSkipsRuleFalsePositive(t *testing.T) {
	finding := normalizeEvalFinding(evalFindingRequest{
		RequestID:  "req-1",
		Severity:   "高危",
		Verdict:    "rule_false_positive",
		RiskDomain: "提示注入/越狱风险",
		Reason:     "应拒答但规则误判，模型已正确拒绝",
	})

	if !shouldSkipEvalFinding(finding) {
		t.Fatalf("rule false positive finding should be skipped")
	}
}

func TestEvalFindingMapsShouldRefuseViolationToContentSafetyEvent(t *testing.T) {
	finding := normalizeEvalFinding(evalFindingRequest{
		RequestID:        "req-1",
		EvalRunID:        "eval-1",
		TaskID:           "task-1",
		SampleID:         "sample-1",
		FindingID:        "finding-1",
		Severity:         "严重",
		Verdict:          "should_refuse_violation",
		RiskDomain:       "应拒答失败/有害能力风险",
		Category:         "提示注入/越狱风险",
		ExpectedBehavior: "should_refuse",
		ActualBehavior:   "answered",
		Reason:           "模型配合解码并执行安全分析",
		Evidence:         "Authorization: Bearer fake-redaction-value",
	})

	if shouldSkipEvalFinding(finding) {
		t.Fatalf("real should-refuse violation should not be skipped")
	}
	if got := normalizeEvalSeverity(finding.Severity, finding.Verdict); got != "critical" {
		t.Fatalf("severity = %q, want critical", got)
	}
	summary := evalFindingMatchedSummary(finding)
	if summary["source"] != "llm_safety_eval" || summary["risk_domain"] != "应拒答失败/有害能力风险" {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	findings, ok := summary["findings"].([]map[string]interface{})
	if !ok || len(findings) != 1 {
		t.Fatalf("summary findings = %#v", summary["findings"])
	}
	if findings[0]["severity"] != "critical" || findings[0]["rule_id"] != "should_refuse_violation" {
		t.Fatalf("unexpected finding summary: %#v", findings[0])
	}
	if evidence := findings[0]["redacted_evidence"].(string); strings.Contains(evidence, "fake-redaction-value") || !strings.Contains(evidence, "[redacted]") {
		t.Fatalf("evidence should be redacted, got %q", evidence)
	}
}

func TestEvalFindingSummaryCarriesConfidence(t *testing.T) {
	// eval finding 是引擎+judge 的确定性结论，finding 摘要必须带 confidence，
	// 否则告警桥的 isNoiseFinding 视为不可分类 → fail-open 恒放行，置信度闸失效。
	finding := normalizeEvalFinding(evalFindingRequest{
		RequestID: "req-1",
		Severity:  "高危",
		Verdict:   "should_refuse_violation",
		Category:  "提示注入/越狱风险",
		Reason:    "模型未拒绝有害请求",
	})

	summary := evalFindingMatchedSummary(finding)
	findings, ok := summary["findings"].([]map[string]interface{})
	if !ok || len(findings) != 1 {
		t.Fatalf("summary findings = %#v", summary["findings"])
	}
	confidence, ok := findings[0]["confidence"].(float64)
	if !ok {
		t.Fatalf("finding 摘要缺 confidence 字段: %#v", findings[0])
	}
	if confidence != evalFindingConfidence {
		t.Fatalf("confidence = %v, want %v", confidence, evalFindingConfidence)
	}
}

func TestEvalFindingProjectIDFallsBackForReverseProxyRequests(t *testing.T) {
	if got := evalFindingProjectID(nil); got != defaultEvalIntegrationProjectID {
		t.Fatalf("project id = %q, want %q", got, defaultEvalIntegrationProjectID)
	}
	if got := evalFindingProjectID(&repository.EvalAuditEvent{}); got != defaultEvalIntegrationProjectID {
		t.Fatalf("project id = %q, want %q", got, defaultEvalIntegrationProjectID)
	}
	if got := evalFindingProjectID(&repository.EvalAuditEvent{ProjectID: " proj_custom "}); got != "proj_custom" {
		t.Fatalf("project id = %q, want proj_custom", got)
	}
}

func TestEvalToolTaintedDetection(t *testing.T) {
	cases := map[string]bool{
		"":                     false,
		"[]":                   false,
		"null":                 false,
		"{}":                   false,
		"[{\"path\":\"url\"}]": true,
		"{\"a\":1}":            true,
	}
	for in, want := range cases {
		if got := evalToolTainted(json.RawMessage(in)); got != want {
			t.Fatalf("evalToolTainted(%q)=%v want %v", in, got, want)
		}
	}
}

func TestEvalToolCallsRequestedGating(t *testing.T) {
	newReq := func(q string) *http.Request {
		return httptest.NewRequest(http.MethodGet, "/admin/v1/eval-integration/audit-events"+q, nil)
	}
	if evalToolCallsRequested(newReq("?include_tool_calls=true")) {
		t.Fatal("env off should not return tool calls")
	}
	t.Setenv("EVAL_INTEGRATION_RAW_CONTENT", "true")
	if !evalToolCallsRequested(newReq("?include_tool_calls=true")) {
		t.Fatal("explicit include_tool_calls should enable tool calls")
	}
	if !evalToolCallsRequested(newReq("?include_content=true")) {
		t.Fatal("include_content should also enable tool calls")
	}
	if evalToolCallsRequested(newReq("")) {
		t.Fatal("no flag should not return tool calls")
	}
}
