package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// P2-2：B 路（:8082 反代）此前发给引擎的 context 只有 {tenant_id, source}，
// 引擎降级层（endpoint_kind==coding / access_type==ai_ide）对反代流量完全失明。
// 修复后 checkSecurity 复用目录匹配把端点画像注入 context。
// 用 Cursor（目录内 category=coding / risk_profile=ai_ide_agent）钉死降级层消费的两个关键键。
func TestReverseProxyCheckSecurity_InjectsEndpointContext(t *testing.T) {
	captured := make(chan map[string]interface{}, 1)
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]interface{}
		_ = json.Unmarshal(raw, &body)
		captured <- body
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow","findings":[]}`))
	}))
	defer engine.Close()

	h := &ReverseProxyHandler{
		tenantID:    "tenant_default",
		securityURL: engine.URL,
		client:      engine.Client(),
	}

	// 路径不含 chat/message 等关键词，端点归类落到目录 category=coding 本身。
	if _, err := h.checkRequestSecurity(context.Background(), "req-1", []byte("hello"), "application/json", "api5.cursor.sh", "/aiserver.v1/"); err != nil {
		t.Fatalf("checkRequestSecurity err: %v", err)
	}

	body := <-captured
	ctxMap, ok := body["context"].(map[string]interface{})
	if !ok {
		t.Fatalf("引擎请求体缺 context: %#v", body)
	}
	// 原有字段不回归。
	if ctxMap["tenant_id"] != "tenant_default" || ctxMap["source"] != "reverse_proxy" {
		t.Fatalf("tenant_id/source 基础上下文不得丢失: %#v", ctxMap)
	}
	// 引擎降级层消费的两个关键键。
	if ctxMap["endpoint_kind"] != "coding" {
		t.Fatalf("coding 目录命中应注入 endpoint_kind=coding, got %#v", ctxMap)
	}
	if ctxMap["access_type"] != "ai_ide" {
		t.Fatalf("ai_ide_agent 画像应注入 access_type=ai_ide, got %#v", ctxMap)
	}
	if ctxMap["product"] != "cursor_agent" {
		t.Fatalf("应注入目录 product, got %#v", ctxMap)
	}
	if ctxMap["target_host"] != "api5.cursor.sh" {
		t.Fatalf("应注入 target_host, got %#v", ctxMap)
	}
}

// 端到端：forwardRequest 的三个调用点（输入/流式输出/非流式输出）必须把 targetHost/path
// 真正传进 checkSecurity——只改函数签名不改调用点会静默退化。127.0.0.1 上游走
// openai_compatible 兜底目录（access_type=llm），足以验证接线。
func TestReverseProxyServeHTTP_SecurityChecksCarryEndpointContext(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"answer"}}]}`))
	}))
	defer upstream.Close()

	type engineCall struct {
		path string
		ctx  map[string]interface{}
	}
	calls := make(chan engineCall, 4)
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]interface{}
		_ = json.Unmarshal(raw, &body)
		ctxMap, _ := body["context"].(map[string]interface{})
		calls <- engineCall{path: r.URL.Path, ctx: ctxMap}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow","findings":[]}`))
	}))
	defer engine.Close()

	audit := &fakeReverseProxyAuditRecorder{}
	handler := &ReverseProxyHandler{
		tenantID:                  "tenant_default",
		client:                    upstream.Client(),
		securityURL:               engine.URL,
		resolveEgressTarget:       testEgressResolver(upstream.URL),
		auditRecorder:             audit,
		securityAuditOnlyFallback: true,
		routes: []ReverseProxyRoute{{
			ID:              "rpr_compat",
			PathPrefix:      "/compat",
			TargetURL:       upstream.URL,
			SecurityEnabled: true,
			Status:          "active",
		}},
	}

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/compat/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	if !handler.ServeHTTP(w, req) {
		t.Fatalf("expected request handled by reverse proxy")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	seen := map[string]map[string]interface{}{}
	for len(calls) > 0 {
		c := <-calls
		seen[c.path] = c.ctx
	}
	for _, path := range []string{"/check-input/", "/check-output/"} {
		ctxMap := seen[path]
		if ctxMap == nil {
			t.Fatalf("引擎未收到 %s 调用, seen=%v", path, seen)
		}
		if got, _ := ctxMap["access_type"].(string); got != "llm" {
			t.Fatalf("%s context 应带 access_type=llm（openai 兼容兜底目录）, got %#v", path, ctxMap)
		}
		if got, _ := ctxMap["product"].(string); got != "openai_compatible_api" {
			t.Fatalf("%s context 应带 product, got %#v", path, ctxMap)
		}
		if got, _ := ctxMap["target_host"].(string); got == "" {
			t.Fatalf("%s context 应带 target_host, got %#v", path, ctxMap)
		}
	}
}

// matched_summary 与 C 路口径对齐：AccessType/Product/EndpointKind 注入（非空才写），
// 供收件箱闸 / 看板按流量画像过滤。
func TestBuildReverseProxySecurityEventRow_InjectsAccessProfileIntoSummary(t *testing.T) {
	record := reverseProxyAuditRecord{
		RequestID:    "req-123",
		TenantID:     "tenant_default",
		TargetHost:   "api5.cursor.sh",
		TargetPath:   "/aiserver.v1/StreamChat",
		AccessType:   "ai_ide",
		Product:      "cursor_agent",
		EndpointKind: "coding",
	}
	findings := []SecurityFinding{{Type: "prompt_injection", Severity: "high"}}

	row := buildReverseProxySecurityEventRow(record, "input", "security_audit_only", findings)
	if got, _ := row.MatchedSummary["access_type"].(string); got != "ai_ide" {
		t.Fatalf("matched_summary 应带 access_type, got %#v", row.MatchedSummary)
	}
	if got, _ := row.MatchedSummary["product"].(string); got != "cursor_agent" {
		t.Fatalf("matched_summary 应带 product, got %#v", row.MatchedSummary)
	}
	if got, _ := row.MatchedSummary["endpoint_kind"].(string); got != "coding" {
		t.Fatalf("matched_summary 应带 endpoint_kind, got %#v", row.MatchedSummary)
	}

	// 空值不写（与 C 路的非空才注入口径一致）。
	empty := buildReverseProxySecurityEventRow(reverseProxyAuditRecord{
		RequestID: "req-456",
		TenantID:  "tenant_default",
	}, "input", "security_audit", findings)
	for _, key := range []string{"access_type", "product", "endpoint_kind"} {
		if _, present := empty.MatchedSummary[key]; present {
			t.Fatalf("空 %s 不得写入 matched_summary: %#v", key, empty.MatchedSummary)
		}
	}
}
