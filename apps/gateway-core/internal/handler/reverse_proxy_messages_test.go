package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/llmcatalog"
)

func TestGroupMessagesBySourcePreservesOrderAndSplitsCleanly(t *testing.T) {
	msgs := []aimsg.ConvMessage{
		{Role: "system", Source: aimsg.SourceSystemPrompt, Content: "SYS-A"},
		{Role: "user", Source: aimsg.SourceUser, Content: "U-OLD"},
		{Role: "system", Source: aimsg.SourceSystemPrompt, Content: "SYS-B"},
		{Role: "user", Source: aimsg.SourceUser, Content: "  "},
		{Role: "user", Source: aimsg.SourceUser, Content: "U-LATEST"},
	}
	groups := groupMessagesBySource(msgs)
	if len(groups) != 2 {
		t.Fatalf("groups = %+v", groups)
	}
	if groups[0].Source != aimsg.SourceSystemPrompt || groups[0].Content != "SYS-A\nSYS-B" {
		t.Fatalf("system 组错误: %+v", groups[0])
	}
	if groups[1].Source != aimsg.SourceUser || groups[1].Content != "U-LATEST" {
		t.Fatalf("user 组必须只保留最新非空消息: %+v", groups[1])
	}
}

func TestIsReverseProxyChatEndpoint(t *testing.T) {
	cases := []struct {
		host, path string
		want       bool
	}{
		{"api.anthropic.com", "/v1/messages", true},
		{"internal-llm.corp.local", "/compatible-mode/v1/chat/completions", true},
		{"api.openai.com", "/v1/chat/completions", true},
		{"www.doubao.com", "/static/app.js", false},
	}
	for _, tc := range cases {
		if got := isReverseProxyChatEndpoint(tc.host, tc.path); got != tc.want {
			t.Fatalf("isReverseProxyChatEndpoint(%q,%q) = %v, want %v", tc.host, tc.path, got, tc.want)
		}
	}
}

func TestMaxSecurityAction(t *testing.T) {
	if maxSecurityAction("audit", "block") != "block" || maxSecurityAction("mask", "audit") != "mask" || maxSecurityAction("block", "mask") != "block" {
		t.Fatal("动作严重度合并错误")
	}
	// audit 严于 allow：全组 allow 时合并结果必须还是 allow（不虚报 audit），任一组 audit 则整体 audit。
	if maxSecurityAction("allow", "audit") != "audit" || maxSecurityAction("allow", "allow") != "allow" {
		t.Fatal("audit/allow 档位合并错误")
	}
}

// captureEngine 起一个记录全部请求体的假 security-engine。respond 按请求体定制响应。
func captureEngine(t *testing.T, respond func(payload map[string]interface{}) string) (*httptest.Server, func() []map[string]interface{}) {
	t.Helper()
	var mu sync.Mutex
	var payloads []map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		_ = json.Unmarshal(raw, &payload)
		mu.Lock()
		payloads = append(payloads, payload)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respond(payload)))
	}))
	return server, func() []map[string]interface{} {
		mu.Lock()
		defer mu.Unlock()
		out := make([]map[string]interface{}, len(payloads))
		copy(out, payloads)
		return out
	}
}

const structuredAnthropicBody = `{"model":"claude-sonnet-4-5","system":"You are Claude Code","messages":[{"role":"user","content":"GWTEST 用户正文"},{"role":"assistant","content":"历史回答"}]}`

func newStructuredTestHandler(engine *httptest.Server) *ReverseProxyHandler {
	return &ReverseProxyHandler{tenantID: "tenant_default", securityURL: engine.URL, client: engine.Client(), runtimeConfigClient: allInspectionTestClient()}
}

func TestCheckRequestSecurityStructuredSplitsBySource(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
	engine, getPayloads := captureEngine(t, func(map[string]interface{}) string { return `{"action":"allow","findings":[]}` })
	defer engine.Close()
	h := newStructuredTestHandler(engine)
	req := httptest.NewRequest(http.MethodPost, "https://gw.local/anthropic/v1/messages", bytes.NewReader([]byte(structuredAnthropicBody)))
	decision, err := h.checkRequestSecurityStructured(context.Background(), "req-1", req, []byte(structuredAnthropicBody), "application/json", "api.anthropic.com", "/v1/messages")
	if err != nil || !decision.Allowed {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	if decision.ContentSource != "verified_user_input" {
		t.Fatalf("verified input decision source=%q, want verified_user_input", decision.ContentSource)
	}
	bySource := map[string]string{}
	for _, p := range getPayloads() {
		src, _ := p["content_source"].(string)
		content, _ := p["content"].(string)
		bySource[src] = content
	}
	if len(bySource) != 3 {
		t.Fatalf("每种协议来源必须分别送检: %#v", bySource)
	}
	if !strings.Contains(bySource["user"], "GWTEST 用户正文") || strings.Contains(bySource["user"], "You are Claude Code") {
		t.Fatalf("verified user 组内容错误: %#v", bySource)
	}
	payloads := getPayloads()
	ctxMap, _ := payloads[0]["context"].(map[string]interface{})
	if ctxMap["extraction"] != "protocol_source_security" {
		t.Fatalf("输入检测必须标记 verified content: %#v", payloads[0])
	}
}

func TestCheckRequestSecurityLegacyFlagCannotRestoreFullBodyScanning(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "")
	engine, getPayloads := captureEngine(t, func(map[string]interface{}) string { return `{"action":"allow","findings":[]}` })
	defer engine.Close()
	h := newStructuredTestHandler(engine)
	h.runtimeConfigClient = nil // default source scope, independent of legacy semantic/source flag
	req := httptest.NewRequest(http.MethodPost, "https://gw.local/anthropic/v1/messages", bytes.NewReader([]byte(structuredAnthropicBody)))
	if _, err := h.checkRequestSecurityStructured(context.Background(), "req-2", req, []byte(structuredAnthropicBody), "application/json", "api.anthropic.com", "/v1/messages"); err != nil {
		t.Fatal(err)
	}
	payloads := getPayloads()
	if len(payloads) != 1 {
		t.Fatalf("开关关闭必须保持单次整包送检: %d 次", len(payloads))
	}
	if payloads[0]["content_source"] != "user" {
		t.Fatal("legacy flag must not remove protocol provenance")
	}
	if content, _ := payloads[0]["content"].(string); content != "GWTEST 用户正文" {
		t.Fatalf("default scope must inspect latest user only: %q", content)
	}
}

func TestCheckRequestSecurityStructuredParseFailTagsFlatFallback(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
	engine, getPayloads := captureEngine(t, func(map[string]interface{}) string { return `{"action":"allow","findings":[]}` })
	defer engine.Close()
	h := newStructuredTestHandler(engine)
	body := []byte(`{"model":"x","messages":`) // 截断 JSON：chat 端点但解析失败
	req := httptest.NewRequest(http.MethodPost, "https://gw.local/v1/chat/completions", bytes.NewReader(body))
	if _, err := h.checkRequestSecurityStructured(context.Background(), "req-3", req, body, "application/json", "internal-llm.corp.local", "/v1/chat/completions"); err != nil {
		t.Fatal(err)
	}
	if payloads := getPayloads(); len(payloads) != 1 || payloads[0]["skip_semantic"] != true || payloads[0]["content_source"] != "unknown" {
		t.Fatalf("解析失败必须保留确定性扫描并明确来源未知: %#v", payloads)
	}
}

func TestCheckRequestSecurityStructuredUnknownRoleSkipsSemantic(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
	engine, getPayloads := captureEngine(t, func(map[string]interface{}) string {
		return `{"action":"allow","findings":[]}`
	})
	defer engine.Close()
	h := newStructuredTestHandler(engine)
	body := []byte(`{
	  "model":"gpt-5",
	  "messages":[
	    {"role":"custom_runtime","content":"内部 Skill 指令：必须调用，不可协商"},
	    {"role":"user","content":"继续"}
	  ]
	}`)
	req := httptest.NewRequest(http.MethodPost, "https://gw.local/v1/chat/completions", bytes.NewReader(body))
	if _, err := h.checkRequestSecurityStructured(context.Background(), "req-unknown", req, body, "application/json", "api.example.com", "/v1/chat/completions"); err != nil {
		t.Fatal(err)
	}
	payloads := getPayloads()
	if len(payloads) != 2 || payloads[0]["content_source"] != "unknown" || payloads[1]["content_source"] != aimsg.SourceUser {
		t.Fatalf("未知来源不能免检: %#v", payloads)
	}
	if strings.Contains(payloads[1]["content"].(string), "内部 Skill") {
		t.Fatal("sources mixed")
	}

}

func TestCheckRequestSecurityStructuredBlockMergesFromAnyGroup(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
	engine, _ := captureEngine(t, func(payload map[string]interface{}) string {
		if payload["content_source"] == "user" {
			return `{"action":"block","findings":[{"type":"prompt_injection","severity":"high"}]}`
		}
		return `{"action":"allow","findings":[]}`
	})
	defer engine.Close()
	h := newStructuredTestHandler(engine)
	req := httptest.NewRequest(http.MethodPost, "https://gw.local/anthropic/v1/messages", bytes.NewReader([]byte(structuredAnthropicBody)))
	decision, err := h.checkRequestSecurityStructured(context.Background(), "req-4", req, []byte(structuredAnthropicBody), "application/json", "api.anthropic.com", "/v1/messages")
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || decision.Action != "block" || len(decision.Findings) == 0 {
		t.Fatalf("任一组 block 必须合并为整体 block: %+v", decision)
	}
}

func TestCheckRequestSecurityStructuredMaskFallsBackToFullBody(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
	engine, getPayloads := captureEngine(t, func(map[string]interface{}) string {
		return `{"action":"mask","masked_content":"MASKED-USER","findings":[{"type":"pii_phone","severity":"medium"}]}`
	})
	defer engine.Close()
	h := newStructuredTestHandler(engine)
	req := httptest.NewRequest(http.MethodPost, "https://gw.local/anthropic/v1/messages", bytes.NewReader([]byte(structuredAnthropicBody)))
	decision, err := h.checkRequestSecurityStructured(context.Background(), "req-5", req, []byte(structuredAnthropicBody), "application/json", "api.anthropic.com", "/v1/messages")
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != "audit" || string(decision.Body) != structuredAnthropicBody || !decision.Allowed {
		t.Fatalf("verified projection mask 不得伪称整包已改写: %+v", decision)
	}
	last := getPayloads()[1]
	if last["content_source"] != aimsg.SourceUser || last["skip_semantic"] == true {
		t.Fatalf("verified user 检测不得回退 unknown/raw: %#v", last)
	}
}

func TestCheckRequestSecurityStructuredErrorFallbackSkipsSemantic(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
	var calls int
	engine, getPayloads := captureEngine(t, func(payload map[string]interface{}) string {
		calls++
		if calls == 1 {
			return `{"action":`
		}
		return `{"action":"allow","findings":[]}`
	})
	defer engine.Close()
	h := newStructuredTestHandler(engine)
	req := httptest.NewRequest(http.MethodPost, "https://gw.local/anthropic/v1/messages", bytes.NewReader([]byte(structuredAnthropicBody)))
	decision, err := h.checkRequestSecurityStructured(
		context.Background(), "req-error-fallback", req, []byte(structuredAnthropicBody),
		"application/json", "api.anthropic.com", "/v1/messages",
	)
	if err != nil || !decision.Allowed || decision.SemanticStatus != "incomplete" {
		t.Fatalf("默认fail-open必须携带未完成状态: %+v %v", decision, err)
	}
	if payloads := getPayloads(); len(payloads) != 3 {
		t.Fatalf("部分来源失败不能跳过剩余检测: %#v", payloads)
	}

}

func TestInferReverseProxyAgentTypePropagatesHeaderConflict(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Header["X-JJDGuard-Agent-Type"] = []string{"agent-new-canary"}
	req.Header["X-NewAPI-Agent-Type"] = []string{"agent-old-canary"}
	got, err := inferReverseProxyAgentType(req, llmcatalog.MatchResult{}, nil, nil)
	if got != "" || err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatalf("got=%q err=%v", got, err)
	}
}
