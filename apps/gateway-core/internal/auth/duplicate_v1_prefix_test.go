package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
)

// 现场 P3-9：Anthropic 协议客户端的 Base URL 多写了一层 /v1，网关日志出现
// POST /v1/v1/messages 且返回 401（鉴权在路由之前）。这里锁定新的行为：
// 重复前缀在鉴权之前就返回 404 和明确提示，不转发、不查库、不自动纠正。

func duplicatePrefixHandler(t *testing.T, a *AuthMiddleware) http.Handler {
	t.Helper()
	return a.Middleware(&config.Config{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("重复前缀的请求不应到达任何下游处理器")
	}))
}

func decodeDuplicatePrefixBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是 JSON: %v body=%s", err, recorder.Body.String())
	}
	return body
}

func TestDuplicateV1PrefixReturns404WithProtocolShapedBody(t *testing.T) {
	cases := []struct {
		name, method, path, protocol string
	}{
		{"Anthropic 消息", http.MethodPost, "/v1/v1/messages", "anthropic"},
		{"Anthropic 计数", http.MethodPost, "/v1/v1/messages/count_tokens", "anthropic"},
		{"OpenAI 对话", http.MethodPost, "/v1/v1/chat/completions", "openai"},
		{"OpenAI 响应", http.MethodPost, "/v1/v1/responses", "openai"},
		{"OpenAI 向量", http.MethodPost, "/v1/v1/embeddings", "openai"},
		{"OpenAI 模型列表", http.MethodGet, "/v1/v1/models", "openai"},
		{"Gemini 原生", http.MethodPost, "/v1/v1beta/models/m:generateContent", "gemini"},
		{"只有前缀", http.MethodGet, "/v1/v1", "generic"},
		{"未知后缀", http.MethodPost, "/v1/v1/unknown", "generic"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// db 为 nil：若代码继续走密钥查询会直接 panic，因此这也证明没有查库。
			handler := duplicatePrefixHandler(t, NewAuthMiddleware(nil, nil, nil))
			request := httptest.NewRequest(tc.method, tc.path+"?probe=query-canary", nil)
			request.Header.Set("Authorization", "Bearer sk-header-canary")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusNotFound {
				t.Fatalf("status=%d, want 404 body=%s", recorder.Code, recorder.Body.String())
			}
			if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
				t.Fatalf("Content-Type=%q", got)
			}
			if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("缺少 X-Content-Type-Options: nosniff")
			}
			// 不回显请求里的任何内容：路径、查询串、凭据。
			for _, leaked := range []string{"query-canary", "sk-header-canary", tc.path} {
				if strings.Contains(recorder.Body.String(), leaked) {
					t.Fatalf("响应回显了请求内容 %q: %s", leaked, recorder.Body.String())
				}
			}

			body := decodeDuplicatePrefixBody(t, recorder)
			errorBody, _ := body["error"].(map[string]any)
			if errorBody == nil {
				t.Fatalf("缺少 error 对象: %s", recorder.Body.String())
			}
			message, _ := errorBody["message"].(string)
			if !strings.HasPrefix(message, "地址多了一层 /v1，请把 Base URL 改成") {
				t.Fatalf("提示文案不符合约定: %q", message)
			}

			switch tc.protocol {
			case "anthropic":
				if body["type"] != "error" || errorBody["type"] != "not_found_error" {
					t.Fatalf("不符合 Anthropic 错误体: %s", recorder.Body.String())
				}
				if !strings.Contains(message, "不带 /v1") || !strings.Contains(message, "ANTHROPIC_BASE_URL") {
					t.Fatalf("Anthropic 提示应说明不带 /v1: %q", message)
				}
				requestID, _ := body["request_id"].(string)
				if !strings.HasPrefix(requestID, "req_") || recorder.Header().Get("X-Request-Id") != requestID {
					t.Fatalf("request_id=%q header=%q", requestID, recorder.Header().Get("X-Request-Id"))
				}
			case "openai", "generic":
				if errorBody["code"] != "base_url_duplicate_v1_prefix" || errorBody["type"] != "invalid_request_error" {
					t.Fatalf("不符合网关通用错误体: %s", recorder.Body.String())
				}
				requestID, _ := errorBody["request_id"].(string)
				if !strings.HasPrefix(requestID, "req_") || recorder.Header().Get("X-Request-Id") != requestID {
					t.Fatalf("request_id=%q header=%q", requestID, recorder.Header().Get("X-Request-Id"))
				}
				if tc.protocol == "openai" && !strings.Contains(message, "只带一层 /v1") {
					t.Fatalf("OpenAI 提示应说明只带一层 /v1: %q", message)
				}
			case "gemini":
				if errorBody["code"] != float64(404) || errorBody["status"] != "NOT_FOUND" {
					t.Fatalf("不符合 Google 错误体: %s", recorder.Body.String())
				}
				if !strings.Contains(message, "不带 /v1") {
					t.Fatalf("Gemini 提示应说明不带 /v1: %q", message)
				}
			}
		})
	}
}

func TestDuplicateV1PrefixDoesNotCatchLegitimateRoutes(t *testing.T) {
	// 这些路径都是真实存在或属于其它入口的，必须保持原有的鉴权前置行为（缺凭据 → 401）。
	for _, path := range []string{
		"/v1/messages",
		"/v1/chat/completions",
		"/v1/models",
		"/v1/models/v1",    // 模型名恰好叫 v1
		"/v1/models/v1/v1", // 仍属于 /v1/models/{model}
		"/v1/v10/messages", // 不是 v1 段
		"/v1/V1/messages",  // 大小写不同，不当作重复前缀
		"/v1beta/models/m", // Gemini 的正确前缀
		"/v1/unknown/v1",   // v1 不在第二段
		"/v1/messages/v1/v1",
	} {
		t.Run(path, func(t *testing.T) {
			handler := duplicatePrefixHandler(t, NewAuthMiddleware(nil, nil, nil))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("%s status=%d, want 401（未携带凭据）body=%s", path, recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "多了一层 /v1") {
				t.Fatalf("%s 被误判为重复前缀: %s", path, recorder.Body.String())
			}
		})
	}
}

func TestDuplicateV1PrefixKeepsHeaderConflictAuditBeforeHint(t *testing.T) {
	// 鉴权前唯一的强制审计是「请求头冲突」。重复前缀的提示必须排在它之后，
	// 否则攻击者可借 /v1/v1/ 路径绕过这条关键审计。
	audits := 0
	auditServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		audits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer auditServer.Close()
	handler := duplicatePrefixHandler(t, NewAuthMiddleware(nil, nil, headeraudit.NewClient(auditServer.URL, "test-secret")))

	conflicting := httptest.NewRequest(http.MethodPost, "/v1/v1/messages", nil)
	conflicting.Header.Set("X-JJDGuard-Session-Id", "new-session")
	conflicting.Header.Set("X-NewAPI-Session-Id", "old-session")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, conflicting)
	if recorder.Code != http.StatusBadRequest || audits != 1 {
		t.Fatalf("头冲突应先被审计并拒绝: status=%d audits=%d body=%s", recorder.Code, audits, recorder.Body.String())
	}

	// 审计不可用时同样 fail-closed，不能因为路径重复而放行成 404。
	unavailable := duplicatePrefixHandler(t, NewAuthMiddleware(nil, nil, headeraudit.NewClient("", "")))
	conflict := httptest.NewRequest(http.MethodPost, "/v1/v1/chat/completions", nil)
	conflict.Header.Set("X-JJDGuard-Workspace-Id", "ws-new")
	conflict.Header.Set("X-NewAPI-Workspace-Id", "ws-old")
	recorder = httptest.NewRecorder()
	unavailable.ServeHTTP(recorder, conflict)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("审计不可用应 fail-closed 为 503，实际 %d body=%s", recorder.Code, recorder.Body.String())
	}

	// 没有头冲突时不产生任何审计事件，也不会因此变成 400/503。
	audits = 0
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/v1/messages", nil))
	if recorder.Code != http.StatusNotFound || audits != 0 {
		t.Fatalf("无冲突应直接 404: status=%d audits=%d", recorder.Code, audits)
	}
}

func TestClassifyDuplicateV1Prefix(t *testing.T) {
	for path, want := range map[string]string{
		"/v1/v1":                              "generic",
		"/v1/v1/":                             "generic",
		"/v1/v1/messages":                     "anthropic",
		"/v1/v1/messages/count_tokens":        "anthropic",
		"/v1/v1/chat/completions":             "openai",
		"/v1/v1/responses":                    "openai",
		"/v1/v1/embeddings":                   "openai",
		"/v1/v1/images/generations":           "openai",
		"/v1/v1/files":                        "openai",
		"/v1/v1/models/gpt":                   "openai",
		"/v1/v1beta":                          "gemini",
		"/v1/v1beta/models/m:generateContent": "gemini",
		"/v1/v1/whatever":                     "generic",
		"/v1/messages":                        "",
		"/v1":                                 "",
		"/v1/":                                "",
		"/mcp/v1/v1":                          "",
		"/v1beta/v1/v1":                       "",
	} {
		got, ok := classifyDuplicateV1Prefix(path)
		if (want == "") == ok || got != want {
			t.Errorf("classifyDuplicateV1Prefix(%q) = (%q, %v), want %q", path, got, ok, want)
		}
	}
}
