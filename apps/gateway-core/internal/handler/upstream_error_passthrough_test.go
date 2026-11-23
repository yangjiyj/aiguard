package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

func upstreamAnthropicBody(errType, message string) []byte {
	raw, _ := json.Marshal(map[string]any{"type": "error", "error": map[string]any{"type": errType, "message": message}})
	return raw
}

func TestClientUpstreamErrorMessage(t *testing.T) {
	const generic = "upstream Messages request failed"
	long := strings.Repeat("字", 1500)
	cases := []struct {
		name      string
		err       *provider.UpstreamHTTPError
		want      string // 精确匹配；空串表示改用 check
		check     func(t *testing.T, got string)
		wantGener bool
	}{
		{name: "nil", err: nil, wantGener: true},
		{name: "4xx带message原文透传", err: &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", `"thinking.type.disabled" is not supported for this model. Use "thinking.type.adaptive" and "output_config.effort" to control thinking behavior.`)},
			want: `"thinking.type.disabled" is not supported for this model. Use "thinking.type.adaptive" and "output_config.effort" to control thinking behavior.`},
		{name: "429不透传_白名单只放400/404/413/422", err: &provider.UpstreamHTTPError{StatusCode: 429, Body: upstreamAnthropicBody("rate_limit_error", "Number of request tokens has exceeded your per-minute rate limit")}, want: "上游请求过于频繁，请稍后重试"},
		{name: "402不透传", err: &provider.UpstreamHTTPError{StatusCode: 402, Body: upstreamAnthropicBody("billing_error", "payment required")}, want: "上游账号额度不足，请联系管理员"},
		{name: "404透传", err: &provider.UpstreamHTTPError{StatusCode: 404, Body: upstreamAnthropicBody("not_found_error", "model: claude-opus-9 not found")}, want: "model: claude-opus-9 not found"},
		{name: "413透传", err: &provider.UpstreamHTTPError{StatusCode: 413, Body: upstreamAnthropicBody("request_too_large", "Request exceeds the maximum allowed number of bytes")}, want: "Request exceeds the maximum allowed number of bytes"},
		{name: "422透传", err: &provider.UpstreamHTTPError{StatusCode: 422, Body: upstreamAnthropicBody("invalid_request_error", "field required: messages")}, want: "field required: messages"},
		{name: "5xx返回中文解释", err: &provider.UpstreamHTTPError{StatusCode: 500, Body: upstreamAnthropicBody("api_error", "internal boom 10.1.2.3")}, want: "上游服务暂时不可用、超时或过载，请稍后重试"},
		{name: "502返回中文解释", err: &provider.UpstreamHTTPError{StatusCode: 502, Body: upstreamAnthropicBody("api_error", "bad gateway")}, want: "上游服务暂时不可用、超时或过载，请稍后重试"},
		{name: "401说的是网关自己的上游凭据_不透传", err: &provider.UpstreamHTTPError{StatusCode: 401, Body: upstreamAnthropicBody("authentication_error", "invalid x-api-key")}, want: "上游凭据无效，请联系管理员"},
		{name: "403不透传", err: &provider.UpstreamHTTPError{StatusCode: 403, Body: upstreamAnthropicBody("permission_error", "organization disabled")}, want: "上游模型不存在或无访问权限，请联系管理员"},
		{name: "无body", err: &provider.UpstreamHTTPError{StatusCode: 400}, wantGener: true},
		{name: "body不是JSON_不把原始正文给客户端", err: &provider.UpstreamHTTPError{StatusCode: 400, Body: []byte("<html>upstream-lb-7 at 10.0.0.9</html>"), Message: "<html>upstream-lb-7 at 10.0.0.9</html>"}, wantGener: true},
		{name: "JSON里没有message", err: &provider.UpstreamHTTPError{StatusCode: 400, Body: []byte(`{"error":{"type":"invalid_request_error"}}`)}, wantGener: true},
		{name: "只有Message没有Body_不透传", err: &provider.UpstreamHTTPError{StatusCode: 400, Message: "from somewhere"}, wantGener: true},
		{name: "OpenAI形态error.message", err: &provider.UpstreamHTTPError{StatusCode: 400, Body: []byte(`{"error":{"message":"invalid model: model not found","type":"invalid_request_error"}}`)},
			want: "invalid model: model not found"},
		{name: "超长message截断到1000字符", err: &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", long)},
			check: func(t *testing.T, got string) {
				if !utf8.ValidString(got) {
					t.Fatalf("截断后不是合法 UTF-8")
				}
				runes := []rune(got)
				if len(runes) > 1000 || !strings.HasSuffix(got, "...") || len(runes) < 900 {
					t.Fatalf("截断不对: runes=%d suffix=%q", len(runes), string([]rune(got)[len(runes)-3:]))
				}
			}},
		{name: "换行和制表符压成空格", err: &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", "line1\nline2\t\"x\"")}, want: `line1 line2 "x"`},
		{name: "URL被去掉", err: &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", "bad request, see https://api.internal.example.com:8443/v1/messages?key=abc and http://10.1.2.3:9000/x for details")},
			check: func(t *testing.T, got string) {
				for _, leak := range []string{"api.internal.example.com", "10.1.2.3", "8443", "http://", "https://", "key=abc"} {
					if strings.Contains(got, leak) {
						t.Fatalf("泄露 %q: %s", leak, got)
					}
				}
				if !strings.Contains(got, "bad request, see") || !strings.Contains(got, "for details") {
					t.Fatalf("非敏感文字应保留: %s", got)
				}
			}},
		{name: "密钥样式串被去掉", err: &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", "invalid key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 or Bearer abcdefghijklmnop1234 or AKIAABCDEFGHIJKLMNOP or eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0NTY3.SflKxwRJSMeKKF2QT4 or 0123456789abcdef0123456789abcdef")},
			check: func(t *testing.T, got string) {
				for _, leak := range []string{"sk-ant-api03", "abcdefghijklmnop1234", "AKIAABCDEFGHIJKLMNOP", "eyJhbGci", "0123456789abcdef0123456789abcdef"} {
					if strings.Contains(got, leak) {
						t.Fatalf("泄露 %q: %s", leak, got)
					}
				}
			}},
		{name: "内网地址和内部主机名被去掉", err: &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", "connect to 192.168.31.5:8080 failed; resolved relay.corp:443 and localhost:9000")},
			check: func(t *testing.T, got string) {
				for _, leak := range []string{"192.168.31.5", "relay.corp", "localhost:9000", ":8080"} {
					if strings.Contains(got, leak) {
						t.Fatalf("泄露 %q: %s", leak, got)
					}
				}
			}},
		{name: "正常内容不被误伤", err: &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", "max_tokens: 200000 > 128000, which is the maximum allowed number of output tokens for claude-opus-4-8; messages.0: use the top-level 'system' parameter for the initial system prompt")},
			want: "max_tokens: 200000 > 128000, which is the maximum allowed number of output tokens for claude-opus-4-8; messages.0: use the top-level 'system' parameter for the initial system prompt"},
		{name: "Claude Code版本过低给中文提示并保留上游原文", err: &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", "Claude Code 2.1.241 does not support this model; version 2.1.280 or newer is required")},
			want: "当前 Claude Code 版本 2.1.241 不支持该模型，请升级到 2.1.280 或更高版本（上游原文：Claude Code 2.1.241 does not support this model; version 2.1.280 or newer is required）"},
		{name: "Claude Code旧版本2.1.205同样处理", err: &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", "Claude Code 2.1.205 does not support this model; version 2.1.280 or newer is required")},
			check: func(t *testing.T, got string) {
				if !strings.HasPrefix(got, "当前 Claude Code 版本 2.1.205 不支持该模型，请升级到 2.1.280 或更高版本") {
					t.Fatalf("got %s", got)
				}
			}},
		{name: "版本提示只在4xx生效", err: &provider.UpstreamHTTPError{StatusCode: 500, Body: upstreamAnthropicBody("api_error", "Claude Code 2.1.241 does not support this model; version 2.1.280 or newer is required")}, want: "上游服务暂时不可用、超时或过载，请稍后重试"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := clientUpstreamErrorMessage(tc.err, generic)
			switch {
			case tc.wantGener:
				if got != generic {
					t.Fatalf("got %q, want generic %q", got, generic)
				}
			case tc.check != nil:
				tc.check(t, got)
			default:
				if got != tc.want {
					t.Fatalf("got %q\nwant %q", got, tc.want)
				}
			}
		})
	}
}

func decodeAnthropicError(t *testing.T, recorder *httptest.ResponseRecorder) (errType, message, requestID string) {
	t.Helper()
	var payload struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("not JSON: %v: %s", err, recorder.Body.String())
	}
	return payload.Error.Type, payload.Error.Message, payload.RequestID
}

// 原生 /v1/messages：上游 4xx 的 message 透传给客户端，状态码与 request_id 保留，流式与非流式一致。
func TestNativeMessagesPassesThroughUpstream4xxMessage(t *testing.T) {
	upstreamMessage := `"thinking.type.disabled" is not supported for this model. Use "thinking.type.adaptive" and "output_config.effort" to control thinking behavior.`
	for _, stream := range []bool{false, true} {
		caller := &MockProviderCaller{CallError: &provider.UpstreamHTTPError{
			StatusCode: http.StatusBadRequest,
			Body:       upstreamAnthropicBody("invalid_request_error", upstreamMessage),
			Message:    upstreamMessage,
			Headers:    http.Header{"Anthropic-Request-Id": {"req_up_1"}, "Retry-After": {"3"}, "Set-Cookie": {"x=1"}},
		}}
		h := nativeMessagesTestHandler(caller, nil, nil)
		body := []byte(`{"model":"claude-opus-5","max_tokens":32,"stream":` + map[bool]string{false: "false", true: "true"}[stream] + `,"messages":[{"role":"user","content":"hello"}]}`)
		recorder := serveNativeMessages(t, h, "/v1/messages", body, nil)

		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("stream=%t status=%d body=%s", stream, recorder.Code, recorder.Body.String())
		}
		errType, message, requestID := decodeAnthropicError(t, recorder)
		if errType != "invalid_request_error" || message != upstreamMessage {
			t.Fatalf("stream=%t type=%q message=%q", stream, errType, message)
		}
		if requestID == "" || requestID != recorder.Header().Get("X-Request-Id") {
			t.Fatalf("stream=%t request_id=%q header=%q", stream, requestID, recorder.Header().Get("X-Request-Id"))
		}
		if recorder.Header().Get("Retry-After") != "3" || recorder.Header().Get("Set-Cookie") != "" {
			t.Fatalf("headers: %v", recorder.Header())
		}
	}
}

func TestNativeMessagesUsesHintFor5xxAndGenericForNetworkErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"5xx", &provider.UpstreamHTTPError{StatusCode: 500, Body: upstreamAnthropicBody("api_error", "boom at https://relay.internal:8443 key sk-abcdefghijklmnopqrstuvwxyz")}, 500},
		{"overloaded529", &provider.UpstreamHTTPError{StatusCode: 529, Body: upstreamAnthropicBody("overloaded_error", "Overloaded")}, 529},
		{"网络错误", &netErrorForTest{}, 502},
		{"4xx无body", &provider.UpstreamHTTPError{StatusCode: 400}, 400},
	}
	for _, tc := range cases {
		caller := &MockProviderCaller{CallError: tc.err}
		h := nativeMessagesTestHandler(caller, nil, nil)
		recorder := serveNativeMessages(t, h, "/v1/messages", []byte(`{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`), nil)
		if recorder.Code != tc.want {
			t.Fatalf("%s: status=%d body=%s", tc.name, recorder.Code, recorder.Body.String())
		}
		_, message, _ := decodeAnthropicError(t, recorder)
		wantMessage := "upstream Messages request failed"
		if tc.want >= 500 && tc.name != "网络错误" {
			wantMessage = "上游服务暂时不可用、超时或过载，请稍后重试"
		}
		if message != wantMessage {
			t.Fatalf("%s: message=%q", tc.name, message)
		}
		for _, leak := range []string{"relay.internal", "sk-abc", "boom", "connection refused"} {
			if strings.Contains(recorder.Body.String(), leak) {
				t.Fatalf("%s: leaked %q: %s", tc.name, leak, recorder.Body.String())
			}
		}
	}
}

type netErrorForTest struct{}

func (*netErrorForTest) Error() string { return "dial tcp 10.0.0.1:443: connection refused" }

func TestNativeMessagesClaudeCodeTooOldGetsChineseHint(t *testing.T) {
	upstream := "Claude Code 2.1.241 does not support this model; version 2.1.280 or newer is required"
	caller := &MockProviderCaller{CallError: &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", upstream)}}
	h := nativeMessagesTestHandler(caller, nil, nil)
	recorder := serveNativeMessages(t, h, "/v1/messages", []byte(`{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`), nil)
	if recorder.Code != 400 {
		t.Fatalf("status=%d", recorder.Code)
	}
	_, message, _ := decodeAnthropicError(t, recorder)
	if !strings.Contains(message, "当前 Claude Code 版本 2.1.241 不支持该模型，请升级到 2.1.280 或更高版本") || !strings.Contains(message, upstream) {
		t.Fatalf("message=%q", message)
	}
}

// chat/completions 等共用 writeUpstreamErrorResponse 的路径与原生路径口径一致。
func TestWriteUpstreamErrorResponseUsesSameCaliber(t *testing.T) {
	cases := []struct {
		name    string
		err     *provider.UpstreamHTTPError
		status  int
		message string
	}{
		{"顶层上下文错误", &provider.UpstreamHTTPError{StatusCode: 400, Body: []byte(`{"message":"prompt is too long: 1002476 tokens > 1000000 maximum"}`)}, 400, "prompt is too long: 1002476 tokens > 1000000 maximum"},
		{"额度只返回解释", &provider.UpstreamHTTPError{StatusCode: 402, Body: []byte(`{"message":"insufficient quota balance for org-secret"}`)}, 402, "上游账号额度不足，请联系管理员"},
		{"4xx透传", &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", "tools.3.custom.input_schema: maxItems is not supported")}, 400, "tools.3.custom.input_schema: maxItems is not supported"},
		{"5xx中文解释", &provider.UpstreamHTTPError{StatusCode: 503, Body: upstreamAnthropicBody("api_error", "down at 10.1.1.1")}, 503, "上游服务暂时不可用、超时或过载，请稍后重试"},
		{"无body通用", &provider.UpstreamHTTPError{StatusCode: 400}, 400, "upstream request failed"},
		{"含URL去URL", &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", "bad: https://x.internal/y")}, 400, "bad: <url>"},
		{"版本过低", &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", "Claude Code 2.1.241 does not support this model; version 2.1.280 or newer is required")}, 400,
			"当前 Claude Code 版本 2.1.241 不支持该模型，请升级到 2.1.280 或更高版本（上游原文：Claude Code 2.1.241 does not support this model; version 2.1.280 or newer is required）"},
	}
	for _, tc := range cases {
		recorder := httptest.NewRecorder()
		writeUpstreamErrorResponse(recorder, tc.err, "req-same-1", "upstream_response")
		if recorder.Code != tc.status {
			t.Fatalf("%s: status=%d", tc.name, recorder.Code)
		}
		var payload ErrorResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("%s: %v: %s", tc.name, err, recorder.Body.String())
		}
		if payload.Error.Message != tc.message || payload.Error.Code != "upstream_error" || payload.Error.RequestID != "req-same-1" ||
			payload.Error.Stage != "upstream_response" || payload.Error.UpstreamStatus != tc.status {
			t.Fatalf("%s: %+v", tc.name, payload.Error)
		}
		if recorder.Header().Get("X-Request-ID") != "req-same-1" || recorder.Header().Get("X-JJDGuard-Error-Stage") != "upstream_response" {
			t.Fatalf("%s: headers=%v", tc.name, recorder.Header())
		}
	}
}

// 原文透传仍只允许白名单，其余状态返回中文解释。
func TestClientUpstreamErrorMessageStatusAllowlist(t *testing.T) {
	const generic = "upstream request failed"
	body := upstreamAnthropicBody("invalid_request_error", "plain problem with field x")
	for _, status := range []int{400, 404, 413, 422} {
		if got := clientUpstreamErrorMessage(&provider.UpstreamHTTPError{StatusCode: status, Body: body}, generic); got != "plain problem with field x" {
			t.Errorf("status %d 应透传, got %q", status, got)
		}
	}
	for _, status := range []int{401, 402, 403, 405, 406, 408, 409, 410, 415, 418, 424, 429, 431, 451, 499, 500, 502, 503, 529} {
		want := "请求参数不受上游模型支持，请检查参数后重试"
		switch status {
		case 401:
			want = "上游凭据无效，请联系管理员"
		case 402:
			want = "上游账号额度不足，请联系管理员"
		case 403:
			want = "上游模型不存在或无访问权限，请联系管理员"
		case 429:
			want = "上游请求过于频繁，请稍后重试"
		case 408:
			want = "上游服务暂时不可用、超时或过载，请稍后重试"
		}
		if status >= 500 {
			want = "上游服务暂时不可用、超时或过载，请稍后重试"
		}
		if got := clientUpstreamErrorMessage(&provider.UpstreamHTTPError{StatusCode: status, Body: body}, generic); got != want {
			t.Errorf("status %d 应返回中文解释 %q, got %q", status, want, got)
		}
	}
}

// 账号类原文仍不透传，但客户端必须获得可理解的中文解释。
func TestClientUpstreamErrorMessageUsesHintsForSensitiveWords(t *testing.T) {
	const generic = "upstream request failed"
	messages := []string{
		// 审查给出的样例
		"Your credit balance is too low to access the Anthropic API. Please go to Plans & Billing to upgrade or purchase credits.",
		"该令牌额度已用尽 remain quota: ¥0.12",
		"API key not valid. Please pass a valid API key.",
		// 清单里的每个词各一条，并混合大小写
		"the api key is wrong", "bad API_KEY value", "missing apikey header", "insufficient credit", "account Balance too low",
		"exceeded QUOTA for this minute", "see billing settings", "This Organization has been disabled", "账户余额不足", "额度不足", "令牌无效", "已欠费，请充值", "请先充值",
	}
	for _, message := range messages {
		for _, status := range []int{400, 404, 413, 422} {
			err := &provider.UpstreamHTTPError{StatusCode: status, Body: upstreamAnthropicBody("invalid_request_error", message)}
			want := "上游账号额度不足，请联系管理员"
			lower := strings.ToLower(message)
			if strings.Contains(lower, "api") && !strings.Contains(lower, "balance") || strings.Contains(message, "令牌无效") {
				want = "上游凭据无效，请联系管理员"
			}
			if strings.Contains(lower, "organization") {
				want = "上游模型不存在或无访问权限，请联系管理员"
			}
			if strings.Contains(lower, "for this minute") {
				want = "上游请求过于频繁，请稍后重试"
			}
			if got := clientUpstreamErrorMessage(err, generic); got != want {
				t.Errorf("status %d 中文解释应为 %q: %q -> %q", status, want, message, got)
			}
		}
	}
	// 不含这些词的正常报错不受影响（包含 tokens 这个词本身不算命中）
	ok := &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", "max_tokens: 200000 > 128000, which is the maximum allowed number of output tokens")}
	if got := clientUpstreamErrorMessage(ok, generic); got == generic {
		t.Errorf("正常 max_tokens 报错不应被误拦")
	}
}

// 审查要求 3：补强净化，并证明不会误伤模型名、版本号、字段路径。
func TestClientUpstreamErrorMessageSanitizesReviewSamples(t *testing.T) {
	const generic = "upstream request failed"
	leakCases := []struct {
		name, message string
		leaks         []string
		wantContains  []string
	}{
		{"org前缀28位", "invalid request for org-AbCdEfGhIjKlMnOpQrStUvWxYz12 today", []string{"org-AbCd", "AbCdEfGhIjKlMnOpQrStUvWxYz12"}, []string{"invalid request for", "today"}},
		{"proj前缀短串", "project proj-a1b2c3 not found", []string{"proj-a1b2c3"}, []string{"project", "not found"}},
		{"sk-ant短串", "rejected sk-ant-x1 as input", []string{"sk-ant-x1"}, []string{"rejected", "as input"}},
		{"sk短串", "got sk-abc in header", []string{"sk-abc"}, []string{"got", "in header"}},
		{"点分主机名不带端口", "dial tcp: lookup relay.internal.corp on 10.0.0.2:53: no such host", []string{"relay.internal.corp", "10.0.0.2"}, []string{"lookup <host>", "no such host"}},
		{"IPv6方括号带端口", "connect to [fd00::12]:8443 refused", []string{"fd00", "8443"}, []string{"connect to", "refused"}},
		{"IPv6裸地址", "peer 2001:db8::1 and fe80::1 and 2001:0db8:0000:0000:0000:ff00:0042:8329 and ::1 gone", []string{"2001:db8", "fe80", "ff00:0042", "::1"}, []string{"peer", "gone"}},
		{"AWS ARN", "not authorized: arn:aws:iam::123456789012:role/x cannot assume", []string{"123456789012", "arn:aws", "role/x"}, []string{"not authorized", "cannot assume"}},
		{"AWS ARN中国区", "denied on arn:aws-cn:s3:::my-bucket/path ok", []string{"arn:aws", "my-bucket"}, []string{"denied on", "ok"}},
	}
	for _, tc := range leakCases {
		t.Run(tc.name, func(t *testing.T) {
			got := clientUpstreamErrorMessage(&provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", tc.message)}, generic)
			if got == generic {
				t.Fatalf("不应回退通用文案（应净化后透传）: %q", tc.message)
			}
			for _, leak := range tc.leaks {
				if strings.Contains(got, leak) {
					t.Errorf("泄露 %q: %s", leak, got)
				}
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("应保留 %q: %s", want, got)
				}
			}
		})
	}
}

// 净化不得误伤：模型名、版本号、时间、字段路径、普通英文缩写都必须原样保留。
func TestClientUpstreamErrorMessageSanitizerKeepsModelNamesVersionsAndFieldPaths(t *testing.T) {
	const generic = "upstream request failed"
	benign := []string{
		"model claude-opus-4-8 and claude-sonnet-5-5 and claude-3.5-sonnet and anthropic/claude-haiku-5-5 are not allowed here",
		"gpt-4.1 at 12:30:45 needs version 1.2.3 (or 2.1.280 or newer)",
		`"thinking.type.disabled" is not supported for this model. Use "thinking.type.adaptive" and "output_config.effort" to control thinking behavior.`,
		"tools.3.custom.input_schema: maxItems is not supported; messages.0: use the top-level 'system' parameter",
		"see e.g. std::vector in task-1 or disk-full state",
		"max_tokens: 200000 > 128000, which is the maximum allowed number of output tokens for claude-opus-4-8",
	}
	for _, message := range benign {
		got := clientUpstreamErrorMessage(&provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", message)}, generic)
		if got != message {
			t.Errorf("被误伤:\n  in=%q\n out=%q", message, got)
		}
	}
}

// 原生端点对账号错误仅返回中文解释，状态码与 request_id 保留。
func TestNativeMessagesReviewCasesUseChineseHints(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		message string
	}{
		{"401凭据", 401, "API key not valid"},
		{"402余额", 402, "balance insufficient"},
		{"403权限", 403, "permission denied for organization"},
		{"429限流", 429, "Number of request tokens has exceeded your per-minute rate limit"},
		{"400余额不足", 400, "Your credit balance is too low to access the Anthropic API. Please go to Plans & Billing."},
		{"400中文额度", 400, "该令牌额度已用尽 remain quota: ¥0.12"},
		{"400密钥无效", 400, "API key not valid. Please pass a valid API key."},
	}
	for _, tc := range cases {
		caller := &MockProviderCaller{CallError: &provider.UpstreamHTTPError{StatusCode: tc.status, Body: upstreamAnthropicBody("invalid_request_error", tc.message)}}
		h := nativeMessagesTestHandler(caller, nil, nil)
		recorder := serveNativeMessages(t, h, "/v1/messages", []byte(`{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`), nil)
		if recorder.Code != tc.status {
			t.Fatalf("%s: status=%d", tc.name, recorder.Code)
		}
		_, message, requestID := decodeAnthropicError(t, recorder)
		want := "上游账号额度不足，请联系管理员"
		if tc.status == 429 {
			want = "上游请求过于频繁，请稍后重试"
		}
		if tc.status == 403 {
			want = "上游模型不存在或无访问权限，请联系管理员"
		}
		if strings.Contains(tc.message, "API key") {
			want = "上游凭据无效，请联系管理员"
		}
		if message != want || requestID == "" {
			t.Fatalf("%s: message=%q request_id=%q", tc.name, message, requestID)
		}
		if strings.Contains(recorder.Body.String(), "credit") || strings.Contains(recorder.Body.String(), "¥0.12") || strings.Contains(recorder.Body.String(), "API key") {
			t.Fatalf("%s: 敏感文案泄露: %s", tc.name, recorder.Body.String())
		}
	}
}

// 探测补强：IPv6 带 zone（fe80::1%eth0）不能漏出网卡名；更多常见后缀的点分主机名要替换；文件名不能被当成主机名。
func TestClientUpstreamErrorMessageSanitizerZoneAndMoreSuffixes(t *testing.T) {
	const generic = "upstream request failed"
	redacted := []struct{ message, leak string }{
		{"peer fe80::1%eth0 unreachable", "eth0"},
		{"lookup relay.example.tech failed", "relay.example.tech"},
		{"lookup gw.prod.dev failed", "gw.prod.dev"},
		{"lookup api.svc.cluster.local failed", "cluster.local"},
		{"lookup node1.home.arpa failed", "home.arpa"},
		{"lookup db.example.co.uk failed", "example.co.uk"},
		{"lookup relay.example.de failed", "relay.example.de"},
	}
	for _, tc := range redacted {
		got := clientUpstreamErrorMessage(&provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", tc.message)}, generic)
		if got == generic || strings.Contains(got, tc.leak) {
			t.Errorf("应净化 %q: %q", tc.message, got)
		}
	}
	kept := []string{"edit app.js and file.py and readme.md and config.yaml and run.sh", "schema.json is invalid at foo.ts line 3"}
	for _, message := range kept {
		got := clientUpstreamErrorMessage(&provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", message)}, generic)
		if got != message {
			t.Errorf("文件名被误伤: %q -> %q", message, got)
		}
	}
}
