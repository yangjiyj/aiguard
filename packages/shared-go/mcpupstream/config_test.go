package mcpupstream

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestParseConfigLegacyDefaultsUnchanged(t *testing.T) {
	cfg, err := ParseConfig("", nil)
	if err != nil || cfg.Transport != TransportStreamableHTTP || cfg.AuthLocation != AuthHeader ||
		cfg.AuthName != "Authorization" || cfg.AuthTemplate != TemplateBearer || cfg.ExtraHeaders != nil || cfg.DetectedTransport != "" {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
	cfg, err = ParseConfig("streamable_http", map[string]interface{}{"auth_header_name": "x-mcp-token"})
	if err != nil || cfg.AuthName != "X-Mcp-Token" || cfg.AuthTemplate != TemplateRaw {
		t.Fatalf("custom header legacy: %+v err=%v", cfg, err)
	}
	// 存量未知 transport 值按 streamable_http 处理，不报错。
	cfg, err = ParseConfig("weird", nil)
	if err != nil || cfg.Transport != TransportStreamableHTTP {
		t.Fatalf("unknown transport: %+v err=%v", cfg, err)
	}
	// 存量：无密钥时头名异常不应让配置解析失败（只有注入密钥时才校验）。
	if _, err := ParseConfig("streamable_http", map[string]interface{}{"auth_header_name": "Host"}); err != nil {
		t.Fatalf("legacy bad header name without secret must still parse: %v", err)
	}
}

func TestApplyAuthRejectsForbiddenHeaderWhenSecretPresent(t *testing.T) {
	cfg, _ := ParseConfig("streamable_http", map[string]interface{}{"auth_header_name": "Host"})
	req := mustReq(t, "http://x/mcp")
	if err := ApplyAuth(req, cfg, "s3cret-value"); err == nil {
		t.Fatal("forbidden header name must be rejected when a secret is configured")
	}
}

func TestParseConfigAuthModes(t *testing.T) {
	cfg, err := ParseConfig("auto", map[string]interface{}{
		CapAuthLocation: "query", CapAuthQueryParam: "api_key", CapAuthTemplate: "Bearer {secret}",
		CapDetectedTransport: "sse",
	})
	if err != nil || cfg.AuthLocation != AuthQuery || cfg.AuthName != "api_key" || cfg.EffectiveTransport() != TransportSSE {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
	for _, bad := range []map[string]interface{}{
		{CapAuthLocation: "query"},                                        // 缺参数名
		{CapAuthLocation: "query", CapAuthQueryParam: "a b"},              // 非法参数名
		{CapAuthLocation: "body"},                                         // 未知位置
		{CapAuthTemplate: "Bearer"},                                       // 缺占位
		{CapAuthTemplate: "{secret}{secret}"},                             // 多占位
		{CapAuthTemplate: "x\r\nInjected: 1 {secret}"},                    // 头注入
		{CapExtraHeaders: map[string]interface{}{"Host": "evil"}},         // 禁用头
		{CapExtraHeaders: map[string]interface{}{"Cookie": "a=b"}},        // 禁用头
		{CapExtraHeaders: map[string]interface{}{"X-A": "a\r\nB: c"}},     // 值注入
		{CapExtraHeaders: map[string]interface{}{"Authorization": "dup"}}, // 与鉴权头重名
		{CapExtraHeaders: map[string]interface{}{"X-A": 1}},               // 非字符串
	} {
		if _, err := ParseConfig("streamable_http", bad); err == nil {
			t.Fatalf("expected error for %v", bad)
		}
	}
}

func TestSplitURLSecrets(t *testing.T) {
	clean, ex, err := SplitURLSecrets("https://mcp.amap.com/mcp?key=abc123&lang=zh")
	if err != nil || ex == nil || ex.ParamName != "key" || ex.Secret != "abc123" || ex.Template != TemplateRaw ||
		clean != "https://mcp.amap.com/mcp?lang=zh" {
		t.Fatalf("clean=%q ex=%+v err=%v", clean, ex, err)
	}
	clean, ex, err = SplitURLSecrets("https://appbuilder.baidu.com/v2/ai_search/mcp/sse?api_key=Bearer+bce-v3%2FALTAK-xyz")
	if err != nil || ex == nil || ex.ParamName != "api_key" || ex.Secret != "bce-v3/ALTAK-xyz" || ex.Template != TemplateBearer ||
		strings.Contains(clean, "?") {
		t.Fatalf("baidu: clean=%q ex=%+v err=%v", clean, ex, err)
	}
	if _, ex, _ = SplitURLSecrets("https://x.example/sse?Authorization=tok_1234"); ex == nil || ex.ParamName != "Authorization" {
		t.Fatalf("zhipu style: %+v", ex)
	}
	if _, ex, _ = SplitURLSecrets("https://x.example/mcp?route=saved"); ex != nil {
		t.Fatalf("non-secret param must stay: %+v", ex)
	}
	if _, _, err = SplitURLSecrets("https://x.example/mcp?key=a&token=b"); err == nil {
		t.Fatal("multiple secrets must be rejected")
	}
}

func TestRedaction(t *testing.T) {
	// 默认全部遮蔽；仅白名单内的已知非密钥参数（lang 等）保留原值，便于排障。
	if got := RedactURL("https://mcp.map.baidu.com/sse?ak=SECRET99&lang=zh&unknown=VAL#frag"); strings.Contains(got, "SECRET99") ||
		strings.Contains(got, "VAL") || strings.Contains(got, "frag") || !strings.Contains(got, "ak=***") || !strings.Contains(got, "lang=zh") {
		t.Fatalf("RedactURL=%q", got)
	}
	in := `{"error":"bad key=ABCDEF123456 at https://a.example/x?api_key=Bearer+TOPSECRET&q=1 header Bearer eyJhbGciOi.payload.sig"}`
	out := RedactText(in, "ABCDEF123456")
	for _, leak := range []string{"ABCDEF123456", "TOPSECRET", "eyJhbGciOi"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leak %q in %q", leak, out)
		}
	}
	long := strings.Repeat("长", 500)
	if got := Summarize([]byte(long)); len([]rune(got)) > SummaryLimit+1 {
		t.Fatalf("summary not truncated: %d", len([]rune(got)))
	}
}

func TestResolveEndpoint(t *testing.T) {
	base, _ := url.Parse("https://mcp.example.com:8443/api/sse?key=K")
	cases := []struct {
		in      string
		want    string
		wantErr string
	}{
		{"/messages?sessionId=1", "https://mcp.example.com:8443/messages?sessionId=1", ""},
		{"messages?sessionId=1", "https://mcp.example.com:8443/api/messages?sessionId=1", ""},
		{"https://mcp.example.com:8443/m?s=1", "https://mcp.example.com:8443/m?s=1", ""},
		{`{"endpoint":"/m?s=2"}`, "https://mcp.example.com:8443/m?s=2", ""},
		{"https://evil.example.com:8443/m", "", "不同源"},
		{"https://mcp.example.com/m", "", "不同源"},
		{"http://mcp.example.com:8443/m", "", "不同源"},
		{"//evil.example.com/m", "", "不同源"},
		{"https://u:p@mcp.example.com:8443/m", "", "内嵌账号"},
		{"/m#x", "", "片段"},
		{"file:///etc/passwd", "", ""},
		{"", "", "为空"},
	}
	for _, c := range cases {
		got, err := ResolveEndpoint(base, c.in)
		if c.want != "" {
			if err != nil || got.String() != c.want {
				t.Fatalf("%q => %v err=%v want %s", c.in, got, err, c.want)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%q must be rejected, got %v", c.in, got)
		}
		if c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr) {
			t.Fatalf("%q err=%v want %q", c.in, err, c.wantErr)
		}
		if strings.Contains(err.Error(), "key=K") {
			t.Fatalf("error leaks base query: %v", err)
		}
	}
}

func TestSetQueryParamMergesInsteadOfOverwriting(t *testing.T) {
	u, _ := url.Parse("https://x.example/m?sessionId=abc&key=old")
	SetQueryParam(u, "key", "new value")
	q := u.Query()
	if q.Get("sessionId") != "abc" || q.Get("key") != "new value" || strings.Count(u.RawQuery, "key=") != 1 {
		t.Fatalf("query=%q", u.RawQuery)
	}
}

func TestClassifyHTTPFailure(t *testing.T) {
	h := map[string][]string{"Www-Authenticate": {`Bearer realm="OAuth", resource_metadata="https://x/.well-known/oauth-protected-resource"`}}
	e := ClassifyHTTPFailure(401, h, nil)
	if e.Kind != KindOAuth || !strings.Contains(e.Message, "当前版本暂不支持 OAuth") {
		t.Fatalf("%+v", e)
	}
	e = ClassifyHTTPFailure(429, map[string][]string{"Retry-After": {"30"}}, []byte("slow down"))
	if e.Kind != KindHTTP429 || e.RetryAfter != "30" || !strings.Contains(e.Message, "Retry-After") {
		t.Fatalf("%+v", e)
	}
	e = ClassifyHTTPFailure(403, nil, []byte(`{"msg":"forbidden key=ZZZZ1234"}`))
	if e.Kind != KindHTTP403 || strings.Contains(e.Message, "ZZZZ1234") {
		t.Fatalf("%+v", e)
	}
}

func mustReq(t *testing.T, u string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
