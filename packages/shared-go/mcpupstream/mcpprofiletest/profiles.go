package mcpprofiletest

import "testing"

const key = "k-secret-9f3a7c21"

// pathSecretValue 含需要路径段编码的字符：斜杠、空格、百分号、井号、问号与中文。
const pathSecretValue = "tok/en 100%#?密钥"

var echoArgs = map[string]interface{}{"text": "你好"}

func caps(kv ...interface{}) map[string]interface{} {
	m := map[string]interface{}{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return m
}

// Profile 是一个命名画像：上游行为 + 针对它的接入用例。
type Profile struct {
	Name  string
	Opts  Options
	Cases func(i *Instance) []Case
}

// SecretValue 是画像统一使用的测试密钥（用于断言日志 / 错误里不得出现）。
func SecretValue() string { return key }

// PathSecretValue 返回 path-secret 画像使用的密钥（含需路径段编码的字符）。
func PathSecretValue() string { return pathSecretValue }

func okCase(name, url, transport string, c map[string]interface{}, wantTransport string) Case {
	return Case{Name: name, URL: url, Transport: transport, Caps: c, Secret: key, WantOK: true,
		WantTransport: wantTransport, WantProtocol: "2025-11-25", Tools: []string{"echo", "get_weather", "delete_all"},
		CallTool: "echo", CallArgs: echoArgs, WantCallText: "echo: 你好"}
}

// All 返回全部画像。
func All() []Profile {
	return []Profile{
		{Name: "amap-style", Opts: Options{Name: "amap", StreamablePath: "/mcp", SSEPath: "/sse", Version: "2025-11-25",
			StreamAuth: AuthSpec{Mode: "query", Name: "key", Template: "{secret}", Secret: key, Unauth: "amap"},
			SSEAuth:    AuthSpec{Mode: "query", Name: "key", Template: "{secret}", Secret: key, Unauth: "amap"}},
			Cases: func(i *Instance) []Case {
				q := caps("upstream_auth_location", "query", "upstream_auth_query_param", "key")
				return []Case{
					okCase("query-key-streamable", i.URL()+"/mcp", "auto", q, "streamable_http"),
					okCase("query-key-sse", i.URL()+"/sse", "auto", q, "sse"),
					{Name: "unauth-200-business-error", URL: i.URL() + "/mcp", Transport: "streamable_http",
						Caps: caps(), Secret: "", WantKind: "not_jsonrpc", WantMsg: "HTTP 200 但不是合法 JSON-RPC（疑似鉴权失败）"},
				}
			}},
		{Name: "zhipu-style", Opts: Options{Name: "zhipu", Prefix: "/api/mcp/web_search", StreamablePath: "/mcp", SSEPath: "/sse", Version: "2025-06-18",
			StreamAuth: AuthSpec{Mode: "header", Name: "Authorization", Template: "Bearer {secret}", Secret: key, Unauth: "zhipu"},
			SSEAuth:    AuthSpec{Mode: "query", Name: "Authorization", Template: "{secret}", Secret: key, Unauth: "zhipu"}},
			Cases: func(i *Instance) []Case {
				p := i.URL() + "/api/mcp/web_search"
				c1 := okCase("mcp-bearer-header", p+"/mcp", "auto", caps(), "streamable_http")
				c1.WantProtocol = "2025-06-18"
				c2 := okCase("sse-query-authorization", p+"/sse", "auto", caps("upstream_auth_location", "query", "upstream_auth_query_param", "Authorization"), "sse")
				c2.WantProtocol = "2025-06-18"
				return []Case{c1, c2,
					{Name: "unauth-200-code-1001", URL: p + "/mcp", Transport: "auto", Caps: caps(), Secret: "", WantKind: "not_jsonrpc", WantMsg: "疑似鉴权失败"}}
			}},
		{Name: "baidu-appbuilder-style", Opts: Options{Name: "baidu", Prefix: "/v2/ai_search/mcp", SSEPath: "/sse", Version: "2025-03-26",
			SSEAuth: AuthSpec{Mode: "query", Name: "api_key", Template: "Bearer {secret}", Secret: key, Unauth: "plain401"}},
			Cases: func(i *Instance) []Case {
				c := okCase("api_key=Bearer-value", i.URL()+"/v2/ai_search/mcp/sse", "sse",
					caps("upstream_auth_location", "query", "upstream_auth_query_param", "api_key", "upstream_auth_template", "Bearer {secret}"), "sse")
				c.WantProtocol = "2025-03-26"
				return []Case{c}
			}},
		{Name: "dashscope-style", Opts: Options{Name: "dashscope", Prefix: "/api/v1/mcps/WebSearch", StreamablePath: "/mcp", SSEPath: "/sse", Version: "2025-06-18",
			StreamAuth: AuthSpec{Mode: "header", Name: "Authorization", Template: "Bearer {secret}", Secret: key, Unauth: "dashscope"},
			SSEAuth:    AuthSpec{Mode: "header", Name: "Authorization", Template: "Bearer {secret}", Secret: key, Unauth: "dashscope"}},
			Cases: func(i *Instance) []Case {
				p := i.URL() + "/api/v1/mcps/WebSearch"
				c1 := okCase("mcp", p+"/mcp", "auto", caps(), "streamable_http")
				c1.WantProtocol = "2025-06-18"
				c2 := okCase("sse", p+"/sse", "auto", caps(), "sse")
				c2.WantProtocol = "2025-06-18"
				return []Case{c1, c2,
					{Name: "unauth-401-private-json", URL: p + "/mcp", Transport: "streamable_http", Caps: caps(), Secret: "",
						WantKind: "http_401", WantMsg: "InvalidApiKey"}}
			}},
		{Name: "legacy-sse-relative-endpoint", Opts: Options{Name: "legacy-rel", SSEPath: "/sse", Version: "2024-11-05", Endpoint: "relative"},
			Cases: func(i *Instance) []Case {
				c := okCase("relative", i.URL()+"/sse", "sse", caps(), "sse")
				c.Secret, c.WantProtocol = "", "2024-11-05"
				return []Case{c}
			}},
		{Name: "legacy-sse-absolute-endpoint", Opts: Options{Name: "legacy-abs", SSEPath: "/sse", Version: "2024-11-05", Endpoint: "absolute"},
			Cases: func(i *Instance) []Case {
				c := okCase("absolute", i.URL()+"/sse", "sse", caps(), "sse")
				c.Secret, c.WantProtocol = "", "2024-11-05"
				return []Case{c}
			}},
		{Name: "legacy-sse-cross-origin-endpoint", Opts: Options{Name: "legacy-x", SSEPath: "/sse", Version: "2024-11-05", Endpoint: "crossorigin"},
			Cases: func(i *Instance) []Case {
				return []Case{{Name: "cross-origin-must-reject", URL: i.URL() + "/sse", Transport: "sse", Caps: caps(),
					WantKind: "cross_origin", WantMsg: "不同源"}}
			}},
		{Name: "heartbeat-and-comments", Opts: Options{Name: "heartbeat", SSEPath: "/sse", Version: "2025-03-26", Heartbeat: true, Endpoint: "relative"},
			Cases: func(i *Instance) []Case {
				c := okCase("comments-crlf-multiline", i.URL()+"/sse", "sse", caps(), "sse")
				c.Secret, c.WantProtocol = "", "2025-03-26"
				return []Case{c}
			}},
		{Name: "sse-ping-events", Opts: Options{Name: "ping", SSEPath: "/sse", Version: "2025-03-26", Endpoint: "relative", PingEvents: true},
			Cases: func(i *Instance) []Case {
				c := okCase("upstream-ping-events", i.URL()+"/sse", "sse", caps(), "sse")
				c.Secret, c.WantProtocol = "", "2025-03-26"
				return []Case{c}
			}},
		{Name: "sse-future-version", Opts: Options{Name: "sse-future", SSEPath: "/sse", Version: "2099-01-01", Endpoint: "relative"},
			Cases: func(i *Instance) []Case {
				c := okCase("sse-future-version", i.URL()+"/sse", "sse", caps(), "sse")
				c.Secret, c.WantProtocol, c.WantRawProto = "", "2025-11-25", "2099-01-01"
				return []Case{c}
			}},
		{Name: "sse-ancient-version", Opts: Options{Name: "sse-ancient", SSEPath: "/sse", Version: "1999-01-01", Endpoint: "relative"},
			Cases: func(i *Instance) []Case {
				return []Case{{Name: "sse-ancient-version", URL: i.URL() + "/sse", Transport: "sse", Caps: caps(),
					WantKind: "protocol_version", WantMsg: "MCP 协议版本不受支持"}}
			}},
		// path-secret：密钥在 URL 路径中（形如 https://x.com/mcp/<token>/sse）。
		// 密钥含需要路径段编码的字符（空格、斜杠、百分号、中文），用于验证替换值做了路径段编码。
		{Name: "path-secret", Opts: Options{Name: "pathsecret", Prefix: "/mcp/", StreamablePath: "/mcp", SSEPath: "/sse", Version: "2025-06-18",
			PathSecret: pathSecretValue, Endpoint: "relative"},
			Cases: func(i *Instance) []Case {
				c1 := okCase("path-secret-streamable", i.URL()+"/mcp/{secret}/mcp", "auto", caps("upstream_auth_location", "path"), "streamable_http")
				c1.Secret, c1.WantProtocol = pathSecretValue, "2025-06-18"
				c2 := okCase("path-secret-sse", i.URL()+"/mcp/{secret}/sse", "auto", caps("upstream_auth_location", "path"), "sse")
				c2.Secret, c2.WantProtocol = pathSecretValue, "2025-06-18"
				bad := Case{Name: "path-secret-wrong", URL: i.URL() + "/mcp/{secret}/mcp", Transport: "streamable_http",
					Caps: caps("upstream_auth_location", "path"), Secret: "wrong/secret 1", WantKind: "http_401", WantMsg: "HTTP 401"}
				return []Case{c1, c2, bad}
			}},
		{Name: "streamable-mixed", Opts: Options{Name: "mixed", StreamablePath: "/mcp", Version: "2025-11-25", Mixed: true},
			Cases: func(i *Instance) []Case {
				c := okCase("json-charset+sse-call+mixed-session-id+initialized-404", i.URL()+"/mcp", "streamable_http", caps(), "streamable_http")
				c.Secret = ""
				return []Case{c}
			}},
		{Name: "version-skew-future", Opts: Options{Name: "skew", StreamablePath: "/mcp", Version: "2099-01-01"},
			Cases: func(i *Instance) []Case {
				c := okCase("future-version-accepted", i.URL()+"/mcp", "streamable_http", caps(), "streamable_http")
				c.Secret, c.WantProtocol, c.WantRawProto = "", "2025-11-25", "2099-01-01"
				return []Case{c}
			}},
		{Name: "version-skew-oldest", Opts: Options{Name: "skew-old", StreamablePath: "/mcp", Version: "2024-11-05"},
			Cases: func(i *Instance) []Case {
				c := okCase("oldest-supported-accepted", i.URL()+"/mcp", "streamable_http", caps(), "streamable_http")
				c.Secret, c.WantProtocol = "", "2024-11-05"
				return []Case{c}
			}},
		{Name: "version-skew-ancient", Opts: Options{Name: "skew-ancient", StreamablePath: "/mcp", Version: "1999-01-01"},
			Cases: func(i *Instance) []Case {
				return []Case{{Name: "ancient-version-rejected", URL: i.URL() + "/mcp", Transport: "streamable_http", Caps: caps(),
					WantKind: "protocol_version", WantMsg: "MCP 协议版本不受支持"}}
			}},
		{Name: "oauth-required", Opts: Options{Name: "oauth", StreamablePath: "/mcp", Version: "2025-06-18",
			StreamAuth: AuthSpec{Mode: "header", Name: "Authorization", Template: "Bearer {secret}", Secret: key, Unauth: "oauth"}},
			Cases: func(i *Instance) []Case {
				return []Case{{Name: "oauth-hint", URL: i.URL() + "/mcp", Transport: "auto", Caps: caps(), Secret: "",
					WantKind: "oauth_required", WantMsg: "上游要求 OAuth 2.1 授权（WWW-Authenticate resource_metadata="}}
			}},
		{Name: "pagination-weird", Opts: Options{Name: "paging", StreamablePath: "/mcp", Version: "2025-11-25", Pagination: "weird"},
			Cases: func(i *Instance) []Case {
				c := okCase("empty-page-and-repeated-cursor", i.URL()+"/mcp", "streamable_http", caps(), "streamable_http")
				c.Secret, c.Tools = "", []string{"echo", "get_weather"}
				return []Case{c}
			}},
		{Name: "plain-text-401", Opts: Options{Name: "plain", StreamablePath: "/mcp", Version: "2025-06-18",
			StreamAuth: AuthSpec{Mode: "header", Name: "Authorization", Template: "Bearer {secret}", Secret: key, Unauth: "plain401"}},
			Cases: func(i *Instance) []Case {
				return []Case{{Name: "plain-401", URL: i.URL() + "/mcp", Transport: "streamable_http", Caps: caps(), Secret: "",
					WantKind: "http_401", WantMsg: "missing required Authorization header"}}
			}},
		{Name: "header-extra", Opts: Options{Name: "extra", StreamablePath: "/mcp", Version: "2025-06-18",
			StreamAuth:     AuthSpec{Mode: "header", Name: "Authorization", Template: "Bearer {secret}", Secret: key, Unauth: "plain401"},
			RequireHeaders: map[string]string{"Stripe-Account": "acct_123"}},
			Cases: func(i *Instance) []Case {
				c := okCase("with-extra-header", i.URL()+"/mcp", "streamable_http",
					caps("upstream_extra_headers", map[string]interface{}{"Stripe-Account": "acct_123"}), "streamable_http")
				c.WantProtocol = "2025-06-18"
				return []Case{c, {Name: "missing-extra-header-rejected", URL: i.URL() + "/mcp", Transport: "streamable_http", Caps: caps(), Secret: key,
					WantKind: "http_403", WantMsg: "403"}}
			}},
		{Name: "modelscope-style", Opts: Options{Name: "modelscope", Prefix: "/svc-abc123", StreamablePath: "/mcp", SSEPath: "/sse", Version: "2025-03-26",
			StreamAuth: AuthSpec{Mode: "header", Name: "Authorization", Template: "Bearer {secret}", Secret: key, Optional: true},
			SSEAuth:    AuthSpec{Mode: "header", Name: "Authorization", Template: "Bearer {secret}", Secret: key, Optional: true}},
			Cases: func(i *Instance) []Case {
				c := okCase("per-server-path-optional-bearer", i.URL()+"/svc-abc123/mcp", "auto", caps(), "streamable_http")
				c.WantProtocol = "2025-03-26"
				return []Case{c}
			}},
		{Name: "legacy-qianwen-existing-corp", Opts: Options{Name: "corp-streamable", StreamablePath: "/mcp", Version: "2025-11-25",
			StreamAuth: AuthSpec{Mode: "header", Name: "Authorization", Template: "Bearer {secret}", Secret: key, Unauth: "plain401"}},
			Cases: func(i *Instance) []Case {
				// 存量 streamable_http 服务（客户现网：智慧芽 / 威科先行）：capabilities 没有任何新字段，协商 2025-11-25。
				return []Case{okCase("legacy-streamable-no-new-caps", i.URL()+"/mcp", "streamable_http", caps("protocol_version", "2025-11-25"), "streamable_http")}
			}},
	}
}

// Start 启动画像并生成用例。
func (p Profile) Start(t testing.TB) *Instance {
	t.Helper()
	inst := StartServer(t, p.Opts)
	inst.Cases = p.Cases(inst)
	return inst
}
