package mcpupstream_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream/mcpprofiletest"
)

const pathSecretSample = "tok/en 100%#?密钥"

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// path 鉴权位置：配置解析，保存校验要求 URL 恰好含一个 {secret}。
func TestPathAuthConfigAndSaveValidation(t *testing.T) {
	cfg, err := mcpupstream.ParseConfig("auto", map[string]interface{}{mcpupstream.CapAuthLocation: "path"})
	if err != nil || cfg.AuthLocation != mcpupstream.AuthPath || !cfg.UsesNewCapabilities {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
	for _, c := range []struct {
		url     string
		wantErr string
	}{
		{"https://x.example/mcp/{secret}/sse", ""},
		{"https://x.example/{secret}", ""},
		{"https://x.example/mcp/sse", "必须恰好包含一个 {密钥}"},
		{"https://x.example/mcp/{secret}/a/{secret}/sse", "必须恰好包含一个 {密钥}"},
		{"https://{secret}.example/mcp", "只能出现在 URL 路径"},
		{"https://x.example/mcp?k={secret}", "只能出现在 URL 路径"},
		{"https://x.example:{secret}/mcp", "只能出现在 URL 路径"},
	} {
		err := mcpupstream.ValidatePathSecretURL(c.url)
		if c.wantErr == "" && err != nil {
			t.Fatalf("%s must be valid: %v", c.url, err)
		}
		if c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
			t.Fatalf("%s want error %q, got %v", c.url, c.wantErr, err)
		}
	}
	// 非 path 模式的 URL 里不允许出现 {secret} 占位（避免被当成字面路径发往上游）。
	if err := mcpupstream.ValidateNonPathURL("https://x.example/mcp/{secret}/sse"); err == nil || !strings.Contains(err.Error(), "URL 路径") {
		t.Fatalf("a {secret} placeholder without path auth must be rejected: %v", err)
	}
	if err := mcpupstream.ValidateNonPathURL("https://x.example/mcp"); err != nil {
		t.Fatal(err)
	}
}

// 替换占位符：替换值做路径段编码；斜杠、空格、百分号、井号、问号、中文都不能破坏路径结构。
func TestSubstitutePathSecretEncodesAsSingleSegment(t *testing.T) {
	u := mustParse(t, "https://x.example/mcp/{secret}/sse")
	got, err := mcpupstream.SubstitutePathSecret(u, pathSecretSample)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/mcp/"+pathSecretSample+"/sse" {
		t.Fatalf("decoded path must hold the raw secret as ONE segment: %q", got.Path)
	}
	if got.RawQuery != "" || got.Fragment != "" {
		t.Fatalf("secret chars must not leak into query/fragment: %q %q", got.RawQuery, got.Fragment)
	}
	if strings.Count(got.EscapedPath(), "/") != 3 {
		t.Fatalf("a secret containing '/' must not add path segments: %s", got.EscapedPath())
	}
	if strings.ContainsAny(got.EscapedPath(), " #?") {
		t.Fatalf("escaped path must not contain raw space/#/?: %s", got.EscapedPath())
	}
	// 原 URL 不被改动（占位形态保持）。
	if !strings.Contains(u.String(), "%7Bsecret%7D") && !strings.Contains(u.Path, "{secret}") {
		t.Fatalf("source URL must keep the placeholder: %s", u)
	}
	// 含 ../ 的密钥不能造成路径穿越。
	got, err = mcpupstream.SubstitutePathSecret(u, "../../admin")
	if err != nil || strings.Contains(got.EscapedPath(), "/../") || got.Path != "/mcp/../../admin/sse" {
		t.Fatalf("dot segments inside a secret must stay inside one segment: %s err=%v", got.EscapedPath(), err)
	}
	if strings.Count(got.EscapedPath(), "/") != 3 {
		t.Fatalf("dot-dot secret must not add segments: %s", got.EscapedPath())
	}
}

// 展示 / 日志 / 错误信息只出现占位形式或 ***：
//   - 库里与展示的 URL 永远是占位形态，不含密钥，原样可读；
//   - 真实密钥只在请求内存里存在；万一进入文本，凭已知密钥做的脱敏必须覆盖各种编码形态。
func TestPathSecretNeverAppearsInRedactedOutput(t *testing.T) {
	secret := pathSecretSample
	if got := mcpupstream.RedactURL("https://x.example/mcp/{secret}/sse?sessionId=abc&key=Z"); !strings.Contains(got, "%7Bsecret%7D") && !strings.Contains(got, "{secret}") ||
		strings.Contains(got, "key=Z") || strings.Contains(got, "sessionId=abc") {
		t.Fatalf("placeholder URL stays readable while query values (including session ids) are masked: %s", got)
	}
	real := "https://x.example/mcp/" + url.PathEscape(secret) + "/sse?sessionId=abc"
	for _, form := range []string{secret, url.PathEscape(secret), url.QueryEscape(secret), url.PathEscape(url.PathEscape(secret))} {
		in := "dial https://x.example/mcp/" + form + "/sse failed"
		for name, out := range map[string]string{"mcpupstream.RedactText": mcpupstream.RedactText(in, secret), "mcpupstream.RedactPathSecret": mcpupstream.RedactPathSecret(in, secret)} {
			if strings.Contains(out, form) || strings.Contains(out, "tok") {
				t.Fatalf("%s must hide the secret in form %q: %s", name, form, out)
			}
		}
	}
	if out := mcpupstream.RedactPathSecret(real, secret); strings.Contains(out, "tok") || !strings.Contains(out, "***") {
		t.Fatalf("mcpupstream.RedactPathSecret must mask the secret segment of a real URL: %s", out)
	}
	// 过短的“密钥”不做全局替换（避免把普通文本破坏成 ***）。
	if out := mcpupstream.RedactPathSecret("/mcp/ab/sse", "ab"); out != "/mcp/ab/sse" {
		t.Fatalf("too-short secrets must not be blindly replaced: %s", out)
	}
}

// SSE endpoint 同源校验用“替换后的真实 URL”比较；endpoint 路径里含密钥时，错误信息不能带出该路径。
func TestResolveEndpointUsesSubstitutedBaseAndNeverEchoesEndpointPath(t *testing.T) {
	base := mustParse(t, "https://x.example/mcp/"+url.PathEscape(pathSecretSample)+"/sse")
	ep, err := mcpupstream.ResolveEndpoint(base, "/mcp/"+url.PathEscape(pathSecretSample)+"/messages?sessionId=1")
	if err != nil || ep.Host != "x.example" {
		t.Fatalf("same-origin endpoint with secret in path must resolve: %v %v", ep, err)
	}
	// 跨源：错误里不得出现 endpoint 路径（其中含密钥）。
	_, err = mcpupstream.ResolveEndpoint(base, "https://evil.example/mcp/"+url.PathEscape(pathSecretSample)+"/messages")
	if err == nil {
		t.Fatal("cross-origin endpoint must be rejected")
	}
	for _, leak := range []string{pathSecretSample, url.PathEscape(pathSecretSample), "tok", "/messages", "/mcp/"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("cross-origin error must not echo the endpoint/base path (%q): %v", leak, err)
		}
	}
	// 其它 endpoint 解析错误同样不回显 endpoint 内容。
	for _, bad := range []string{"https://u:p@x.example/mcp/" + url.PathEscape(pathSecretSample), "/m#" + url.PathEscape(pathSecretSample), "file:///" + pathSecretSample} {
		if _, err := mcpupstream.ResolveEndpoint(base, bad); err != nil && (strings.Contains(err.Error(), "tok") || strings.Contains(err.Error(), "100")) {
			t.Fatalf("endpoint parse error must not echo input: %v", err)
		}
	}
}

// mcpupstream.ApplyAuth 在 path 模式下不改 query / 头，由调用方在构造请求前替换 URL；StripCallerCredentials 对 path 模式无副作用。
func TestApplyAuthPathModeDoesNotTouchHeadersOrQuery(t *testing.T) {
	cfg, _ := mcpupstream.ParseConfig("auto", map[string]interface{}{mcpupstream.CapAuthLocation: "path"})
	req, _ := http.NewRequest(http.MethodPost, "https://x.example/mcp/abc/sse?a=1", nil)
	if err := mcpupstream.ApplyAuth(req, cfg, "s3cret"); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") != "" || req.URL.RawQuery != "a=1" {
		t.Fatalf("path mode must not add headers/query: %v %q", req.Header, req.URL.RawQuery)
	}
}

// 端到端：密钥以“单个、编码正确的路径段”送达上游（Streamable 的 POST、SSE 的 GET 与 POST endpoint 都是）。
func TestPathSecretReachesUpstreamAsSingleEncodedSegment(t *testing.T) {
	for _, p := range mcpprofiletest.All() {
		if p.Name != "path-secret" {
			continue
		}
		inst := p.Start(t)
		for _, c := range inst.Cases[:2] { // streamable + sse
			sess, err := connect(t, c)
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			if _, err := sess.ListTools(context.Background(), 3, 50); err != nil {
				t.Fatalf("%s tools/list: %v", c.Name, err)
			}
			sess.Close()
		}
		want := "/mcp/" + url.PathEscape(mcpprofiletest.PathSecretValue()) + "/"
		var posts, gets int
		for _, r := range inst.Requests() {
			if !strings.HasPrefix(r.EscapedPath, want) {
				t.Fatalf("every upstream request must carry the encoded secret segment %q, got %q", want, r.EscapedPath)
			}
			if strings.Count(r.EscapedPath, "/") != 3 {
				t.Fatalf("secret with '/' must stay in ONE segment: %q", r.EscapedPath)
			}
			if r.Method == http.MethodPost {
				posts++
			} else {
				gets++
			}
		}
		if posts == 0 || gets == 0 {
			t.Fatalf("expected both streamable POSTs and SSE GET: posts=%d gets=%d", posts, gets)
		}
	}
}

// 错误里不含 endpoint 路径：跨源 endpoint（路径带密钥）被拒时，错误文案不含该路径和密钥。
func TestPathSecretCrossOriginEndpointErrorHasNoPathOrSecret(t *testing.T) {
	inst := mcpprofiletest.StartServer(t, mcpprofiletest.Options{
		Name: "path-cross", Prefix: "/mcp/", SSEPath: "/sse", Version: "2025-06-18",
		PathSecret: mcpprofiletest.PathSecretValue(), Endpoint: "crossorigin",
	})
	c := mcpprofiletest.Case{URL: inst.URL() + "/mcp/{secret}/sse", Transport: "sse",
		Caps: map[string]interface{}{"upstream_auth_location": "path"}, Secret: mcpprofiletest.PathSecretValue()}
	_, err := connect(t, c)
	if err == nil || mcpupstream.KindOf(err) != mcpupstream.KindCrossOrigin {
		t.Fatalf("cross-origin endpoint must be rejected: %v", err)
	}
	for _, leak := range []string{mcpprofiletest.PathSecretValue(), url.PathEscape(mcpprofiletest.PathSecretValue()), "tok/en", "tok%2Fen", "/mcp/", "/messages"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error must not echo paths or secrets (%q): %v", leak, err)
		}
	}
	if inst.VictimHits() != 0 {
		t.Fatalf("victim must receive nothing, got %d", inst.VictimHits())
	}
}

// 上游返回的错误体里回显了路径（含密钥）：摘要经脱敏后不得含密钥的任何编码形态。
func TestPathSecretEchoedByUpstreamErrorIsRedacted(t *testing.T) {
	e := mcpupstream.ClassifyHTTPFailure(502, nil, []byte(`{"error":"upstream failed for /mcp/`+url.PathEscape(pathSecretSample)+`/sse (`+pathSecretSample+`)"}`), pathSecretSample)
	for _, leak := range []string{pathSecretSample, url.PathEscape(pathSecretSample), "tok"} {
		if strings.Contains(e.Message, leak) {
			t.Fatalf("upstream-echoed secret must be redacted (%q): %s", leak, e.Message)
		}
	}
}

// 构造请求 / 拨号失败时，Go 的 *url.Error 会带完整请求 URL（含路径密钥）：对外错误只能保留根因。
func TestPathSecretRequestBuildAndDialErrorsStripURL(t *testing.T) {
	secret := pathSecretSample
	real := "https://x.example/mcp/" + url.PathEscape(secret) + "/sse"
	ue := &url.Error{Op: "Get", URL: real, Err: errString("dial tcp 127.0.0.1:9: connect: connection refused")}
	for name, err := range map[string]error{
		"ClassifyDial":              mcpupstream.ClassifyDial(ue, secret),
		"ClassifyDialNoKnownSecret": mcpupstream.ClassifyDial(ue),
		"RequestBuild":              mcpupstream.NewRequestErrorForTest(ue),
	} {
		for _, leak := range []string{secret, url.PathEscape(secret), "tok/en", "tok%2Fen", "/mcp/"} {
			if strings.Contains(err.Error(), leak) {
				t.Fatalf("%s must not echo the request URL (%q): %v", name, leak, err)
			}
		}
	}
	// 非 url.Error 的错误文本里若带 URL，凭已知密钥脱敏。
	plain := errString("Get \"" + real + "\": EOF")
	if out := mcpupstream.ClassifyDial(plain, secret).Error(); strings.Contains(out, "tok/en") || strings.Contains(out, "tok%2Fen") {
		t.Fatalf("known secret in a plain error text must be redacted: %s", out)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// M-3：密钥值为 "." 或 ".." 时，作为路径段会被 URL 规范化吃掉 / 改变路径结构：替换时直接报中文错误。
func TestFollowupM3_DotSegmentSecretIsRejected(t *testing.T) {
	u := mustParse(t, "https://x.example/mcp/{secret}/sse")
	for _, bad := range []string{".", ".."} {
		_, err := mcpupstream.SubstitutePathSecret(u, bad)
		if err == nil || !strings.Contains(err.Error(), "密钥") || !strings.Contains(err.Error(), "路径") {
			t.Fatalf("secret %q must be rejected with a Chinese hint, got %v", bad, err)
		}
		if strings.Contains(err.Error(), "x.example") {
			t.Fatalf("error must not echo the URL: %v", err)
		}
	}
	// 含点的普通密钥（如 "a.b"、".hidden"、"..x"）仍然允许。
	for _, ok := range []string{"a.b", ".hidden", "..x", "x.."} {
		if _, err := mcpupstream.SubstitutePathSecret(u, ok); err != nil {
			t.Fatalf("secret %q is a normal path segment and must be accepted: %v", ok, err)
		}
	}
	// 保存时的校验入口给出同样提示。
	if err := mcpupstream.ValidatePathSecretValue(".."); err == nil || !strings.Contains(err.Error(), "路径") {
		t.Fatalf("save-time validation must reject '..': %v", err)
	}
	if err := mcpupstream.ValidatePathSecretValue("normal-token_123"); err != nil {
		t.Fatal(err)
	}
}

// L-2：sessionid / session / session_id 不在脱敏白名单里（会话 id 可能被当作凭据重放），默认遮蔽；
// 只保留真正非敏感的参数。
func TestFollowupL2_SessionIDIsRedactedAndAllowlistIsTight(t *testing.T) {
	got := mcpupstream.RedactURL("https://x.example/sse?sessionId=abc&session_id=def&session=ghi&SessionID=jkl&version=1&format=json&lang=zh&region=cn")
	for _, leak := range []string{"abc", "def", "ghi", "jkl"} {
		if strings.Contains(got, leak) {
			t.Fatalf("session identifiers must be redacted, leaked %q: %s", leak, got)
		}
	}
	for _, keep := range []string{"version=1", "format=json", "lang=zh", "region=cn"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("truly non-sensitive params must be kept (%q): %s", keep, got)
		}
	}
	for _, name := range []string{"sessionid", "session", "session_id", "sessionId", "SESSION-ID"} {
		if mcpupstream.IsSafeQueryParam(name) {
			t.Fatalf("%q must not be on the redaction allowlist", name)
		}
	}
	// 文本脱敏：URL 里的 sessionId 值同样遮蔽。
	if out := mcpupstream.RedactText("POST https://x.example/messages?sessionId=SESSVALUE99 failed"); strings.Contains(out, "SESSVALUE99") {
		t.Fatalf("RedactText must mask sessionId values in URLs: %s", out)
	}
}

// 竞态回归：DialSSE 成功返回后，调用方立刻取消建连用的 ctx（桥接 dialMCPSSEUpstream 里就是 defer cancel()），
// 已建立的连接必须不受影响。旧实现里 watcher 在 select 中同时面对“ctx 已取消”和“已建立”两个就绪分支，
// 随机选到前者就会把刚建好的连接取消掉，表现为随后的 initialize 握手报 context canceled。
//
// 测试用“拦截 endpoint 事件的最后一刻”放大窗口：服务端先发 endpoint，客户端在 endpoint 到达
// 与 DialSSE 返回之间的任何调度点都可能被取消；这里让取消与返回尽可能同时发生，并重复大量迭代。
func TestDialSSEConnectionSurvivesCancelOfDialContextAfterReturn(t *testing.T) {
	inst := mcpprofiletest.StartServer(t, mcpprofiletest.Options{Name: "survive", SSEPath: "/sse", Version: "2025-06-18", Endpoint: "relative"})
	u := mustParse(t, inst.URL()+"/sse")
	cfg, _ := mcpupstream.ParseConfig("sse", nil)
	var wg sync.WaitGroup
	var bad int32
	const workers, iters = 8, 120
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				ctx, cancel := context.WithCancel(context.Background())
				conn, err := mcpupstream.DialSSE(ctx, mcpupstream.SSEOptions{URL: u, Config: cfg, Client: &http.Client{}, EndpointTimeout: 2 * time.Second})
				if err != nil {
					cancel()
					continue // 建连被取消 / 失败不是本测试关心的
				}
				cancel() // 返回后立即取消，不留调度间隙
				hctx, hcancel := context.WithTimeout(context.Background(), 2*time.Second)
				_, herr := mcpupstream.HandshakeSSE(hctx, conn, map[string]interface{}{"name": "t", "version": "1"}, true)
				hcancel()
				conn.Close()
				if herr != nil {
					atomic.AddInt32(&bad, 1)
				}
			}
		}()
	}
	wg.Wait()
	if n := atomic.LoadInt32(&bad); n != 0 {
		t.Fatalf("%d/%d established connections were killed by cancelling the dial context after DialSSE returned", n, workers*iters)
	}
}
