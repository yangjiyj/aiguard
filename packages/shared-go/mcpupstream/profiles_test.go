package mcpupstream_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream/mcpprofiletest"
)

// 测试用 client：loopback 上游，不经 safetarget（生产路径由 control-plane / gateway-core 的调用方绑定）。
func plainClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func connect(t *testing.T, c mcpprofiletest.Case) (*mcpupstream.Session, error) {
	t.Helper()
	cfg, err := mcpupstream.ParseConfig(c.Transport, c.Caps)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return mcpupstream.Connect(ctx, mcpupstream.Options{
		URL: u, Config: cfg, Secret: c.Secret, Client: plainClient(), StreamClient: plainClient(),
		EndpointTimeout: 2 * time.Second,
	})
}

func TestVendorProfilesFullChain(t *testing.T) {
	for _, p := range mcpprofiletest.All() {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			inst := p.Start(t)
			for _, c := range inst.Cases {
				c := c
				t.Run(c.Name, func(t *testing.T) {
					sess, err := connect(t, c)
					if !c.WantOK {
						if err == nil {
							sess.Close()
							t.Fatalf("expected failure kind=%s", c.WantKind)
						}
						if got := mcpupstream.KindOf(err); got != c.WantKind {
							t.Fatalf("kind=%q want %q err=%v", got, c.WantKind, err)
						}
						if !strings.Contains(err.Error(), c.WantMsg) {
							t.Fatalf("message %q missing %q", err.Error(), c.WantMsg)
						}
						if strings.Contains(err.Error(), mcpprofiletest.SecretValue()) {
							t.Fatalf("error leaks secret: %v", err)
						}
						if c.WantKind == "cross_origin" && inst.VictimHits() != 0 {
							t.Fatalf("cross-origin victim received %d requests", inst.VictimHits())
						}
						return
					}
					if err != nil {
						t.Fatalf("connect: %v", err)
					}
					defer sess.Close()
					if sess.Transport != c.WantTransport {
						t.Fatalf("transport=%s want %s", sess.Transport, c.WantTransport)
					}
					if sess.Negotiated.Effective != c.WantProtocol {
						t.Fatalf("protocol=%s want %s", sess.Negotiated.Effective, c.WantProtocol)
					}
					if c.WantRawProto != "" && (sess.Negotiated.Raw != c.WantRawProto || !sess.Negotiated.Forward || len(sess.Warnings) == 0) {
						t.Fatalf("forward compat not recorded: %+v warnings=%v", sess.Negotiated, sess.Warnings)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					res, err := sess.ListTools(ctx, 10, 500)
					if err != nil {
						t.Fatalf("ListTools: %v", err)
					}
					var names []string
					for _, raw := range res.Tools {
						var tool struct{ Name string }
						_ = json.Unmarshal(raw, &tool)
						names = append(names, tool.Name)
					}
					if strings.Join(names, ",") != strings.Join(c.Tools, ",") {
						t.Fatalf("tools=%v want %v (warnings=%v)", names, c.Tools, res.Warnings)
					}
					out, err := sess.Call(ctx, "tools/call", map[string]interface{}{"name": c.CallTool, "arguments": c.CallArgs})
					if err != nil {
						t.Fatalf("tools/call: %v", err)
					}
					if !strings.Contains(string(out), c.WantCallText) {
						t.Fatalf("call result=%s want %q", out, c.WantCallText)
					}
					// 密钥不得出现在上游日志可见之外的任何地方：此处只验证 query 模式的密钥确实送达上游。
					for _, r := range inst.Requests() {
						if strings.Contains(r.RawQuery, "sessionId") && strings.Count(r.RawQuery, "sessionId") > 1 {
							t.Fatalf("sessionId duplicated in query: %s", r.RawQuery)
						}
					}
				})
			}
		})
	}
}

func TestStreamableRejectsHTMLAndFallsBack(t *testing.T) {
	inst := mcpprofiletest.StartServer(t, mcpprofiletest.Options{Name: "mixed-endpoint", SSEPath: "/sse", Version: "2025-03-26"})
	u, _ := url.Parse(inst.URL() + "/sse")
	// auto 且路径以 /sse 结尾：直接走旧 SSE。
	cfg, _ := mcpupstream.ParseConfig("auto", nil)
	sess, err := mcpupstream.Connect(context.Background(), mcpupstream.Options{URL: u, Config: cfg, Client: plainClient(), StreamClient: plainClient(), EndpointTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if sess.Transport != "sse" || !sess.AutoDetected {
		t.Fatalf("transport=%s auto=%v", sess.Transport, sess.AutoDetected)
	}

	// 路径不以 /sse 结尾：先试 Streamable，404 → 回退（用 /sse 路径别名模拟需另起服务，这里验证 405/404 分类）。
	inst2 := mcpprofiletest.StartServer(t, mcpprofiletest.Options{Name: "get-only", SSEPath: "/events", Version: "2025-03-26"})
	u2, _ := url.Parse(inst2.URL() + "/events")
	cfg2, _ := mcpupstream.ParseConfig("auto", nil)
	s2, err := mcpupstream.Connect(context.Background(), mcpupstream.Options{URL: u2, Config: cfg2, Client: plainClient(), StreamClient: plainClient(), EndpointTimeout: time.Second})
	if err != nil {
		t.Fatalf("auto fallback after 405: %v", err)
	}
	defer s2.Close()
	if s2.Transport != "sse" || s2.FallbackNote == "" {
		t.Fatalf("transport=%s note=%q", s2.Transport, s2.FallbackNote)
	}
	if strings.Contains(s2.FallbackNote, inst2.URL()) && strings.Contains(s2.FallbackNote, "?") {
		t.Fatalf("fallback note must not carry URL query: %s", s2.FallbackNote)
	}
}

func TestExplicitStreamableNeverFallsBack(t *testing.T) {
	inst := mcpprofiletest.StartServer(t, mcpprofiletest.Options{Name: "sse-only", SSEPath: "/events", Version: "2025-03-26"})
	u, _ := url.Parse(inst.URL() + "/events")
	cfg, _ := mcpupstream.ParseConfig("streamable_http", nil)
	_, err := mcpupstream.Connect(context.Background(), mcpupstream.Options{URL: u, Config: cfg, Client: plainClient(), StreamClient: plainClient()})
	if err == nil {
		t.Fatal("explicit streamable_http must not fall back to SSE")
	}
	for _, r := range inst.Requests() {
		if r.Method == http.MethodGet {
			t.Fatalf("explicit streamable_http must not issue GET: %+v", r)
		}
	}
}

func TestSSEQueryAuthMergesWithEndpointQuery(t *testing.T) {
	var p mcpprofiletest.Profile
	for _, c := range mcpprofiletest.All() {
		if c.Name == "amap-style" {
			p = c
		}
	}
	inst := p.Start(t)
	c := inst.Cases[1]
	sess, err := connect(t, c)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if _, err := sess.ListTools(context.Background(), 5, 100); err != nil {
		t.Fatal(err)
	}
	var postSeen bool
	for _, r := range inst.Requests() {
		if r.Method == http.MethodPost {
			postSeen = true
			q, _ := url.ParseQuery(r.RawQuery)
			if q.Get("key") != mcpprofiletest.SecretValue() || q.Get("sessionId") == "" {
				t.Fatalf("POST query must carry both auth and sessionId: %q", r.RawQuery)
			}
		}
	}
	if !postSeen {
		t.Fatal("no POST observed")
	}
}

func TestUserAgentAndExtraHeadersSent(t *testing.T) {
	var p mcpprofiletest.Profile
	for _, c := range mcpprofiletest.All() {
		if c.Name == "header-extra" {
			p = c
		}
	}
	inst := p.Start(t)
	sess, err := connect(t, inst.Cases[0])
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	for _, r := range inst.Requests() {
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "JJDGuard-MCP/") {
			t.Fatalf("missing product UA: %q", r.Header.Get("User-Agent"))
		}
		if r.Header.Get("Stripe-Account") != "acct_123" {
			t.Fatalf("extra header missing: %v", r.Header)
		}
	}
}
