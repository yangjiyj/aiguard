package handler

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

// 任务 8.2 的另一组：防跳板出站不在防护项注册表里，按设计 D5/D6 单独表驱动——
// 默认拒绝；对应开关打开放行（只放开它自己那一类）；全局观察留痕下仍拒（不受观察留痕影响）。
// 这里覆盖网关上的三处：正向代理（8082）、反向代理路由、MCP 上游。独立代理、平台自身出站
// （通知渠道、身份源）在各自模块里有同口径的表。

type staticEgressResolver map[string]string

func (r staticEgressResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if ip, ok := r[host]; ok {
		return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
	}
	return nil, errors.New("no such host")
}

func TestAntiPivotForwardProxyEgressMatrix(t *testing.T) {
	for _, tc := range []struct {
		class, host, ip string
		open            map[string]string // 放行开关（system_settings 键值）
	}{
		{"private", "intranet.example", "10.0.0.7", map[string]string{egresspolicy.KeyAllowPrivate: "true"}},
		{"private cidr", "intranet.example", "10.0.0.7", map[string]string{egresspolicy.KeyAllowedCIDRs: `["10.0.0.7/32"]`}},
		{"loopback", "loop.example", "127.0.0.1", map[string]string{egresspolicy.KeyAllowLoopback: "true"}},
		{"metadata", "meta.example", "169.254.169.254", map[string]string{egresspolicy.KeyAllowMetadata: "true"}},
		{"alibaba metadata", "meta.example", "100.100.100.200", map[string]string{egresspolicy.KeyAllowMetadata: "true"}},
		{"internal hostname", "metadata.google.internal", "169.254.169.254", map[string]string{egresspolicy.KeyAllowMetadata: "true"}},
	} {
		t.Run(tc.class, func(t *testing.T) {
			guard := func(t *testing.T, values map[string]string) (bool, int, []string) {
				t.Helper()
				recorder := &fakeReverseProxyAuditRecorder{}
				h := forwardProxyWithRuntime(values, recorder, lookupIPs(tc.ip))
				r := httptest.NewRequest(http.MethodConnect, "http://"+tc.host+":443", nil)
				r.Host = tc.host + ":443"
				w := httptest.NewRecorder()
				_, ok := h.guardEgress(w, r, tc.host, 443)
				return ok, w.Code, securityEventReasons(recorder)
			}
			t.Setenv("SECURITY_AUDIT_ONLY", "false")
			if ok, code, events := guard(t, map[string]string{}); ok || code != http.StatusForbidden || len(events) != 1 || events[0] != egresspolicy.ReasonInternalEgressDenied {
				t.Fatalf("default must deny and record: ok=%v code=%d events=%v", ok, code, events)
			}
			if ok, _, events := guard(t, tc.open); !ok || len(events) != 1 || events[0] != egresspolicy.ReasonInternalEgressAllowed {
				t.Fatalf("switch %v must allow and record: ok=%v events=%v", tc.open, ok, events)
			}
			// 全局观察留痕（部署变量作初值，2.9.22 D7）：检测类拦截都放行，这里照拒。
			t.Setenv("SECURITY_AUDIT_ONLY", "true")
			h := forwardProxyWithRuntime(map[string]string{}, &fakeReverseProxyAuditRecorder{}, lookupIPs(tc.ip))
			if outcome, _ := h.whitelistOutcome(context.Background(), "unlisted.example", 443); outcome.Enforce {
				t.Fatalf("fixture: global record mode must relax the whitelist, got %+v", outcome)
			}
			if ok, code, _ := guard(t, map[string]string{}); ok || code != http.StatusForbidden {
				t.Fatalf("global record mode must still deny: ok=%v code=%d", ok, code)
			}
		})
	}
}

func TestAntiPivotReverseProxyEgressMatrix(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer upstream.Close()
	for _, tc := range []struct {
		class, target, host, ip string
		route                   func(*ReverseProxyRoute) // 打开对应开关
	}{
		{"loopback", upstream.URL, "127.0.0.1", "127.0.0.1", func(r *ReverseProxyRoute) { r.EgressOverrides.AllowLoopback = true }},
		{"private", "http://10.0.0.7:9", "10.0.0.7", "10.0.0.7", func(r *ReverseProxyRoute) {
			r.AllowPrivateEgress, r.PrivateEgressCIDRs = true, []string{"10.0.0.7/32"}
		}},
		{"link local", "http://169.254.20.1:9", "169.254.20.1", "169.254.20.1", func(r *ReverseProxyRoute) { r.EgressOverrides.AllowLinkLocal = true }},
		{"metadata", "http://169.254.169.254:80", "169.254.169.254", "169.254.169.254", func(r *ReverseProxyRoute) { r.EgressOverrides.AllowMetadata = true }},
		{"internal hostname", "http://llm.corp.internal:9", "llm.corp.internal", "203.0.113.10", func(r *ReverseProxyRoute) { r.EgressOverrides.AllowInternalHostnames = true }},
	} {
		t.Run(tc.class, func(t *testing.T) {
			serve := func(t *testing.T, recordOnly bool, route ReverseProxyRoute) int {
				t.Helper()
				h := &ReverseProxyHandler{tenantID: "tenant_default", client: upstream.Client(), auditRecorder: &fakeReverseProxyAuditRecorder{},
					securityAuditOnlyFallback: recordOnly, routes: []ReverseProxyRoute{route}}
				if h.securityAuditOnly(context.Background()) != recordOnly {
					t.Fatalf("fixture: global record mode = %v", !recordOnly)
				}
				w := httptest.NewRecorder()
				if !h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://gateway.local/r/v1/models", nil)) {
					t.Fatal("route not matched")
				}
				return w.Code
			}
			base := ReverseProxyRoute{ID: "rpr_matrix", PathPrefix: "/r", TargetURL: tc.target, Status: "active"}
			if code := serve(t, false, base); code != http.StatusForbidden {
				t.Fatalf("default must deny: %d", code)
			}
			opened := base
			tc.route(&opened)
			if code := serve(t, true, base); code != http.StatusForbidden {
				t.Fatalf("global record mode must still deny: %d", code)
			}
			if tc.class == "loopback" {
				if code := serve(t, false, opened); code != http.StatusOK {
					t.Fatalf("loopback override must reach the upstream: %d", code)
				}
				return
			}
			// 其余几类没有真实可达的上游：放行在网关同一个校验函数上断言（不拨号）。
			if _, err := resolveSafeEgressTargetForRouteWithOverrides(context.Background(), tc.host, 9, opened.AllowPrivateEgress, opened.PrivateEgressCIDRs, opened.EgressOverrides, lookupIPs(tc.ip)); err != nil {
				t.Fatalf("switch must allow: %v", err)
			}
		})
	}
}

func TestAntiPivotMCPUpstreamEgressMatrix(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()
	ping := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	for _, tc := range []struct {
		class, url string
		resolver   staticEgressResolver
		open       func(*mcpServerRoute)
	}{
		{"loopback", upstream.URL + "/mcp", nil, func(s *mcpServerRoute) { s.EgressOverrides.AllowLoopback = true }},
		{"private", "http://10.0.0.7:9/mcp", nil, func(s *mcpServerRoute) { s.AllowPrivateEgress = true }},
		{"link local", "http://169.254.20.1:9/mcp", nil, func(s *mcpServerRoute) { s.EgressOverrides.AllowLinkLocal = true }},
		{"metadata", "http://169.254.169.254/mcp", nil, func(s *mcpServerRoute) { s.EgressOverrides.AllowMetadata = true }},
		{"internal hostname", "http://metadata.google.internal/mcp", staticEgressResolver{"metadata.google.internal": "169.254.169.254"}, func(s *mcpServerRoute) {
			s.EgressOverrides.AllowInternalHostnames, s.EgressOverrides.AllowMetadata = true, true
		}},
	} {
		t.Run(tc.class, func(t *testing.T) {
			forward := func(t *testing.T, recordOnly bool, server mcpServerRoute) error {
				t.Helper()
				client := NewToolRiskClient("http://127.0.0.1:1", "internal")
				setToolGuardTestPosture(t, client, recordOnly, false)
				h := &MCPProxyHandler{client: upstream.Client(), toolRiskClient: client, auditRecorder: &mcpProxyAuditRecorder{db: newFakeAuditDB()}}
				if h.securityAuditOnly(context.Background()) != recordOnly {
					t.Fatalf("fixture: global record mode = %v", !recordOnly)
				}
				resp, _, err := h.forwardMCPUpstream(context.Background(), &server, mcpEgressTestRequest(), ping)
				if err == nil {
					resp.Body.Close()
				}
				return err
			}
			base := mcpServerRoute{ID: "mcp_local", TenantID: "tenant_test", Name: "local", ServerURL: tc.url, Status: "active", Transport: "streamable_http"}
			if err := forward(t, false, base); !errors.Is(err, errMCPUpstreamEgressDenied) {
				t.Fatalf("default must deny: %v", err)
			}
			if err := forward(t, true, base); !errors.Is(err, errMCPUpstreamEgressDenied) {
				t.Fatalf("global record mode must still deny: %v", err)
			}
			opened := base
			tc.open(&opened)
			if tc.class == "loopback" {
				if err := forward(t, false, opened); err != nil {
					t.Fatalf("loopback override must reach the upstream: %v", err)
				}
				return
			}
			if _, err := safetarget.ResolveWithOptions(context.Background(), tc.url, opened.egressOptions(), tc.resolver); err != nil {
				t.Fatalf("switch must allow: %v", err)
			}
		})
	}
}
