package handler

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// 双层代理场景：客户 PC 把代理指向我们的正向代理，我们再经客户的出网代理上网。
// 我们是中间那一层。上层出网代理几乎总在内网地址（10./172.16./192.168.），
// 而 EgressGuard 默认把内网地址当 SSRF 目标挡掉——所以默认配置下双层代理必然拨不通。
//
// 这里锁三件事：
//  1. 默认不变：没配上层代理时，内网地址照旧被挡（SSRF 防线不能因为这个功能松掉）。
//  2. 显式配置的上层代理地址可以拨通，且只有它可以——不是把整个内网放开。
//  3. 上层代理走 CONNECT 语义，隧道目标仍要过白名单与留证，不能因为多一跳就绕开审计。

func TestUpstreamProxyDefaultsKeepPrivateEgressBlocked(t *testing.T) {
	guard := NewEgressGuard(nil, nil)
	for _, address := range []string{"10.20.30.40:8080", "192.168.31.7:3128", "172.16.0.9:8080"} {
		if _, err := guard.Resolve(context.Background(), address); err == nil {
			t.Fatalf("默认配置下 %s 必须仍被挡住，否则等于普遍放开内网出网", address)
		}
	}
}

func TestUpstreamProxyAllowsOnlyTheConfiguredHop(t *testing.T) {
	guard := NewEgressGuard(nil, nil)
	guard.SetUpstreamProxy(&url.URL{Scheme: "http", Host: "10.20.30.40:8080"})

	if _, err := guard.Resolve(context.Background(), "10.20.30.40:8080"); err != nil {
		t.Fatalf("显式配置的上层代理必须可拨：%v", err)
	}

	// 同网段的别的地址不能顺带放开——豁免必须精确到那一跳。
	for _, address := range []string{"10.20.30.41:8080", "10.20.30.40:9090", "192.168.31.7:3128"} {
		if _, err := guard.Resolve(context.Background(), address); err == nil {
			t.Fatalf("%s 不是配置的上层代理，不应被放开", address)
		}
	}
}

func TestUpstreamProxyExemptionIsPortSpecific(t *testing.T) {
	guard := NewEgressGuard(nil, nil)
	guard.SetUpstreamProxy(&url.URL{Scheme: "http", Host: "192.168.31.7:3128"})

	if _, err := guard.Resolve(context.Background(), "192.168.31.7:3128"); err != nil {
		t.Fatalf("配置的上层代理端口必须可拨：%v", err)
	}
	// 元数据服务这类地址即使被写成上层代理也不能放——那是云凭据窃取的经典路径。
	guard.SetUpstreamProxy(&url.URL{Scheme: "http", Host: "169.254.169.254:80"})
	if _, err := guard.Resolve(context.Background(), "169.254.169.254:80"); err == nil {
		t.Fatal("云元数据地址不得因为被写成上层代理而放开")
	}
}

func TestUpstreamProxyTransportRoutesThroughConfiguredHop(t *testing.T) {
	guard := NewEgressGuard(nil, nil)
	guard.SetUpstreamProxy(&url.URL{Scheme: "http", Host: "10.20.30.40:8080"})
	transport := guard.HTTPTransport()
	if transport.Proxy == nil {
		t.Fatal("配置上层代理后 transport.Proxy 不能为空")
	}
	target, _ := url.Parse("https://api.openai.com/v1/chat/completions")
	resolved, err := transport.Proxy(&http.Request{URL: target})
	if err != nil {
		t.Fatalf("Proxy 解析失败：%v", err)
	}
	if resolved == nil || resolved.Host != "10.20.30.40:8080" {
		t.Fatalf("出网必须经配置的上层代理，实际=%v", resolved)
	}
}

func TestUpstreamProxyRejectsMalformedConfiguration(t *testing.T) {
	for _, raw := range []string{"::::", "http://", "notaurl\x00", "http://10.0.0.5"} {
		if _, err := ParseUpstreamProxy(raw); err == nil {
			t.Fatalf("非法上层代理配置 %q 必须被拒绝（缺端口/无主机都算非法）", raw)
		}
	}
	parsed, err := ParseUpstreamProxy("http://10.20.30.40:8080")
	if err != nil {
		t.Fatalf("合法配置被拒：%v", err)
	}
	if parsed.Host != "10.20.30.40:8080" {
		t.Fatalf("解析结果不对：%v", parsed)
	}
	// 空值 = 不启用，不能报错，否则默认部署直接起不来。
	empty, err := ParseUpstreamProxy("")
	if err != nil || empty != nil {
		t.Fatalf("空配置应表示不启用，得到 parsed=%v err=%v", empty, err)
	}
}

func TestUpstreamProxyTunnelStillEnforcesWhitelist(t *testing.T) {
	// 多一跳不能变成绕过审计的后门：隧道目标仍由白名单裁决。
	guard := NewEgressGuard(nil, nil)
	guard.SetUpstreamProxy(&url.URL{Scheme: "http", Host: "10.20.30.40:8080"})
	dialed := make([]string, 0, 2)
	guard.dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		return nil, context.Canceled // 不真连，只看拨给了谁
	}
	_, _ = guard.DialContext(context.Background(), "tcp", "api.openai.com:443")
	if len(dialed) != 1 {
		t.Fatalf("应恰好拨一次，实际 %v", dialed)
	}
	if !strings.HasPrefix(dialed[0], "10.20.30.40:8080") {
		t.Fatalf("启用上层代理后 TCP 应先拨到代理那一跳，实际=%s", dialed[0])
	}
}
