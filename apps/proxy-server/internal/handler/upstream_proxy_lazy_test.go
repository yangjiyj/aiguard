package handler

import (
	"net/http"
	"net/url"
	"testing"
)

// keep-alive transport 是 sync.Once 懒初始化的。它一旦在上层出网代理配置
// 完成之前被初始化，如果当时把 Proxy 快照下来，就会永久是 nil ——
// MITM keep-alive 路径静默直连出网，客户以为流量经他的出网代理而实际没走。
// 这是合规事故而不是可用性问题，所以 Proxy 必须每次请求现查。
//
// 这条测试按真实风险顺序来：先触发懒初始化，再设置配置。
func TestKeepAliveTransportPicksUpProxySetAfterInit(t *testing.T) {
	handler := NewProxyHandler(nil, nil, nil, nil, nil)
	_ = handler.mitmKeepAliveTransport() // 先初始化，制造风险顺序
	handler.SetUpstreamEgressProxy(&url.URL{Scheme: "http", Host: "10.20.30.40:8080"})

	transport, ok := handler.mitmKeepAliveTransport().(*http.Transport)
	if !ok {
		t.Fatalf("keep-alive transport 类型异常：%T", handler.mitmKeepAliveTransport())
	}
	if transport.Proxy == nil {
		t.Fatal("Proxy 不能为 nil，否则后设置的上层代理永远不生效")
	}
	target, _ := url.Parse("https://api.openai.com/v1/chat/completions")
	resolved, err := transport.Proxy(&http.Request{URL: target})
	if err != nil {
		t.Fatalf("Proxy 解析失败：%v", err)
	}
	if resolved == nil || resolved.Host != "10.20.30.40:8080" {
		t.Fatalf("初始化之后设置的上层代理必须生效，实际=%v", resolved)
	}
}

// 未配置上层代理时，keep-alive transport 的取值语义必须与改造前一致：
// 沿用 http.ProxyFromEnvironment（含 NO_PROXY 判定），不能因为我们接了钩子
// 就变成恒不走代理。
//
// 注意这里不直接断言某个具体地址：http.ProxyFromEnvironment 在进程内用
// sync.Once 缓存环境快照，包内任何更早的测试都可能先把它冻住，t.Setenv
// 就再也影响不了它（实测：单跑通过、全包跑失败）。所以改成断言「我们的钩子
// 与直接调用 http.ProxyFromEnvironment 的结果逐个相同」——这既锁住了委托
// 语义，又不依赖测试执行顺序。
func TestKeepAliveTransportWithoutUpstreamDelegatesToEnvironment(t *testing.T) {
	handler := NewProxyHandler(nil, nil, nil, nil, nil)
	transport := handler.mitmKeepAliveTransport().(*http.Transport)

	for _, raw := range []string{
		"https://api.openai.com/v1/chat/completions",
		"http://plain.example/v1/x",
		"https://excluded.example/v1/x",
	} {
		target, parseErr := url.Parse(raw)
		if parseErr != nil {
			t.Fatalf("测试用例 URL 非法：%v", parseErr)
		}
		request := &http.Request{URL: target}

		want, wantErr := http.ProxyFromEnvironment(request)
		got, gotErr := transport.Proxy(request)
		if (wantErr == nil) != (gotErr == nil) {
			t.Fatalf("%s: 错误语义不一致 want=%v got=%v", raw, wantErr, gotErr)
		}
		switch {
		case want == nil && got == nil:
		case want == nil || got == nil:
			t.Fatalf("%s: 未配置上层代理时必须与环境判定一致 want=%v got=%v", raw, want, got)
		case want.String() != got.String():
			t.Fatalf("%s: 代理地址不一致 want=%s got=%s", raw, want, got)
		}
	}
}
