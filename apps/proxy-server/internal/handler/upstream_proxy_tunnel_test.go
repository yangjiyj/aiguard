package handler

import (
	"bufio"
	"context"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// 正向代理里有两条不经 http.Transport 的出网路径：
//   - tunnelDirect：CONNECT 直通，裸 TCP 对拷；
//   - handleMITM 的兜底分支：手拨 DialTLSContext + 手写请求。
//
// 这两条路径如果只是「把 TCP 拨到代理那一跳」就完了——没有 CONNECT，
// 客户端的 ClientHello 会被直接灌给代理，表现为连上就挂死。
// 所以要有显式建隧道的入口，并且隧道失败必须报错：静默退回直连意味着
// 客户以为流量走了他的出网代理、实际没走，那是合规事故。

// fakeProxyServer 在管道另一端扮演出网代理：读一个 CONNECT 请求，回固定响应。
func fakeProxyServer(t *testing.T, response string) (DialContextFunc, func() string) {
	t.Helper()
	var mu = make(chan string, 1)
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			reader := bufio.NewReader(server)
			var received strings.Builder
			for {
				line, err := reader.ReadString('\n')
				received.WriteString(line)
				if err != nil || line == "\r\n" || line == "\n" {
					break
				}
			}
			mu <- received.String()
			_, _ = server.Write([]byte(response))
		}()
		return client, nil
	}
	return dial, func() string {
		select {
		case got := <-mu:
			return got
		case <-time.After(3 * time.Second):
			t.Fatal("未收到 CONNECT 请求")
			return ""
		}
	}
}

func TestUpstreamProxyTunnelSendsConnect(t *testing.T) {
	dial, received := fakeProxyServer(t, "HTTP/1.1 200 Connection Established\r\n\r\n")
	guard := NewEgressGuard(nil, dial)
	guard.SetUpstreamProxy(&url.URL{Scheme: "http", Host: "10.20.30.40:8080"})

	conn, err := guard.DialTunnelContext(context.Background(), "tcp", "api.openai.com:443")
	if err != nil {
		t.Fatalf("经上层代理建隧道应成功：%v", err)
	}
	defer conn.Close()

	request := received()
	if !strings.HasPrefix(request, "CONNECT api.openai.com:443 HTTP/1.1\r\n") {
		t.Fatalf("必须向上层代理发 CONNECT，实际=%q", request)
	}
	if !strings.Contains(request, "Host: api.openai.com:443\r\n") {
		t.Fatalf("CONNECT 必须带 Host 头，实际=%q", request)
	}
}

func TestUpstreamProxyTunnelFailsLoudlyOnRefusal(t *testing.T) {
	dial, _ := fakeProxyServer(t, "HTTP/1.1 403 Forbidden\r\n\r\n")
	guard := NewEgressGuard(nil, dial)
	guard.SetUpstreamProxy(&url.URL{Scheme: "http", Host: "10.20.30.40:8080"})

	conn, err := guard.DialTunnelContext(context.Background(), "tcp", "api.openai.com:443")
	if err == nil {
		conn.Close()
		t.Fatal("上层代理拒绝时必须报错，绝不能静默退回直连")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("错误应带上代理返回的状态，便于现场定位，实际=%v", err)
	}
}

func TestUpstreamProxyTunnelDisabledKeepsDirectDial(t *testing.T) {
	dialedTo := ""
	guard := NewEgressGuard(nil, func(ctx context.Context, network, address string) (net.Conn, error) {
		dialedTo = address
		return nil, context.Canceled
	})
	// 未配置上层代理：行为必须与改造前逐字节一致，直接拨真实目标。
	_, _ = guard.DialTunnelContext(context.Background(), "tcp", "8.8.8.8:443")
	if dialedTo != "8.8.8.8:443" {
		t.Fatalf("不启用上层代理时应直拨目标，实际=%s", dialedTo)
	}
}

func TestUpstreamProxyTunnelRejectsSmuggledTarget(t *testing.T) {
	dial, _ := fakeProxyServer(t, "HTTP/1.1 200 OK\r\n\r\n")
	guard := NewEgressGuard(nil, dial)
	guard.SetUpstreamProxy(&url.URL{Scheme: "http", Host: "10.20.30.40:8080"})

	// 目标里带控制字符 = 试图往 CONNECT 请求行里注入额外的头。
	for _, bad := range []string{
		"evil.example\r\nX-Injected: 1:443",
		"evil.example:443\r\n",
		"evil\x00.example:443",
	} {
		if _, err := guard.DialTunnelContext(context.Background(), "tcp", bad); err == nil {
			t.Fatalf("含控制字符的目标 %q 必须被拒（CONNECT 请求走私）", bad)
		}
	}
}
