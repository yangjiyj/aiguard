package handler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
)

var errUnsafeEgressTarget = errors.New("unsafe egress target")

type resolvedEgressTarget struct {
	Host        string
	Port        int
	DialAddress string
}

// resolveForwardEgressTarget 是正向代理（8082）的防跳板出站校验：主机名先过一道内部名判定，
// 再逐个判定 DNS 解析出的全部地址，任一地址不放行就整体拒绝，放行时把连接钉到第一个地址。
// 放行与否只看平台设置（允许内网、回环、元数据三开关，放行网段与主机名名单），默认全部拒绝；
// 全局观察留痕不改变这里的判定。viaSetting 表示目标是内部地址、靠设置放行（调用方记一条事件）。
func resolveForwardEgressTarget(ctx context.Context, host string, port int, settings egresspolicy.Settings, lookup lookupIPAddrFunc) (resolvedEgressTarget, bool, error) {
	normalizedHost := egresspolicy.NormalizeHost(host)
	if normalizedHost == "" {
		return resolvedEgressTarget{}, false, fmt.Errorf("empty egress host")
	}
	if port < 1 || port > 65535 {
		return resolvedEgressTarget{}, false, fmt.Errorf("invalid egress port %d", port)
	}
	viaSetting := false
	_, literalErr := netip.ParseAddr(normalizedHost)
	if literalErr != nil {
		analysis := agentguard.AnalyzeTarget("http://" + net.JoinHostPort(normalizedHost, strconv.Itoa(port)))
		if analysis.Hit {
			if !forwardEgressHostnameAllowed(normalizedHost, analysis.Reason, settings) {
				return resolvedEgressTarget{}, false, fmt.Errorf("%w: %s", errUnsafeEgressTarget, analysis.Reason)
			}
			viaSetting = true
		}
	}
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	addrs, err := lookup(ctx, normalizedHost)
	if err != nil {
		return resolvedEgressTarget{}, false, fmt.Errorf("resolve egress host: %w", err)
	}
	if len(addrs) == 0 {
		return resolvedEgressTarget{}, false, fmt.Errorf("resolve egress host: no addresses")
	}

	var selected netip.Addr
	for _, item := range addrs {
		addr, err := netip.ParseAddr(item.IP.String())
		if err != nil {
			return resolvedEgressTarget{}, false, fmt.Errorf("parse resolved egress address: %w", err)
		}
		addr = addr.Unmap()
		verdict := settings.CheckAddr(addr)
		if !verdict.Allowed {
			return resolvedEgressTarget{}, false, fmt.Errorf("%w: resolved %s", errUnsafeEgressTarget, addr.String())
		}
		viaSetting = viaSetting || verdict.ViaSetting
		if !selected.IsValid() {
			selected = addr
		}
	}
	if !selected.IsValid() {
		return resolvedEgressTarget{}, false, fmt.Errorf("resolve egress host: no usable address")
	}
	return resolvedEgressTarget{
		Host:        normalizedHost,
		Port:        port,
		DialAddress: net.JoinHostPort(selected.String(), strconv.Itoa(port)),
	}, viaSetting, nil
}

// forwardEgressHostnameAllowed 判断被判为内部名的主机名（localhost、.internal、元数据名等）
// 能否继续解析：在放行主机名名单里，或打开了对应开关。之后解析出的地址仍逐个判定。
func forwardEgressHostnameAllowed(host, reason string, settings egresspolicy.Settings) bool {
	if settings.HostListed(host) {
		return true
	}
	if reason == "blocked_cloud_metadata_hostname" {
		return settings.AllowMetadata
	}
	return settings.AllowPrivate || settings.AllowLoopback || len(settings.AllowedCIDRs) > 0
}

func dialResolvedEgress(ctx context.Context, target resolvedEgressTarget, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	return dialer.DialContext(ctx, "tcp", target.DialAddress)
}

func httpClientForResolvedEgress(base *http.Client, target resolvedEgressTarget, timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if base != nil {
		if base.Timeout > 0 {
			timeout = base.Timeout
		}
		if baseTransport, ok := base.Transport.(*http.Transport); ok && baseTransport != nil {
			transport = baseTransport.Clone()
		}
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, target.DialAddress)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	if base != nil {
		client.CheckRedirect = base.CheckRedirect
		client.Jar = base.Jar
	}
	return client
}

// streamingHTTPClientForResolvedEgress 与 httpClientForResolvedEgress 一样把连接 DNS 钉到
// 校验过的安全 IP, 但用于流式中继(SSE): 不设整请求级 client.Timeout —— 否则长流式响应
// (高推理大模型可能跑几分钟)会被 wall-clock 硬断(就是 codex 撞的那道 120s 墙)。
// 改用 transport.ResponseHeaderTimeout 防"上游迟迟不回首字节", 请求总时长由调用方的
// ctx 截止时间控制。刻意不复用 base.Timeout(那正是覆盖 bug 的来源), 也不改 base 本身。
func streamingHTTPClientForResolvedEgress(base *http.Client, target resolvedEgressTarget) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if base != nil {
		if baseTransport, ok := base.Transport.(*http.Transport); ok && baseTransport != nil {
			transport = baseTransport.Clone()
		}
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, target.DialAddress)
	}
	transport.ResponseHeaderTimeout = 60 * time.Second

	client := &http.Client{
		Transport: transport,
		Timeout:   0, // 流式: 无整请求超时, 总时长交给 ctx
	}
	if base != nil {
		client.CheckRedirect = base.CheckRedirect
		client.Jar = base.Jar
	}
	return client
}
