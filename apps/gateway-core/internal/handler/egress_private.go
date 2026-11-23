package handler

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

type lookupIPAddrFunc func(context.Context, string) ([]net.IPAddr, error)

// reverseProxyEgressDeniedReason 是反向代理目标被防跳板出站拒绝时安全事件的原因码。
const reverseProxyEgressDeniedReason = "reverse_proxy_internal_egress_denied"

func resolveSafeEgressTargetForRoute(
	ctx context.Context,
	host string,
	port int,
	allowPrivate bool,
	privateCIDRs []string,
	lookup lookupIPAddrFunc,
) (resolvedEgressTarget, error) {
	return resolveSafeEgressTargetForRouteWithOverrides(ctx, host, port, allowPrivate, privateCIDRs, safetarget.EgressOverrides{}, lookup)
}

// resolveSafeEgressTargetForRouteWithOverrides 是反向代理路由的防跳板出站校验。内网只认
// 路由的私网授权网段；回环、链路本地、元数据、内部主机名各认路由 egress_overrides 里自己的
// 开关（默认全部拒绝，开关互不放大）。全局观察留痕不改变这里的判定。
func resolveSafeEgressTargetForRouteWithOverrides(
	ctx context.Context,
	host string,
	port int,
	allowPrivate bool,
	privateCIDRs []string,
	overrides safetarget.EgressOverrides,
	lookup lookupIPAddrFunc,
) (resolvedEgressTarget, error) {
	normalizedHost := strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if normalizedHost == "" {
		return resolvedEgressTarget{}, fmt.Errorf("empty egress host")
	}
	if port < 1 || port > 65535 {
		return resolvedEgressTarget{}, fmt.Errorf("invalid egress port %d", port)
	}

	prefixes, err := parsePrivateEgressCIDRs(privateCIDRs)
	if err != nil {
		return resolvedEgressTarget{}, fmt.Errorf("%w: invalid private egress CIDR: %v", errUnsafeEgressTarget, err)
	}
	if allowPrivate && len(prefixes) == 0 {
		return resolvedEgressTarget{}, fmt.Errorf("%w: private egress enabled without CIDRs", errUnsafeEgressTarget)
	}
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}

	analysis := agentguard.AnalyzeTarget("http://" + net.JoinHostPort(normalizedHost, strconv.Itoa(port)))
	if analysis.Hit {
		literal, literalErr := netip.ParseAddr(normalizedHost)
		if literalErr != nil {
			if !routeHostnameAllowed(normalizedHost, analysis.Reason, overrides) {
				return resolvedEgressTarget{}, fmt.Errorf("%w: %s", errUnsafeEgressTarget, analysis.Reason)
			}
		} else if !routeEgressAddrAllowed(literal.Unmap(), allowPrivate, prefixes, overrides) {
			return resolvedEgressTarget{}, fmt.Errorf("%w: %s", errUnsafeEgressTarget, analysis.Reason)
		}
	}

	addrs, err := lookup(ctx, normalizedHost)
	if err != nil {
		return resolvedEgressTarget{}, fmt.Errorf("resolve egress host: %w", err)
	}
	if len(addrs) == 0 {
		return resolvedEgressTarget{}, fmt.Errorf("resolve egress host: no addresses")
	}

	var selected netip.Addr
	for _, item := range addrs {
		addr, err := netip.ParseAddr(item.IP.String())
		if err != nil {
			return resolvedEgressTarget{}, fmt.Errorf("parse resolved egress address: %w", err)
		}
		addr = addr.Unmap()
		if !routeEgressAddrAllowed(addr, allowPrivate, prefixes, overrides) {
			return resolvedEgressTarget{}, fmt.Errorf("%w: resolved %s", errUnsafeEgressTarget, addr.String())
		}
		if !selected.IsValid() {
			selected = addr
		}
	}
	if !selected.IsValid() {
		return resolvedEgressTarget{}, fmt.Errorf("resolve egress host: no usable address")
	}
	return resolvedEgressTarget{
		Host:        normalizedHost,
		Port:        port,
		DialAddress: net.JoinHostPort(selected.String(), strconv.Itoa(port)),
	}, nil
}

// routeHostnameAllowed 判断被判为内部名的主机名能否继续解析：内部主机名开关放开全部，
// 回环开关放开 localhost 一类，元数据开关放开元数据名。解析出的地址仍逐个判定。
func routeHostnameAllowed(host, reason string, overrides safetarget.EgressOverrides) bool {
	if overrides.AllowInternalHostnames {
		return true
	}
	if reason == "blocked_cloud_metadata_hostname" {
		return overrides.AllowMetadata
	}
	if host == "localhost" || host == "localhost.localdomain" || strings.HasSuffix(host, ".localhost") {
		return overrides.AllowLoopback
	}
	return false
}

// routeEgressAddrAllowed 只把地址类别（egresspolicy.Classify，按网关 2.9.21 口径 CompatGatewayProxy）
// 映射到路由的开关：元数据、回环、链路本地各认 egress_overrides 里自己的开关；内网只认私网授权网段
// （授权网段盖住元数据地址也不放，如 fd00::/8 与 fd00:ec2::254）；保留、组播、未指定地址始终拒绝；
// 公网放行。被目标分析判为内部地址的 IP 字面量同样走这里。
func routeEgressAddrAllowed(addr netip.Addr, allowPrivate bool, prefixes []netip.Prefix, overrides safetarget.EgressOverrides) bool {
	addr = addr.Unmap()
	switch egresspolicy.CompatGatewayProxy.Classify(addr) {
	case egresspolicy.ClassMetadata:
		return overrides.AllowMetadata
	case egresspolicy.ClassLoopback:
		return overrides.AllowLoopback
	case egresspolicy.ClassLinkLocal:
		return overrides.AllowLinkLocal
	case egresspolicy.ClassReserved:
		return false
	case egresspolicy.ClassPrivate:
		return allowPrivate && privateEgressPrefixListed(addr, prefixes)
	}
	return true
}

func parsePrivateEgressCIDRs(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, err
		}
		prefix = prefix.Masked()
		key := prefix.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func privateEgressPrefixListed(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
