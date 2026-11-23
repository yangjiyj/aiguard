package directoryldap

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"unicode"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
	"github.com/go-ldap/ldap/v3"
)

const (
	directoryLDAPTargetAllowlistEnv = "DIRECTORY_LDAP_TARGET_ALLOWLIST"
	directoryLDAPAllowedCIDRsEnv    = "DIRECTORY_LDAP_ALLOWED_CIDRS"
	maxUserFilterLength             = 4096
)

var (
	ErrTargetNotAllowed  = errors.New("directory connection target is not deployment approved")
	ErrInvalidUserFilter = errors.New("directory user filter is invalid")
)

type Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type TargetPolicy struct {
	allowedTargets map[string]struct{}
	allowedCIDRs   []netip.Prefix
	resolver       Resolver
}

type Target struct {
	Hostname    string
	Port        string
	DialAddress string
	Transport   Transport
}

func LoadTargetPolicyFromEnvironment() (TargetPolicy, error) {
	return ParseTargetPolicy(os.Getenv(directoryLDAPTargetAllowlistEnv), os.Getenv(directoryLDAPAllowedCIDRsEnv))
}

func ParseTargetPolicy(rawTargets, rawCIDRs string) (TargetPolicy, error) {
	policy := TargetPolicy{allowedTargets: map[string]struct{}{}}
	for _, entry := range strings.Split(rawTargets, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		host, port, ok := parseAllowedTarget(entry)
		if !ok {
			return TargetPolicy{}, ErrInvalidTarget
		}
		policy.allowedTargets[net.JoinHostPort(host, port)] = struct{}{}
	}
	for _, entry := range strings.Split(rawCIDRs, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(entry)

		if err != nil {
			return TargetPolicy{}, ErrInvalidTarget
		}
		policy.allowedCIDRs = append(policy.allowedCIDRs, prefix.Masked())
	}
	return policy, nil
}

func ValidateConfigWithPolicy(ctx context.Context, config Config, policy TargetPolicy) (Target, error) {
	if err := ValidateConfig(config); err != nil {
		return Target{}, err
	}
	host, port, transport, ok := connectionHostAndPort(config.ConnectionURL)
	if !ok {
		return Target{}, ErrInvalidTarget
	}
	if _, ok := policy.allowedTargets[net.JoinHostPort(host, port)]; !ok {
		// 不在目标名单是配置问题，不记“防跳板拒绝”安全事件，只留一行日志。
		log.Printf("directory LDAP target %s not in allowed target list, rejected", net.JoinHostPort(host, port))
		return Target{}, ErrTargetNotAllowed
	}
	resolver := policy.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	answers, err := resolver.LookupIPAddr(ctx, host)
	if err != nil || len(answers) == 0 {
		return Target{}, ErrInvalidTarget
	}
	var selected netip.Addr
	for _, answer := range answers {
		if answer.Zone != "" {
			return Target{}, ErrInvalidTarget
		}
		address, ok := netip.AddrFromSlice(answer.IP)
		if !ok {
			return Target{}, ErrInvalidTarget
		}
		address = address.Unmap()
		if !isApprovedDirectoryAddress(address, policy.allowedCIDRs) {
			recordDirectoryEgressDenied(ctx, host)
			return Target{}, ErrInvalidTarget
		}
		if !selected.IsValid() {
			selected = address
		}
	}
	if !selected.IsValid() {
		return Target{}, ErrInvalidTarget
	}
	return Target{Hostname: host, Port: port, DialAddress: net.JoinHostPort(selected.String(), port), Transport: transport}, nil
}

func ValidateUserFilter(filter string) error {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return nil
	}
	if len(filter) > maxUserFilterLength || strings.IndexFunc(filter, unicode.IsControl) >= 0 {
		return ErrInvalidUserFilter
	}
	if _, err := ldap.CompileFilter(filter); err != nil {
		return ErrInvalidUserFilter
	}
	return nil
}

// parseAllowedTarget：部署批准的目标为「精确主机名[:端口]」。
// 省略端口等价于 :636（与旧版一致）；其它端口（389/3268/3269/自定义）必须显式写出，
// 例如 "dc.corp.example:3269"、"ldap.corp.example:389"。
func parseAllowedTarget(entry string) (string, string, bool) {
	host, port := entry, defaultLDAPSPort
	if strings.Contains(entry, ":") {
		var err error
		host, port, err = net.SplitHostPort(entry)
		if err != nil || !validPort(port) {
			return "", "", false
		}
	}
	host = normalizedDirectoryHostname(host)
	if host == "" || net.ParseIP(host) != nil || isBlockedDirectoryHostname(host) {
		return "", "", false
	}
	return host, port, true
}

func connectionHostAndPort(raw string) (string, string, Transport, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", "", false
	}
	transport, err := TransportFor(raw)
	if err != nil {
		return "", "", "", false
	}
	host := normalizedDirectoryHostname(parsed.Hostname())
	port := parsed.Port()
	if port == "" {
		port = defaultPortFor(transport)
	}
	if host == "" || net.ParseIP(host) != nil || isBlockedDirectoryHostname(host) || !validPort(port) {
		return "", "", "", false
	}
	return host, port, transport, true
}

func normalizedDirectoryHostname(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func isBlockedDirectoryHostname(host string) bool {
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || egresspolicy.IsMetadataHostname(host)
}

func isApprovedDirectoryAddress(address netip.Addr, allowed []netip.Prefix) bool {
	if address.IsLoopback() || address.IsUnspecified() || address.IsLinkLocalUnicast() ||
		address.IsLinkLocalMulticast() || address.IsInterfaceLocalMulticast() || address.IsMulticast() || isMetadataAddress(address) {
		return false
	}
	for _, prefix := range allowed {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func isMetadataAddress(address netip.Addr) bool {
	return egresspolicy.IsMetadataAddr(address)
}

// EgressDeniedRecorder 在 LDAP 目标解析出的地址不在批准网段（防跳板出站拒绝）时记安全事件（控制面启动时装配）。
// 目标不在名单不记。
var EgressDeniedRecorder func(ctx context.Context, host string)

func recordDirectoryEgressDenied(ctx context.Context, host string) {
	if EgressDeniedRecorder != nil {
		EgressDeniedRecorder(ctx, host)
	}
}

// LDAPAllowedTargetsSetting 是 system_settings 里的 LDAP 目标名单键（JSON 字符串数组，每项
// “主机名[:端口]”，与 DIRECTORY_LDAP_TARGET_ALLOWLIST 同语义）。库里有该键时替换部署名单。
const LDAPAllowedTargetsSetting = "ldap_allowed_targets"

// ParseAllowedTargetsSetting 解析 ldap_allowed_targets 的值；每项都必须是合法目标。
func ParseAllowedTargetsSetting(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil, ErrInvalidTarget
	}
	var out []string
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		host, port, ok := parseAllowedTarget(entry)
		if !ok {
			return nil, ErrInvalidTarget
		}
		out = append(out, net.JoinHostPort(host, port))
	}
	return out, nil
}

// WithAllowedTargets 返回用 targets 替换部署目标名单后的策略（网段名单不变）。
func (policy TargetPolicy) WithAllowedTargets(targets []string) (TargetPolicy, error) {
	replaced := TargetPolicy{allowedTargets: map[string]struct{}{}, allowedCIDRs: policy.allowedCIDRs, resolver: policy.resolver}
	for _, entry := range targets {
		host, port, ok := parseAllowedTarget(strings.TrimSpace(entry))
		if !ok {
			return TargetPolicy{}, ErrInvalidTarget
		}
		replaced.allowedTargets[net.JoinHostPort(host, port)] = struct{}{}
	}
	return replaced, nil
}

// WithResolver returns a policy with the supplied resolver.
func (policy TargetPolicy) WithResolver(resolver Resolver) TargetPolicy {
	policy.resolver = resolver
	return policy
}
