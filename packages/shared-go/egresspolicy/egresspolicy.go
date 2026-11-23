// Package egresspolicy 是正向代理（网关 8082 与独立代理）防跳板出站的平台级设置：
// 允许内网、回环、元数据三个开关，放行网段与主机名名单，未登记目标与白名单读取失败的处置。
// 设置存在 system_settings；默认全部拒绝。全局观察留痕不改变这里的判定。
//
// 全平台唯一的地址分类（Classify）、云元数据地址和元数据主机名清单也在这里：safetarget、网关正向与
// 反向代理、独立代理只把类别映射到各自的开关，各组件 2.9.21 口径的差别集中在 Compat。
package egresspolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// system_settings 键（契约见 2.9.22 计划 2.2 节）。
const (
	KeyAllowPrivate      = "forward_proxy_egress_allow_private"
	KeyAllowLoopback     = "forward_proxy_egress_allow_loopback"
	KeyAllowMetadata     = "forward_proxy_egress_allow_metadata"
	KeyAllowedCIDRs      = "forward_proxy_egress_allowed_cidrs"
	KeyAllowedHosts      = "forward_proxy_egress_allowed_hosts"
	KeyUnlistedAction    = "forward_proxy_unlisted_action"
	KeyWhitelistFailMode = "proxy_whitelist_fail_mode"
)

// Keys 是全部正向代理出站设置键。
var Keys = []string{KeyAllowPrivate, KeyAllowLoopback, KeyAllowMetadata, KeyAllowedCIDRs, KeyAllowedHosts, KeyUnlistedAction, KeyWhitelistFailMode}

const (
	UnlistedDeny       = "deny"
	UnlistedAllowAudit = "allow_audit"
	FailClosed         = "closed"
	FailOpen           = "open"
)

const (
	maxListEntries = 256
	maxHostLength  = 253
)

// 事件原因码：拒绝时记安全事件；因设置放行内部地址时也记一条。
const (
	ReasonInternalEgressDenied  = "forward_proxy_internal_egress_denied"
	ReasonInternalEgressAllowed = "forward_proxy_internal_egress_allowed"
)

// Settings 是解析后的出站放行设置。零值即默认：全部拒绝。
type Settings struct {
	AllowPrivate  bool
	AllowLoopback bool
	AllowMetadata bool
	AllowedCIDRs  []netip.Prefix
	// AllowedHosts 是主机名（精确）或以 . 开头的后缀（匹配该域及其子域）。只放过主机名层面的
	// 检查，解析出的地址仍逐个按开关和网段判定（防 DNS 重绑定）。
	AllowedHosts []string
	// Compat 由组件设置，不来自控制台：组件沿用的 2.9.21 口径（见 Compat）。零值即 Classify 的口径。
	Compat Compat
}

// Class 是地址类别。全平台只有这一份分类（Classify）：safetarget、网关正向与反向代理、独立代理都只把
// 类别映射到自己的开关。
type Class string

const (
	ClassPublic    Class = "public"
	ClassPrivate   Class = "private"
	ClassLoopback  Class = "loopback"
	ClassLinkLocal Class = "link_local"
	ClassMetadata  Class = "metadata"
	ClassReserved  Class = "reserved"
)

// metadataAddresses 是云元数据地址（全平台唯一一份）。
var metadataAddresses = map[netip.Addr]struct{}{
	netip.MustParseAddr("169.254.169.254"): {}, // AWS、Azure、GCP、OCI 的 IMDS。
	netip.MustParseAddr("169.254.170.2"):   {}, // AWS ECS 任务元数据。
	netip.MustParseAddr("100.100.100.200"): {}, // 阿里云。
	netip.MustParseAddr("168.63.129.16"):   {}, // Azure 平台虚拟 IP（WireServer）。
	netip.MustParseAddr("fd00:ec2::254"):   {}, // AWS IMDS 的 IPv6 端点。
	netip.MustParseAddr("fd20:ce::254"):    {}, // GCP IMDS 的 IPv6 端点。
}

// metadataHostnames 是云元数据主机名（全平台唯一一份）。
var metadataHostnames = map[string]struct{}{
	"metadata":                   {},
	"metadata.google.internal":   {},
	"metadata.goog":              {},
	"metadata.azure.internal":    {},
	"metadata.oraclecloud.com":   {},
	"instance-data":              {},
	"instance-data.ec2.internal": {},
}

var (
	// cgnatPrefix 是 RFC 6598 共享地址（运营商级 NAT、Tailscale）。
	cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")
	// benchmarkPrefixes 是基准测试网段（RFC 2544、RFC 5180）。
	benchmarkPrefixes = []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("2001:2::/48")}
	// reservedPrefixes 是不可连接的保留网段：RFC 1122 “本网络”、240/4、RFC 6666 丢弃前缀。
	reservedPrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("100::/64")}
	wireServer       = netip.MustParseAddr("168.63.129.16")
	ipv4Broadcast    = netip.MustParseAddr("255.255.255.255")
)

// IsMetadataAddr 判断是不是云元数据地址（IPv4 映射地址先还原）。
func IsMetadataAddr(addr netip.Addr) bool {
	_, ok := metadataAddresses[addr.Unmap()]
	return ok
}

// IsMetadataHostname 判断是不是云元数据主机名（不区分大小写，忽略末尾的点）。
func IsMetadataHostname(host string) bool {
	_, ok := metadataHostnames[NormalizeHost(host)]
	return ok
}

func inPrefixes(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Classify 给地址归类（与 safetarget 2.9.21 的口径一致）：元数据地址先于所在网段；未指定、组播和保留
// 网段不是可连接的目标；RFC1918/ULA、CGNAT、基准测试网段算内网；其余非全局单播（如广播）算保留。
func Classify(addr netip.Addr) Class {
	addr = addr.Unmap()
	switch {
	case !addr.IsValid():
		return ClassReserved
	case IsMetadataAddr(addr):
		return ClassMetadata
	case addr.IsLoopback():
		return ClassLoopback
	case addr.IsLinkLocalUnicast():
		return ClassLinkLocal
	case addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() ||
		inPrefixes(reservedPrefixes, addr):
		return ClassReserved
	case addr.IsPrivate() || cgnatPrefix.Contains(addr) || inPrefixes(benchmarkPrefixes, addr):
		return ClassPrivate
	case !addr.IsGlobalUnicast():
		return ClassReserved
	}
	return ClassPublic
}

// Compat 是组件为保持 2.9.21 默认判定、在 Classify 的结果上按公网处理的几类网段：2.9.21 时网关正向代理、
// 反向代理路由和独立代理各自分类，口径比 safetarget 窄。只改判这几类，其余一律按 Classify。零值即
// Classify 的口径（safetarget）。
type Compat struct {
	// CGNATIsPublic：100.64.0.0/10 按公网（其中的阿里云元数据地址仍是元数据）。
	CGNATIsPublic bool
	// WireServerIsPublic：Azure 168.63.129.16 按公网。
	WireServerIsPublic bool
	// BenchmarkIsPublic：198.18.0.0/15、2001:2::/48 按公网。
	BenchmarkIsPublic bool
	// ReservedPrefixesArePublic：0.0.0.0/8、240.0.0.0/4、100::/64 按公网（未指定地址和广播除外）。
	ReservedPrefixesArePublic bool
}

var (
	// CompatGatewayProxy 是网关正向代理（8082）和反向代理路由的 2.9.21 口径：内网只认 RFC1918/ULA，元数据
	// 只认 IPv4 的三个地址（IPv6 的两个元数据端点在 ULA 里，2.9.21 照样拦）。
	CompatGatewayProxy = Compat{CGNATIsPublic: true, WireServerIsPublic: true, BenchmarkIsPublic: true, ReservedPrefixesArePublic: true}
	// CompatProxyServer 是独立代理的 2.9.21 口径：比网关多把 CGNAT 当内网。
	CompatProxyServer = Compat{WireServerIsPublic: true, BenchmarkIsPublic: true, ReservedPrefixesArePublic: true}
)

// Classify 是带兼容口径的 Classify。
func (c Compat) Classify(addr netip.Addr) Class {
	addr = addr.Unmap()
	class := Classify(addr)
	switch class {
	case ClassMetadata:
		if c.WireServerIsPublic && addr == wireServer {
			return ClassPublic
		}
	case ClassPrivate:
		if (c.CGNATIsPublic && cgnatPrefix.Contains(addr)) || (c.BenchmarkIsPublic && inPrefixes(benchmarkPrefixes, addr)) {
			return ClassPublic
		}
	case ClassReserved:
		if c.ReservedPrefixesArePublic && inPrefixes(reservedPrefixes, addr) && !addr.IsUnspecified() && addr != ipv4Broadcast {
			return ClassPublic
		}
	}
	return class
}

// Verdict 是一个地址的判定：Allowed 为放行；ViaSetting 表示它不是公网地址、靠设置放行。
type Verdict struct {
	Class      Class
	Allowed    bool
	ViaSetting bool
}

// CheckAddr 判定一个已解析地址（按 s.Compat 归类）。公网放行；元数据只认元数据开关；回环、内网各认自己的
// 开关；放行网段可放开回环、链路本地、内网，但不放开元数据（要单独打开元数据开关）；未指定地址、组播、
// 保留网段等不是可连接的目标，一律拒绝。
func (s Settings) CheckAddr(addr netip.Addr) Verdict {
	addr = addr.Unmap()
	class := s.Compat.Classify(addr)
	v := Verdict{Class: class}
	switch class {
	case ClassPublic:
		v.Allowed = true
		return v
	case ClassReserved:
		return v
	case ClassMetadata:
		v.Allowed = s.AllowMetadata
	case ClassLoopback:
		v.Allowed = s.AllowLoopback || s.cidrListed(addr)
	case ClassPrivate:
		v.Allowed = s.AllowPrivate || s.cidrListed(addr)
	case ClassLinkLocal:
		v.Allowed = s.cidrListed(addr)
	}
	v.ViaSetting = v.Allowed
	return v
}

func (s Settings) cidrListed(addr netip.Addr) bool {
	for _, prefix := range s.AllowedCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// HostListed 判断主机名是否在放行名单里：精确相等，或名单项以 . 开头时匹配该域及其子域。
func (s Settings) HostListed(host string) bool {
	host = NormalizeHost(host)
	if host == "" {
		return false
	}
	for _, entry := range s.AllowedHosts {
		if strings.HasPrefix(entry, ".") {
			if host == strings.TrimPrefix(entry, ".") || strings.HasSuffix(host, entry) {
				return true
			}
			continue
		}
		if host == entry {
			return true
		}
	}
	return false
}

// Relaxed 表示至少打开了一项放行。
func (s Settings) Relaxed() bool {
	return s.AllowPrivate || s.AllowLoopback || s.AllowMetadata || len(s.AllowedCIDRs) > 0 || len(s.AllowedHosts) > 0
}

// NormalizeHost 小写、去首尾空白和末尾的点、去 IPv6 方括号。
func NormalizeHost(host string) string {
	return strings.TrimSuffix(strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]"), ".")
}

func parseBool(raw string) bool {
	return strings.EqualFold(strings.TrimSpace(raw), "true")
}

// FromValues 从 system_settings 的键值解析设置；缺键取默认（拒绝）。某个键的值格式不对时只丢这个键
// （按默认），其余照常生效，并在 error 里报出坏的键：写接口据此拒绝保存，运行时记日志后用返回的设置。
func FromValues(values map[string]string) (Settings, error) {
	s := Settings{
		AllowPrivate:  parseBool(values[KeyAllowPrivate]),
		AllowLoopback: parseBool(values[KeyAllowLoopback]),
		AllowMetadata: parseBool(values[KeyAllowMetadata]),
	}
	var errs []error
	if cidrs, err := ParseCIDRList(values[KeyAllowedCIDRs]); err != nil {
		errs = append(errs, err)
	} else {
		s.AllowedCIDRs = cidrs
	}
	if hosts, err := ParseHostList(values[KeyAllowedHosts]); err != nil {
		errs = append(errs, err)
	} else {
		s.AllowedHosts = hosts
	}
	return s, errors.Join(errs...)
}

func decodeList(raw, key string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil, fmt.Errorf("%s must be a JSON string array", key)
	}
	if len(list) > maxListEntries {
		return nil, fmt.Errorf("%s has more than %d entries", key, maxListEntries)
	}
	return list, nil
}

// ParseCIDRList 解析放行网段 JSON 数组；每项必须带前缀长度（单个地址写 /32 或 /128）。
func ParseCIDRList(raw string) ([]netip.Prefix, error) {
	list, err := decodeList(raw, KeyAllowedCIDRs)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid CIDR %q", KeyAllowedCIDRs, entry)
		}
		// IPv4 映射写法（::ffff:a.b.c.d/n）换算成 IPv4 网段；前缀短于 96 位时换算不了，拒绝。
		addr, bits := prefix.Addr(), prefix.Bits()
		if addr.Is4In6() {
			if bits < 96 {
				return nil, fmt.Errorf("%s: invalid CIDR %q", KeyAllowedCIDRs, entry)
			}
			addr, bits = addr.Unmap(), bits-96
		}
		prefix = netip.PrefixFrom(addr, bits).Masked()
		if !prefix.IsValid() {
			return nil, fmt.Errorf("%s: invalid CIDR %q", KeyAllowedCIDRs, entry)
		}
		if !seen[prefix] {
			seen[prefix] = true
			out = append(out, prefix)
		}
	}
	return out, nil
}

// ParseHostList 解析放行主机名 JSON 数组；每项是主机名或以 . 开头的后缀，统一小写。
func ParseHostList(raw string) ([]string, error) {
	list, err := decodeList(raw, KeyAllowedHosts)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, entry := range list {
		host := NormalizeHost(entry)
		if host == "" {
			continue
		}
		if !validHostEntry(host) {
			return nil, fmt.Errorf("%s: invalid host %q", KeyAllowedHosts, entry)
		}
		if !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	return out, nil
}

func validHostEntry(host string) bool {
	name := strings.TrimPrefix(host, ".")
	if name == "" || len(name) > maxHostLength || strings.Contains(name, "..") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
		default:
			return false
		}
	}
	return true
}

// UnlistedAction 返回未登记目标的处置。库里有合法值时用库里的；库里没有该键时才用
// 部署环境变量 GATEWAY_FORWARD_PROXY_MODE 作初值（tunnel_audit 对应 allow_audit）；默认拒绝。
func UnlistedAction(values map[string]string, envMode string) string {
	if raw, ok := values[KeyUnlistedAction]; ok {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case UnlistedAllowAudit:
			return UnlistedAllowAudit
		default:
			return UnlistedDeny
		}
	}
	if strings.EqualFold(strings.TrimSpace(envMode), "tunnel_audit") || strings.EqualFold(strings.TrimSpace(envMode), UnlistedAllowAudit) {
		return UnlistedAllowAudit
	}
	return UnlistedDeny
}

// WhitelistFailMode 返回白名单读取失败时的处置。库里有该键时用库里的；没有时才用部署环境
// 变量 PROXY_WHITELIST_FAIL_MODE 作初值；默认 closed（拒绝）。
func WhitelistFailMode(values map[string]string, envMode string) string {
	raw, ok := values[KeyWhitelistFailMode]
	if !ok {
		raw = envMode
	}
	if strings.EqualFold(strings.TrimSpace(raw), FailOpen) {
		return FailOpen
	}
	return FailClosed
}

// NormalizeUpdate 校验并规范化一次写入里出现的正向代理设置键（就地改写）。未出现的键不动。
func NormalizeUpdate(settings map[string]string) error {
	for _, key := range []string{KeyAllowPrivate, KeyAllowLoopback, KeyAllowMetadata} {
		raw, ok := settings[key]
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "true":
			settings[key] = "true"
		case "false", "":
			settings[key] = "false"
		default:
			return fmt.Errorf("%s must be true or false", key)
		}
	}
	if raw, ok := settings[KeyAllowedCIDRs]; ok {
		cidrs, err := ParseCIDRList(raw)
		if err != nil {
			return err
		}
		list := make([]string, 0, len(cidrs))
		for _, prefix := range cidrs {
			list = append(list, prefix.String())
		}
		encoded, _ := json.Marshal(list)
		settings[KeyAllowedCIDRs] = string(encoded)
	}
	if raw, ok := settings[KeyAllowedHosts]; ok {
		hosts, err := ParseHostList(raw)
		if err != nil {
			return err
		}
		if hosts == nil {
			hosts = []string{}
		}
		encoded, _ := json.Marshal(hosts)
		settings[KeyAllowedHosts] = string(encoded)
	}
	if raw, ok := settings[KeyUnlistedAction]; ok {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value != UnlistedDeny && value != UnlistedAllowAudit {
			return fmt.Errorf("%s must be deny or allow_audit", KeyUnlistedAction)
		}
		settings[KeyUnlistedAction] = value
	}
	if raw, ok := settings[KeyWhitelistFailMode]; ok {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value != FailClosed && value != FailOpen {
			return fmt.Errorf("%s must be closed or open", KeyWhitelistFailMode)
		}
		settings[KeyWhitelistFailMode] = value
	}
	return nil
}

// Loosened 列出一次写入相对写入前放宽了的键：开关从关到开、名单新增了项、未登记目标改为
// 放行审计、读取失败改为放行。写接口据此额外写一条放行审计。
func Loosened(before, after map[string]string) []string {
	var keys []string
	for _, key := range []string{KeyAllowPrivate, KeyAllowLoopback, KeyAllowMetadata} {
		if raw, ok := after[key]; ok && parseBool(raw) && !parseBool(before[key]) {
			keys = append(keys, key)
		}
	}
	if raw, ok := after[KeyAllowedCIDRs]; ok {
		prev, _ := ParseCIDRList(before[KeyAllowedCIDRs])
		next, _ := ParseCIDRList(raw)
		known := map[netip.Prefix]bool{}
		for _, p := range prev {
			known[p] = true
		}
		for _, p := range next {
			if !known[p] {
				keys = append(keys, KeyAllowedCIDRs)
				break
			}
		}
	}
	if raw, ok := after[KeyAllowedHosts]; ok {
		prev, _ := ParseHostList(before[KeyAllowedHosts])
		next, _ := ParseHostList(raw)
		known := map[string]bool{}
		for _, h := range prev {
			known[h] = true
		}
		for _, h := range next {
			if !known[h] {
				keys = append(keys, KeyAllowedHosts)
				break
			}
		}
	}
	if raw, ok := after[KeyUnlistedAction]; ok && raw == UnlistedAllowAudit && before[KeyUnlistedAction] != UnlistedAllowAudit {
		keys = append(keys, KeyUnlistedAction)
	}
	if raw, ok := after[KeyWhitelistFailMode]; ok && raw == FailOpen && before[KeyWhitelistFailMode] != FailOpen {
		keys = append(keys, KeyWhitelistFailMode)
	}
	return keys
}
