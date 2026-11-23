package safetarget

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
)

// EgressOverrides 是 reverse_proxy_routes.egress_overrides、mcp_servers.egress_overrides
// 列的内容（JSONB，缺省 {}，全部为 false）。后三项只对 MCP 服务有效。
type EgressOverrides struct {
	AllowLoopback          bool   `json:"allow_loopback"`
	AllowLinkLocal         bool   `json:"allow_link_local"`
	AllowMetadata          bool   `json:"allow_metadata"`
	AllowInternalHostnames bool   `json:"allow_internal_hostnames"`
	TrustedCAPEM           string `json:"trusted_ca_pem"`
	InsecureSkipVerify     bool   `json:"insecure_skip_verify"`
	AllowSameHostRedirect  bool   `json:"allow_same_host_redirect"`
}

// maxTrustedCAPEMBytes 限制自定义 CA 的大小（几张证书足够）。
const maxTrustedCAPEMBytes = 64 << 10

// ParseEgressOverrides 严格解析列内容：未知键、类型不对、CA 不是证书都报错。空输入是零值。
func ParseEgressOverrides(raw []byte) (EgressOverrides, error) {
	var out EgressOverrides
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return out, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		return EgressOverrides{}, fmt.Errorf("egress_overrides: %w", err)
	}
	return out, out.Validate()
}

// Validate 校验自定义 CA。
func (o EgressOverrides) Validate() error {
	pemText := strings.TrimSpace(o.TrustedCAPEM)
	if pemText == "" {
		return nil
	}
	if len(pemText) > maxTrustedCAPEMBytes {
		return fmt.Errorf("egress_overrides: trusted_ca_pem exceeds %d bytes", maxTrustedCAPEMBytes)
	}
	if !x509.NewCertPool().AppendCertsFromPEM([]byte(pemText)) {
		return ErrInvalidTrustedCA
	}
	return nil
}

// Enabled 按固定顺序列出已打开的项（写审计 egress_override.enable 用）。
func (o EgressOverrides) Enabled() []string {
	var out []string
	for _, item := range []struct {
		name string
		on   bool
	}{
		{"allow_loopback", o.AllowLoopback},
		{"allow_link_local", o.AllowLinkLocal},
		{"allow_metadata", o.AllowMetadata},
		{"allow_internal_hostnames", o.AllowInternalHostnames},
		{"trusted_ca_pem", strings.TrimSpace(o.TrustedCAPEM) != ""},
		{"insecure_skip_verify", o.InsecureSkipVerify},
		{"allow_same_host_redirect", o.AllowSameHostRedirect},
	} {
		if item.on {
			out = append(out, item.name)
		}
	}
	return out
}

// NewlyEnabled 列出 next 相对 prev 新打开的项（自定义 CA 内容变化也算）。
func NewlyEnabled(prev, next EgressOverrides) []string {
	before := map[string]bool{}
	for _, name := range prev.Enabled() {
		before[name] = true
	}
	var out []string
	for _, name := range next.Enabled() {
		if !before[name] || (name == "trusted_ca_pem" && strings.TrimSpace(prev.TrustedCAPEM) != strings.TrimSpace(next.TrustedCAPEM)) {
			out = append(out, name)
		}
	}
	return out
}

// ForReverseProxy 去掉只对 MCP 服务有效的三项（证书与重定向）。
func (o EgressOverrides) ForReverseProxy() EgressOverrides {
	o.TrustedCAPEM, o.InsecureSkipVerify, o.AllowSameHostRedirect = "", false, false
	return o
}

// Options 把对象级放行与对象原有的内网放行开关合成 safetarget 选项。
func (o EgressOverrides) Options(allowPrivate bool) Options {
	return Options{
		AllowPrivate:           allowPrivate,
		AllowLoopback:          o.AllowLoopback,
		AllowLinkLocal:         o.AllowLinkLocal,
		AllowMetadata:          o.AllowMetadata,
		AllowInternalHostnames: o.AllowInternalHostnames,
		TrustedCAPEM:           o.TrustedCAPEM,
		InsecureSkipVerify:     o.InsecureSkipVerify,
		AllowSameHostRedirect:  o.AllowSameHostRedirect,
	}
}
