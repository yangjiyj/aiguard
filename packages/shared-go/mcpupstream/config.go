// Package mcpupstream 是 MCP 上游连接的通用适配层，control-plane 与 gateway-core 共用：
// 上游连接配置（transport / 鉴权位置 / 值模板 / 额外请求头）、URL 脱敏、错误分类、
// 旧 HTTP+SSE transport 客户端。不含任何按厂商分支的逻辑——厂商差异全部用配置表达。
package mcpupstream

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	TransportAuto           = "auto"
	TransportStreamableHTTP = "streamable_http"
	TransportSSE            = "sse"

	AuthHeader = "header"
	AuthQuery  = "query"
	// AuthPath 表示密钥在 URL 路径里（如 https://x.com/mcp/<token>/sse）：server_url 用 {secret}
	// 标出位置，请求时才替换为路径段编码后的真实密钥；库里、展示、日志、审计一律只出现占位形式。
	AuthPath = "path"

	// SecretPlaceholder 是值模板里代表密钥的占位符。
	SecretPlaceholder = "{secret}"
	TemplateBearer    = "Bearer {secret}"
	TemplateRaw       = "{secret}"
)

// capabilities_json 中的键（不新增迁移，全部放在 capabilities 里；auth_header_name 沿用存量键名）。
const (
	CapAuthHeaderName     = "auth_header_name"
	CapAuthLocation       = "upstream_auth_location"
	CapAuthQueryParam     = "upstream_auth_query_param"
	CapAuthTemplate       = "upstream_auth_template"
	CapExtraHeaders       = "upstream_extra_headers"
	CapDetectedTransport  = "detected_transport"
	CapProtocolVersion    = "protocol_version"
	CapProtocolVersionRaw = "protocol_version_raw"
	CapProtocolForward    = "protocol_version_forward_compat"
)

const (
	maxExtraHeaders     = 16
	maxExtraHeaderValue = 512
	maxTemplateAffix    = 32
	maxParamNameLen     = 64
)

// Config 是单个 MCP server 的上游连接配置（由 transport 列 + capabilities_json 解析而来）。
type Config struct {
	// Transport 是配置值：auto / streamable_http / sse。
	Transport string
	// DetectedTransport 是 auto 探测后记录的结果（streamable_http / sse），空表示尚未探测。
	DetectedTransport string
	AuthLocation      string
	// AuthName 在 header 模式是头名，在 query 模式是参数名。
	AuthName     string
	AuthTemplate string
	ExtraHeaders map[string]string
	// UsesNewCapabilities=true 表示该服务显式配置了新字段（query 鉴权 / 自定义值模板 / 额外请求头），
	// 或 transport 为 sse/auto。只有此时才使用统一 User-Agent；存量 streamable_http 行保持改造前的
	// 请求头集合（网关透传下游 UA，控制面保持 Go 默认 UA），做到字节级兼容。
	UsesNewCapabilities bool
	// LegacyAuthHeaderName=true 表示鉴权头名来自存量字段 auth_header_name：运行时沿用改造前的宽松校验
	// （仅拒绝旧黑名单），不用新增的更严黑名单卡住已经在用的存量配置；新建 / 修改保存时才按新黑名单校验。
	LegacyAuthHeaderName bool
}

// ParseConfig 解析配置。transportColumn 是 mcp_servers.transport 列；caps 是 capabilities_json。
// 存量数据（capabilities 没有任何新字段）解析结果与历史行为完全一致：
// header 模式，头名默认 Authorization，Authorization 用 Bearer 模板，其他头名原样。
func ParseConfig(transportColumn string, caps map[string]interface{}) (Config, error) {
	cfg := Config{Transport: strings.ToLower(strings.TrimSpace(transportColumn))}
	if cfg.Transport == "" {
		cfg.Transport = TransportStreamableHTTP
	}
	switch cfg.Transport {
	case TransportAuto, TransportStreamableHTTP, TransportSSE:
	default:
		// 存量行为：除 sse 外一律按 streamable_http 处理。
		cfg.Transport = TransportStreamableHTTP
	}
	if d := strings.ToLower(capString(caps, CapDetectedTransport)); d == TransportStreamableHTTP || d == TransportSSE {
		cfg.DetectedTransport = d
	}

	cfg.AuthLocation = strings.ToLower(capString(caps, CapAuthLocation))
	switch cfg.AuthLocation {
	case "":
		cfg.AuthLocation = AuthHeader
	case AuthHeader, AuthQuery, AuthPath:
	default:
		return cfg, fmt.Errorf("鉴权位置配置无效：%q（仅支持 header / query / path）", cfg.AuthLocation)
	}

	switch cfg.AuthLocation {
	case AuthHeader:
		name := capString(caps, CapAuthHeaderName)
		if name == "" {
			name = "Authorization"
		}
		// 头名合法性推迟到 ApplyAuth（存在密钥时）才校验：存量行里无密钥但头名异常的配置照常可用。
		cfg.AuthName = http.CanonicalHeaderKey(name)
		cfg.LegacyAuthHeaderName = capString(caps, CapAuthHeaderName) != ""
		cfg.AuthTemplate = capString(caps, CapAuthTemplate)
		if cfg.AuthTemplate == "" {
			if strings.EqualFold(name, "Authorization") {
				cfg.AuthTemplate = TemplateBearer
			} else {
				cfg.AuthTemplate = TemplateRaw
			}
		}
	case AuthQuery:
		name := capString(caps, CapAuthQueryParam)
		if !ValidQueryParamName(name) {
			return cfg, fmt.Errorf("MCP 上游鉴权参数名配置无效")
		}
		cfg.AuthName = name
		cfg.AuthTemplate = capString(caps, CapAuthTemplate)
		if cfg.AuthTemplate == "" {
			cfg.AuthTemplate = TemplateRaw
		}
	case AuthPath:
		// 路径模式：密钥原样替换占位符，不套值模板；头名 / 参数名无意义。
		cfg.AuthName = ""
		cfg.AuthTemplate = TemplateRaw
	}
	if err := ValidateTemplate(cfg.AuthTemplate); err != nil {
		return cfg, err
	}

	extra, err := parseExtraHeaders(caps[CapExtraHeaders])
	if err != nil {
		return cfg, err
	}
	for name := range extra {
		if cfg.AuthLocation == AuthHeader && strings.EqualFold(name, cfg.AuthName) {
			return cfg, fmt.Errorf("额外请求头 %s 与鉴权头重名", name)
		}
	}
	cfg.ExtraHeaders = extra
	cfg.UsesNewCapabilities = cfg.Transport != TransportStreamableHTTP ||
		cfg.AuthLocation == AuthQuery || cfg.AuthLocation == AuthPath || len(extra) > 0 ||
		capString(caps, CapAuthTemplate) != ""
	return cfg, nil
}

// ValidateForSave 在“新建 / 修改保存”时按严格口径校验配置：鉴权头名需通过完整黑名单。
// 运行时（ParseConfig + ApplyAuth）对存量头名走旧口径（LegacyAuthHeaderName），不会被它卡住。
func (c Config) ValidateForSave() error {
	if c.AuthLocation == AuthHeader && c.AuthName != "" && !ValidAuthHeaderName(c.AuthName) {
		return fmt.Errorf("鉴权请求头名称 %s 不允许使用（逐跳或协议保留头），请换一个自定义头名", c.AuthName)
	}
	return nil
}

// legacyAuthHeaderAllowed 是改造前网关侧的鉴权头名黑名单（validMCPAuthHeaderName），
// 也是存量行运行时继续沿用的口径。
func legacyAuthHeaderAllowed(name string) bool {
	if !validToken(name) {
		return false
	}
	switch strings.ToLower(name) {
	case "host", "cookie", "set-cookie", "content-length", "content-type", "connection",
		"proxy-authorization", "proxy-connection", "transfer-encoding", "mcp-session-id", "mcp-protocol-version":
		return false
	}
	return true
}

// EffectiveTransport 返回实际使用的 transport：显式配置优先；auto 用已探测结果，
// 未探测时返回 auto（调用方需先探测）。
func (c Config) EffectiveTransport() string {
	switch c.Transport {
	case TransportStreamableHTTP, TransportSSE:
		return c.Transport
	}
	if c.DetectedTransport != "" {
		return c.DetectedTransport
	}
	return TransportAuto
}

// RenderSecret 把密钥套进值模板。
func RenderSecret(template, secret string) string {
	return strings.Replace(template, SecretPlaceholder, secret, 1)
}

// ValidateTemplate 校验值模板：恰好一个 {secret}，前后缀只允许短小的安全字符（防头注入/滥用）。
func ValidateTemplate(t string) error {
	if strings.Count(t, SecretPlaceholder) != 1 {
		return fmt.Errorf("鉴权值模板必须恰好包含一个 {密钥} 占位")
	}
	prefix, suffix, _ := strings.Cut(t, SecretPlaceholder)
	for _, part := range []string{prefix, suffix} {
		if len(part) > maxTemplateAffix {
			return fmt.Errorf("鉴权值模板过长")
		}
		for _, r := range part {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == ' ', r == '-', r == '_', r == '.', r == ':':
			default:
				return fmt.Errorf("鉴权值模板包含不允许的字符")
			}
		}
	}
	return nil
}

// ValidAuthHeaderName 校验鉴权头名：合法 token + 禁用头黑名单。
func ValidAuthHeaderName(name string) bool {
	if !validToken(name) {
		return false
	}
	switch strings.ToLower(name) {
	case "host", "content-length", "content-type", "content-encoding", "accept", "accept-encoding",
		"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
		"te", "trailer", "transfer-encoding", "upgrade", "cookie", "set-cookie", "expect",
		"user-agent", "mcp-session-id", "mcp-protocol-version", "last-event-id":
		return false
	}
	return true
}

// ValidQueryParamName 校验鉴权 query 参数名。
func ValidQueryParamName(name string) bool {
	if name == "" || len(name) > maxParamNameLen {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
		default:
			return false
		}
	}
	return true
}

// ValidExtraHeaderValue 校验额外请求头的值：非空白可见字符，禁控制字符。
func ValidExtraHeaderValue(v string) bool {
	if v == "" || len(v) > maxExtraHeaderValue {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

func parseExtraHeaders(raw interface{}) (map[string]string, error) {
	if raw == nil {
		return nil, nil
	}
	out := map[string]string{}
	switch m := raw.(type) {
	case map[string]interface{}:
		for k, v := range m {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("额外请求头 %s 的值必须是字符串", k)
			}
			out[k] = s
		}
	case map[string]string:
		for k, v := range m {
			out[k] = v
		}
	default:
		return nil, fmt.Errorf("额外请求头配置格式无效")
	}
	if len(out) > maxExtraHeaders {
		return nil, fmt.Errorf("额外请求头最多 %d 个", maxExtraHeaders)
	}
	canon := make(map[string]string, len(out))
	for k, v := range out {
		name := http.CanonicalHeaderKey(strings.TrimSpace(k))
		if !ValidAuthHeaderName(name) {
			return nil, fmt.Errorf("额外请求头 %q 不合法或在禁用名单内", k)
		}
		if !ValidExtraHeaderValue(v) {
			return nil, fmt.Errorf("额外请求头 %s 的值不合法", name)
		}
		canon[name] = v
	}
	if len(canon) == 0 {
		return nil, nil
	}
	return canon, nil
}

func capString(caps map[string]interface{}, key string) string {
	if caps == nil {
		return ""
	}
	s, _ := caps[key].(string)
	return strings.TrimSpace(s)
}

// validToken 判断是否为合法 HTTP token（RFC 7230）。
func validToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// SetQueryParam 在 URL 上设置（覆盖同名）一个 query 参数，保持其余参数的原始顺序与编码。
// SSE 的 endpoint 事件自带 query（如 sessionId）时用它合并鉴权参数，而不是覆盖整段 query。
func SetQueryParam(u *url.URL, name, value string) {
	var keep []string
	for _, pair := range strings.Split(u.RawQuery, "&") {
		if pair == "" {
			continue
		}
		k, _, _ := strings.Cut(pair, "=")
		if dec, err := url.QueryUnescape(k); err == nil && dec == name {
			continue
		}
		keep = append(keep, pair)
	}
	keep = append(keep, url.QueryEscape(name)+"="+url.QueryEscape(value))
	u.RawQuery = strings.Join(keep, "&")
}

// RemoveQueryParam 删除同名 query 参数（防止调用方在下游请求里夹带同名参数覆盖上游鉴权）。
func RemoveQueryParam(u *url.URL, name string) {
	var keep []string
	for _, pair := range strings.Split(u.RawQuery, "&") {
		if pair == "" {
			continue
		}
		k, _, _ := strings.Cut(pair, "=")
		if dec, err := url.QueryUnescape(k); err == nil && dec == name {
			continue
		}
		keep = append(keep, pair)
	}
	u.RawQuery = strings.Join(keep, "&")
}
