package mcpupstream

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/buildinfo"
)

// UserAgent 返回统一的产品 User-Agent：JJDGuard-MCP/<VERSION>。
func UserAgent() string {
	v := strings.TrimSpace(buildinfo.Current().Version)
	if v == "" || v == "unknown" {
		v = "dev"
	}
	return "JJDGuard-MCP/" + v
}

// ErrCredential 表示上游鉴权配置或密钥不可用（不含任何密钥材料）。
var ErrCredential = Errorf(KindAuthConfig, "MCP 上游鉴权凭据不可用")

// ApplyCommon 设置统一 User-Agent 与额外静态请求头。
// 额外请求头先删后设：调用方（下游客户端）不能通过同名头覆盖管理员配置的值。
func ApplyCommon(req *http.Request, cfg Config) {
	// 统一产品 UA 只用于新能力（显式配置了新字段，或 sse / auto 传输）。存量 streamable_http 行
	// 保持改造前的行为：网关透传下游 UA，控制面保持默认 UA，请求头集合字节级不变。
	if cfg.UsesNewCapabilities {
		req.Header.Set("User-Agent", UserAgent())
	}
	for name, value := range cfg.ExtraHeaders {
		req.Header.Set(name, value)
	}
}

// ApplyAuth 把密钥按配置注入请求：header 模式设置请求头；query 模式合并到 URL query
// （同名参数覆盖，其余参数保持）。secret 为空表示未配置鉴权，什么都不做。
// 返回的错误不含密钥材料。
func ApplyAuth(req *http.Request, cfg Config, secret string) error {
	if secret == "" {
		return nil
	}
	if !safeSecret(secret) {
		return ErrCredential
	}
	switch cfg.AuthLocation {
	case AuthPath:
		// 路径模式的密钥在构造请求 URL 时已通过 SubstitutePathSecret 替换，这里不改头与 query。
		return nil
	case AuthQuery:
		if !ValidQueryParamName(cfg.AuthName) || ValidateTemplate(cfg.AuthTemplate) != nil {
			return ErrCredential
		}
		SetQueryParam(req.URL, cfg.AuthName, RenderSecret(cfg.AuthTemplate, secret))
	default:
		headerOK := ValidAuthHeaderName(cfg.AuthName)
		if cfg.LegacyAuthHeaderName {
			headerOK = legacyAuthHeaderAllowed(cfg.AuthName) // 存量头名沿用旧口径，不被新增黑名单卡住
		}
		if !headerOK || ValidateTemplate(cfg.AuthTemplate) != nil {
			return ErrCredential
		}
		req.Header.Del(cfg.AuthName)
		req.Header.Set(cfg.AuthName, RenderSecret(cfg.AuthTemplate, secret))
	}
	return nil
}

// StripCallerCredentials 在 query 鉴权模式下，删除 URL 中与鉴权参数同名的参数，防止被其他来源覆盖。
func StripCallerCredentials(u *url.URL, cfg Config) {
	if cfg.AuthLocation == AuthQuery && cfg.AuthName != "" {
		RemoveQueryParam(u, cfg.AuthName)
	}
}

// safeSecret 禁止密钥含控制字符（防头注入）。
func safeSecret(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

// PathEndsWithSSE 判断 URL 路径是否以 /sse 结尾（auto 模式直接走旧 SSE 的依据）。
func PathEndsWithSSE(u *url.URL) bool {
	p := strings.TrimRight(u.Path, "/")
	return strings.HasSuffix(strings.ToLower(p), "/sse")
}

func canonicalPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

// SameOrigin 判断两个 URL 的 scheme、host、port 是否一致。
func SameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		canonicalPort(a) == canonicalPort(b)
}

// ResolveEndpoint 把 SSE endpoint 事件的 data 解析成绝对 URL：支持相对路径（含无前导 /）、
// 绝对 URL、以及 {"endpoint": "..."} 这种 JSON 包装。解析结果必须与 base 同源（防 SSRF 与被引到内网），
// 不允许 userinfo 与 fragment。base 是 SSE GET 的 URL（可含鉴权 query，解析相对路径时不会继承其 query）。
func ResolveEndpoint(base *url.URL, data string) (*url.URL, error) {
	raw := strings.TrimSpace(data)
	if strings.HasPrefix(raw, "{") {
		var wrapper struct {
			Endpoint string `json:"endpoint"`
			URL      string `json:"url"`
		}
		if err := jsonUnmarshal([]byte(raw), &wrapper); err == nil {
			raw = strings.TrimSpace(wrapper.Endpoint + wrapper.URL)
		}
	}
	if raw == "" || len(raw) > 2048 {
		return nil, Errorf(KindSSEEndpoint, "上游 SSE 返回的消息端点为空或过长")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return nil, Errorf(KindSSEEndpoint, "上游 SSE 返回的消息端点包含控制字符")
		}
	}
	ref, err := url.Parse(raw)
	if err != nil || ref.Opaque != "" {
		return nil, Errorf(KindSSEEndpoint, "上游 SSE 返回的消息端点格式无效")
	}
	if ref.Fragment != "" || strings.Contains(raw, "#") {
		return nil, Errorf(KindSSEEndpoint, "上游 SSE 返回的消息端点不能包含片段")
	}
	target := base.ResolveReference(ref)
	if target.User != nil {
		return nil, Errorf(KindSSEEndpoint, "上游 SSE 返回的消息端点不能包含内嵌账号")
	}
	if !strings.EqualFold(target.Scheme, "http") && !strings.EqualFold(target.Scheme, "https") {
		return nil, Errorf(KindSSEEndpoint, "上游 SSE 返回的消息端点协议不受支持")
	}
	if !SameOrigin(base, target) {
		// 只报“主机级”信息：endpoint 路径与服务地址路径都可能含密钥（路径密钥厂商的 endpoint 通常带 token），
		// 不能进入错误信息（错误信息会写日志、审计并展示给管理员）。
		return nil, Errorf(KindCrossOrigin, "上游 SSE 返回的消息端点与服务地址不同源（%s://%s → %s://%s），已按 SSRF 防护拒绝",
			base.Scheme, base.Host, target.Scheme, target.Host)
	}
	return target, nil
}

// newRequestError 构造“请求构造失败”的错误。http.NewRequest 等返回的 *url.Error 带完整请求 URL
// （路径密钥模式下含真实密钥），因此只保留根因，绝不拼接 URL；其余文本再做脱敏兜底。
func newRequestError(err error) error {
	root := err
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		root = ue.Err
	}
	return &Error{Kind: KindSSEEndpoint, Message: fmt.Sprintf("构造上游请求失败：%s", RedactText(fmt.Sprint(root))), Cause: root}
}

// RequestURL 返回实际发往上游的 URL：path 模式把 {secret} 替换为路径段编码后的密钥；其余模式返回副本。
// 返回值含真实密钥，只能用于构造请求，不能展示、记录或放进错误信息。
func RequestURL(u *url.URL, cfg Config, secret string) (*url.URL, error) {
	if cfg.AuthLocation != AuthPath {
		return cloneURL(u), nil
	}
	if secret == "" {
		return nil, ErrCredential
	}
	return SubstitutePathSecret(u, secret)
}

// NewRequestErrorForTest 暴露 newRequestError 供外部测试包验证（不用于生产路径）。
func NewRequestErrorForTest(err error) error { return newRequestError(err) }
