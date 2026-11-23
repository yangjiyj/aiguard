package mcpupstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

var (
	errBadURL      = errors.New("MCP 服务地址格式非法（需 http(s)://host[:port][/path]）")
	errMultiSecret = errors.New("服务地址的 URL 参数中包含多个疑似密钥，无法自动拆分。请只保留一个，或删除后在「鉴权」中单独填写")
)

// 错误类别（Kind）：管理台测试连接 / 同步失败时用于归因展示。
const (
	KindDNS             = "dns"
	KindTimeout         = "timeout"
	KindTLS             = "tls"
	KindConnect         = "connect"
	KindSSRF            = "url"
	KindHTTP401         = "http_401"
	KindHTTP403         = "http_403"
	KindHTTP429         = "http_429"
	KindHTTP5xx         = "http_5xx"
	KindHTTP            = "http"
	KindNotJSONRPC      = "not_jsonrpc"
	KindOAuth           = "oauth_required"
	KindParse           = "parse"
	KindRPCError        = "rpc_error"
	KindProtocolVersion = "protocol_version"
	KindSSEEndpoint     = "sse_endpoint"
	KindCrossOrigin     = "cross_origin"
	KindUnsupported     = "unsupported"
	KindNotStreamable   = "not_streamable"
	KindRedirect        = "redirect"
	KindSession         = "session"
	KindStreamClosed    = "stream_closed"
	KindAuthConfig      = "auth"
	KindCapacity        = "capacity"
)

// Error 是带分类的上游错误。Message 为面向管理员的中文文案，创建时已脱敏。
type Error struct {
	Kind       string
	Message    string
	HTTPStatus int
	RetryAfter string
	Cause      error
}

func (e *Error) Error() string { return e.Message }
func (e *Error) Unwrap() error { return e.Cause }

// KindOf 提取错误类别；非 *Error 返回空串。
func KindOf(err error) string {
	var ue *Error
	if errors.As(err, &ue) {
		return ue.Kind
	}
	return ""
}

// Errorf 构造指定类别的错误。
func Errorf(kind, format string, args ...interface{}) *Error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...)}
}

var resourceMetadata = regexp.MustCompile(`(?i)resource_metadata\s*=\s*"?([^",\s]+)`)

// ClassifyHTTPFailure 把非 2xx 响应归类为带中文文案的错误。secrets 用于脱敏响应摘要。
func ClassifyHTTPFailure(status int, header http.Header, body []byte, secrets ...string) *Error {
	summary := Summarize(body, secrets...)
	e := &Error{HTTPStatus: status}
	switch {
	case status == http.StatusUnauthorized && resourceMetadata.MatchString(strings.Join(header.Values("WWW-Authenticate"), " ")):
		meta := resourceMetadata.FindStringSubmatch(strings.Join(header.Values("WWW-Authenticate"), " "))[1]
		e.Kind = KindOAuth
		e.Message = fmt.Sprintf("上游要求 OAuth 2.1 授权（WWW-Authenticate resource_metadata=%s），当前版本暂不支持 OAuth，请改用 API Key 方式或联系厂商",
			RedactText(meta, secrets...))
	case status == http.StatusUnauthorized:
		e.Kind = KindHTTP401
		e.Message = fmt.Sprintf("上游返回 HTTP 401（鉴权失败）：请检查密钥是否有效，以及鉴权位置、参数名与值格式是否与厂商要求一致。响应摘要：%s", summary)
	case status == http.StatusForbidden:
		e.Kind = KindHTTP403
		e.Message = fmt.Sprintf("上游返回 HTTP 403（访问被拒绝）：当前密钥可能无权访问该服务，或需要额外请求头（如账户标识）。响应摘要：%s", summary)
	case status == http.StatusTooManyRequests:
		e.Kind = KindHTTP429
		e.RetryAfter = strings.TrimSpace(header.Get("Retry-After"))
		retry := ""
		if e.RetryAfter != "" {
			retry = "，上游建议 " + RedactText(e.RetryAfter) + "（Retry-After）后重试"
		}
		e.Message = fmt.Sprintf("上游限流（HTTP 429）%s。响应摘要：%s", retry, summary)
	case status >= 500:
		e.Kind = KindHTTP5xx
		e.Message = fmt.Sprintf("上游返回服务端错误 HTTP %d。响应摘要：%s", status, summary)
	default:
		e.Kind = KindHTTP
		e.Message = fmt.Sprintf("上游返回 HTTP %d。响应摘要：%s", status, summary)
	}
	return e
}

// NotJSONRPC 构造“HTTP 2xx 但不是合法 JSON-RPC”的错误（高德 / 智谱未鉴权的 200 业务错误体）。
func NotJSONRPC(status int, body []byte, secrets ...string) *Error {
	return &Error{
		Kind: KindNotJSONRPC, HTTPStatus: status,
		Message: fmt.Sprintf("上游返回 HTTP %d 但不是合法 JSON-RPC（疑似鉴权失败），响应摘要：%s（已脱敏，截断到 %d 字）",
			status, Summarize(body, secrets...), SummaryLimit),
	}
}

// ClassifyDial 把网络层错误归类并生成脱敏的中文错误；保留根因供 errors.Is 使用，但不含 URL。
func ClassifyDial(err error, secrets ...string) *Error {
	if err == nil {
		return nil
	}
	root := err
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		root = ue.Err
	}
	if errors.Is(root, safetarget.ErrRedirectNotAllowed) {
		return &Error{Kind: KindRedirect, Cause: root,
			Message: "上游返回了重定向，网关出于安全考虑不跟随重定向，请直接填写最终服务地址"}
	}
	kind, label := KindConnect, "连接失败"
	msg := strings.ToLower(root.Error())
	var netErr net.Error
	var dnsErr *net.DNSError
	switch {
	case errors.Is(root, context.DeadlineExceeded) || (errors.As(root, &netErr) && netErr.Timeout()) ||
		strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		kind, label = KindTimeout, "连接超时"
	case errors.As(root, &dnsErr) || strings.Contains(msg, "no such host") || strings.Contains(msg, "server misbehaving"):
		kind, label = KindDNS, "域名解析失败"
	case strings.Contains(msg, "tls") || strings.Contains(msg, "certificate") || strings.Contains(msg, "x509"):
		kind, label = KindTLS, "TLS 握手失败"
	}
	return &Error{
		Kind:    kind,
		Message: fmt.Sprintf("无法连接 MCP 服务器（%s）：%s", label, RedactText(root.Error(), secrets...)),
		Cause:   root,
	}
}
