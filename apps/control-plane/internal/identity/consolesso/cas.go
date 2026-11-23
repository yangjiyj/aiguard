package consolesso

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// W9 9.3：CAS 3.0（政企统一身份认证平台常用协议）控制台登录。
//
// 流程：/cas/login 生成 state 并绑定浏览器 → 302 到 {base}/login?service=<回调?s=state>
// → CAS 回调 /cas/callback?s=state&ticket=ST-… → 服务端 /p3/serviceValidate 校验票据
// （service 必须逐字相同，由 CAS 服务端比对）→ 按 user_identity_links(cas, issuer, user)
// 查已绑定的控制台账号 → 与 OIDC 相同的一次性票据/会话兑换。
//
// CAS 协议本身没有 state 参数，登录 CSRF 防护靠把 state 放进 service URL 并与浏览器 cookie 绑定。
const (
	CASLoginPath    = "/admin/v1/auth/sso/cas/login"
	CASCallbackPath = "/admin/v1/auth/sso/cas/callback"

	ProviderOIDC  = "oidc"
	ProviderCAS   = "cas"
	ProviderWeCom = "wecom"

	casNamespace       = "http://www.yale.edu/tp/cas"
	maxCASTicketLength = 256 // CAS 3.0 §3.7：票据最长 256 字符
	maxCASResponse     = 64 << 10
)

// CASConfig 描述 CAS 服务端坐标。
type CASConfig struct {
	// BaseURL 是 CAS 服务前缀（如 https://cas.example.gov.cn/cas），浏览器访问 {BaseURL}/login。
	// 它同时是绑定关系里的 issuer。
	BaseURL string
	// ValidateBaseURL 为空时等于 BaseURL；可指向内网地址，control-plane 服务端访问。
	ValidateBaseURL string
	// ServiceURL 是本系统回调，指向 /admin/v1/auth/sso/cas/callback，需在 CAS 服务注册表登记。
	ServiceURL  string
	DisplayName string
}

var errCASNotConfigured = errors.New("console sso: cas not configured")

func (c CASConfig) issuer() string { return strings.TrimSuffix(strings.TrimSpace(c.BaseURL), "/") }

func (c CASConfig) validateBase() string {
	if v := strings.TrimSuffix(strings.TrimSpace(c.ValidateBaseURL), "/"); v != "" {
		return v
	}
	return c.issuer()
}

// Validate：浏览器侧地址（BaseURL、ServiceURL）在 secure 模式下必须 https。
func (c CASConfig) Validate(secure bool) error {
	for _, raw := range []string{c.BaseURL, c.validateBase(), c.ServiceURL} {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" ||
			(u.Scheme != "https" && u.Scheme != "http") {
			return errCASNotConfigured
		}
	}
	for _, raw := range []string{c.BaseURL, c.ServiceURL} {
		if u, _ := url.Parse(strings.TrimSpace(raw)); secure && u.Scheme != "https" {
			return errCASNotConfigured
		}
	}
	if u, _ := url.Parse(c.BaseURL); u.RawQuery != "" {
		return errCASNotConfigured
	}
	return nil
}

// serviceFor 把 state 放进 service URL。登录与校验必须使用同一个字符串。
func (c CASConfig) serviceFor(state string) string {
	sep := "?"
	if strings.Contains(c.ServiceURL, "?") {
		sep = "&"
	}
	return c.ServiceURL + sep + "s=" + url.QueryEscape(state)
}

func (c CASConfig) loginURL(service string) string {
	return c.issuer() + "/login?" + url.Values{"service": {service}}.Encode()
}

type casProxies struct {
	Proxy []string `xml:"http://www.yale.edu/tp/cas proxy"`
}

type casSuccess struct {
	User    string      `xml:"http://www.yale.edu/tp/cas user"`
	Proxies *casProxies `xml:"http://www.yale.edu/tp/cas proxies"`
}

type casFailure struct {
	Code string `xml:"code,attr"`
}

type casServiceResponse struct {
	XMLName xml.Name    `xml:"http://www.yale.edu/tp/cas serviceResponse"`
	Success *casSuccess `xml:"http://www.yale.edu/tp/cas authenticationSuccess"`
	Failure *casFailure `xml:"http://www.yale.edu/tp/cas authenticationFailure"`
}

var (
	errCASRejected  = errors.New("console sso: cas ticket rejected")
	errCASMalformed = errors.New("console sso: cas response malformed")
)

// validCASTicket：服务票据必须以 ST- 开头（CAS 3.0 §3.1.1），拒绝代理票据 PT-。
func validCASTicket(t string) bool {
	if !strings.HasPrefix(t, "ST-") || len(t) > maxCASTicketLength {
		return false
	}
	for _, r := range t {
		if r <= 0x20 || r >= 0x7f {
			return false
		}
	}
	return true
}

// validateCASTicket 调 /p3/serviceValidate。encoding/xml 不展开外部实体（无 XXE）。
func validateCASTicket(ctx context.Context, client *http.Client, c CASConfig, service, ticket string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, tokenTimeout)
	defer cancel()
	endpoint := c.validateBase() + "/p3/serviceValidate?" + url.Values{
		"service": {service}, "ticket": {ticket},
	}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/xml, text/xml")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("console sso: cas validate request: %w", unwrapURLError(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCASResponse+1))
	if err != nil || len(body) > maxCASResponse {
		return "", errCASMalformed
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("console sso: cas validate status %d", resp.StatusCode)
	}
	var out casServiceResponse
	if err := xml.Unmarshal(body, &out); err != nil {
		return "", errCASMalformed
	}
	switch {
	case out.Success != nil && out.Failure != nil:
		return "", errCASMalformed
	case out.Failure != nil:
		return "", fmt.Errorf("%w: code=%s", errCASRejected, sanitizeCode(out.Failure.Code))
	case out.Success == nil:
		return "", errCASMalformed
	}
	// 未请求代理（不带 pgtUrl），出现代理链说明票据不是直接签给本服务的。
	if out.Success.Proxies != nil && len(out.Success.Proxies.Proxy) > 0 {
		return "", fmt.Errorf("%w: proxied ticket", errCASRejected)
	}
	user := strings.TrimSpace(out.Success.User)
	if user == "" || len(user) > 512 {
		return "", errCASMalformed
	}
	return user, nil
}

// unwrapURLError 去掉 *url.Error 里的完整 URL（其中可能带票据或企业微信 secret），只保留底层原因。
func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func sanitizeCode(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(b) < 64; i++ {
		ch := s[i]
		if ch == '_' || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			b = append(b, ch)
		}
	}
	return string(b)
}

// CASLogin GET /admin/v1/auth/sso/cas/login
func (s *Service) CASLogin(w http.ResponseWriter, r *http.Request) {
	if s.cas == nil {
		http.NotFound(w, r)
		return
	}
	state, binding := randomToken(), randomToken()
	if err := s.store.putState(r.Context(), state, flowState{
		Provider: ProviderCAS, BindingHash: hashHex(binding),
	}); err != nil {
		s.fail(w, r, "unavailable")
		return
	}
	s.setBinding(w, binding)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, s.cas.loginURL(s.cas.serviceFor(state)), http.StatusFound)
}

// CASCallback GET /admin/v1/auth/sso/cas/callback?s=…&ticket=ST-…
func (s *Service) CASCallback(w http.ResponseWriter, r *http.Request) {
	if s.cas == nil {
		http.NotFound(w, r)
		return
	}
	s.clearBinding(w)
	q := r.URL.Query()
	state, st := q.Get("s"), q.Get("ticket")
	if state == "" || len(state) > 256 || !validCASTicket(st) {
		s.fail(w, r, "invalid_request")
		return
	}
	if !s.takeBoundState(w, r, state, ProviderCAS) {
		return
	}
	user, err := validateCASTicket(r.Context(), s.http, *s.cas, s.cas.serviceFor(state), st)
	if err != nil {
		log.Printf("component=console_sso provider=cas stage=validate error_code=ticket_invalid err=%v", err)
		if errors.Is(err, errCASRejected) {
			s.fail(w, r, "invalid_token")
		} else {
			s.fail(w, r, "idp_unavailable")
		}
		return
	}
	s.completeLogin(w, r, ProviderCAS, s.cas.issuer(), user)
}
