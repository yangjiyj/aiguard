package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxDiscoverySize = 1 << 20
	httpTimeout      = 10 * time.Second
)

type ClaimConfig struct {
	SubjectClaim  string
	UsernameClaim string
	NameClaim     string
	EmailClaim    string
	DeptCodeClaim string
	DeptNameClaim string
	GroupsClaim   string
}

type TestConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	Scopes       string
	Claims       ClaimConfig
	// SignatureMode：jwks（默认，空等价）/ none。none 时 JWKS 缺失或为空不算失败。
	SignatureMode string
}

type DiscoveryDocument struct {
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	// 以下两项只用于发现性提示，非必填。
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`
}

type TestStageResult struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type TestConnectionResult struct {
	Success bool              `json:"success"`
	Stages  []TestStageResult `json:"stages"`
	Error   string            `json:"error,omitempty"`
	// Hints 是非阻断的发现性提示（例如 IdP 使用对称签名），不影响 Success。
	Hints     []string           `json:"hints,omitempty"`
	Discovery *DiscoveryDocument `json:"-"`
}

type OIDCTester struct {
	guard *SSRFGuard
}

func NewOIDCTester() *OIDCTester {
	return &OIDCTester{guard: NewSSRFGuard()}
}

type oidcSchemeTransport struct {
	guard          *SSRFGuard
	httpsTransport *http.Transport
	httpTransport  *http.Transport
}

func (t *oidcSchemeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if _, _, err := t.guard.CheckRequestURL(req.URL.String()); err != nil {
		return nil, err
	}
	if req.URL.Scheme == "http" {
		return t.httpTransport.RoundTrip(req)
	}
	return t.httpsTransport.RoundTrip(req)
}

func (t *OIDCTester) newHTTPClient() *http.Client {
	httpsTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpsTransport.Proxy = nil
	httpsTransport.DialContext = t.guard.DialContext
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.Proxy = nil
	httpTransport.DialContext = t.guard.DialPrivateContext
	return &http.Client{
		Timeout: httpTimeout,
		Transport: &oidcSchemeTransport{
			guard:          t.guard,
			httpsTransport: httpsTransport,
			httpTransport:  httpTransport,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				return fmt.Errorf("身份源重定向不得跨主机")
			}
			if len(via) >= 5 {
				return fmt.Errorf("重定向次数过多")
			}
			if _, _, err := t.guard.CheckRequestURL(req.URL.String()); err != nil {
				return fmt.Errorf("重定向目标被拒绝: %w", err)
			}
			return nil
		},
	}
}

func (t *OIDCTester) TestConnection(ctx context.Context, cfg TestConfig) *TestConnectionResult {
	result := &TestConnectionResult{}
	addStage := func(name, status, msg string) {
		result.Stages = append(result.Stages, TestStageResult{Name: name, Status: status, Message: msg})
	}

	cfg.IssuerURL = canonicalIssuerURL(cfg.IssuerURL)
	// Stage 1: 地址解析
	_, issuerIP, err := t.guard.CheckRequestURL(cfg.IssuerURL)
	if err != nil {
		addStage("地址解析", "failed", err.Error())
		result.Error = err.Error()
		return result
	}
	addStage("地址解析", "passed", "地址格式正确")

	// Stage 2: 获取发现文档
	discoveryURL := strings.TrimSuffix(cfg.IssuerURL, "/") + "/.well-known/openid-configuration"
	client := t.newHTTPClient()
	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	if err != nil {
		addStage("获取发现文档", "failed", "构造请求失败")
		result.Error = "构造请求失败"
		return result
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		addStage("获取发现文档", "failed", fmt.Sprintf("无法连接到身份源: %v", err))
		result.Error = "无法连接到身份源"
		return result
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoverySize+1))
	if err != nil {
		addStage("获取发现文档", "failed", "读取响应失败")
		result.Error = "读取响应失败"
		return result
	}
	if len(body) > maxDiscoverySize {
		addStage("获取发现文档", "failed", "发现文档超过大小限制（1MB）")
		result.Error = "发现文档超过大小限制"
		return result
	}
	if resp.StatusCode != 200 {
		addStage("获取发现文档", "failed", fmt.Sprintf("身份源返回状态码 %d", resp.StatusCode))
		result.Error = fmt.Sprintf("身份源返回状态码 %d", resp.StatusCode)
		return result
	}
	var discovery DiscoveryDocument
	if err := json.Unmarshal(body, &discovery); err != nil {
		addStage("获取发现文档", "failed", "发现文档不是有效的 JSON")
		result.Error = "发现文档不是有效的 JSON"
		return result
	}
	addStage("获取发现文档", "passed", "成功获取发现文档")

	// Stage 3: 校验签发方一致性
	discoveryIssuer := discovery.Issuer
	if discoveryIssuer == "" {
		addStage("校验签发方一致性", "failed", "发现文档缺少 issuer 字段")
		result.Error = "发现文档缺少 issuer 字段"
		return result
	}
	if normalizeURL(discoveryIssuer) != normalizeURL(cfg.IssuerURL) {
		addStage("校验签发方一致性", "failed", fmt.Sprintf("签发方不匹配: 配置=%s, 发现文档=%s", cfg.IssuerURL, discoveryIssuer))
		result.Error = "签发方地址与发现文档不一致"
		return result
	}
	addStage("校验签发方一致性", "passed", "签发方地址一致")

	// Stage 4: 校验协议端点
	endpoints := []struct {
		name     string
		value    string
		required bool
	}{
		{"authorization_endpoint", discovery.AuthorizationEndpoint, true},
		{"token_endpoint", discovery.TokenEndpoint, true},
		{"jwks_uri", discovery.JWKSURI, cfg.SignatureMode != "none"},
		{"userinfo_endpoint", discovery.UserInfoEndpoint, false},
		{"end_session_endpoint", discovery.EndSessionEndpoint, false},
	}
	for _, endpoint := range endpoints {
		if endpoint.value == "" && endpoint.required {
			addStage("校验协议端点", "failed", fmt.Sprintf("发现文档缺少 %s", endpoint.name))
			result.Error = "发现文档缺少必要的协议端点"
			return result
		}
		if endpoint.value != "" {
			if err := t.validateProtocolEndpoint(endpoint.value); err != nil {
				addStage("校验协议端点", "failed", "发现文档包含不可访问或不安全的协议端点")
				result.Error = "发现文档协议端点不安全"
				return result
			}
		}
	}
	addStage("校验协议端点", "passed", "授权、令牌和 JWKS 端点均已配置")

	// 不校验 id_token 签名时，token 必须由服务端经 HTTPS 直连换取：在保存/测试阶段就拒绝，而不是等到发布。
	if cfg.SignatureMode == "none" && !isHTTPSURL(discovery.TokenEndpoint) {
		addStage("校验 Token 端点 HTTPS", "failed", noneRequiresHTTPSMessage)
		result.Error = noneRequiresHTTPSMessage
		return result
	}

	// Stage 5: 校验 HTTPS
	isHTTPS := strings.HasPrefix(cfg.IssuerURL, "https://")
	allowHTTP := t.guard.isExplicitlyAllowed(issuerIP)
	if !isHTTPS && !allowHTTP {
		addStage("校验 HTTPS", "failed", "身份源地址必须使用 HTTPS")
		result.Error = "身份源地址必须使用 HTTPS（私有化部署除外）"
		return result
	}
	if isHTTPS {
		addStage("校验 HTTPS", "passed", "已使用 HTTPS")
	} else {
		addStage("校验 HTTPS", "passed", "私有化部署允许 HTTP")
	}

	// Stage 6: 检查必要声明配置
	missingClaims := []string{}
	if cfg.Claims.SubjectClaim == "" {
		missingClaims = append(missingClaims, "唯一用户标识")
	}
	if cfg.Claims.UsernameClaim == "" {
		missingClaims = append(missingClaims, "用户名")
	}
	if cfg.Claims.NameClaim == "" {
		missingClaims = append(missingClaims, "姓名")
	}
	if cfg.Claims.EmailClaim == "" {
		missingClaims = append(missingClaims, "邮箱")
	}
	if len(missingClaims) > 0 {
		addStage("检查必要声明配置", "failed", fmt.Sprintf("缺少必要声明: %s", strings.Join(missingClaims, "、")))
		result.Error = "请完善必要声明配置"
		return result
	}
	addStage("检查必要声明配置", "passed", "必要声明配置完整")

	result.Discovery = &discovery
	result.Hints = discoveryHints(&discovery, cfg)
	result.Success = true
	return result
}

const noneRequiresHTTPSMessage = "选择「不校验签名」时，token 端点必须是 https"

func isHTTPSURL(raw string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(raw)), "https://")
}

// discoveryHints 根据发现文档给出非阻断的配置建议。
func discoveryHints(doc *DiscoveryDocument, cfg TestConfig) []string {
	var hints []string
	algs := doc.IDTokenSigningAlgValuesSupported
	if len(algs) > 0 {
		hasHS, hasRS, onlyHS := false, false, true
		for _, alg := range algs {
			upper := strings.ToUpper(alg)
			if strings.HasPrefix(upper, "HS") {
				hasHS = true
			} else {
				onlyHS = false
			}
			if upper == "RS256" {
				hasRS = true
			}
		}
		switch {
		case hasHS && hasRS:
			// 同时支持 RS256：优先建议改 RS256，「不校验签名」只作兜底（无论当前是否已选 none 都提示）。
			hints = append(hints, "该 IdP 同时支持 RS256，建议在 IdP 应用里把 id_token 签名改为 RS256 后使用公钥验签，「不校验签名」仅作兜底。")
		case onlyHS && cfg.SignatureMode != "none":
			hints = append(hints, "该 IdP 使用对称签名（HS256 等），无法按公钥验签；如确认可信，可将「id_token 验签方式」选为「不校验签名」。")
		}
	}
	if len(doc.ClaimsSupported) > 0 {
		claim := cfg.Claims.UsernameClaim
		if claim == "" {
			claim = "preferred_username"
		}
		found := false
		for _, supported := range doc.ClaimsSupported {
			if supported == claim {
				found = true
				break
			}
		}
		if !found && claim == "preferred_username" {
			hints = append(hints, "该 IdP 未声明支持 preferred_username，建议将「用户名取值」改为邮箱。")
		} else if !found {
			hints = append(hints, "该 IdP 未声明支持所选的用户名声明（"+claim+"），请确认其确实返回该字段，或改为邮箱。")
		}
	}
	return hints
}

func (t *OIDCTester) validateProtocolEndpoint(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Fragment != "" {
		return fmt.Errorf("协议端点地址无效")
	}
	if _, _, err := t.guard.CheckRequestURL(raw); err != nil {
		return err
	}
	return nil
}

func (t *OIDCTester) ResolveDiscovery(ctx context.Context, cfg TestConfig) (*DiscoveryDocument, error) {
	result := t.TestConnection(ctx, cfg)
	if !result.Success || result.Discovery == nil {
		return nil, fmt.Errorf("身份源发现文档验证失败")
	}
	doc := *result.Discovery
	return &doc, nil
}

func normalizeURL(u string) string {
	return strings.TrimSuffix(strings.TrimRight(u, "/"), "/")
}

func (t *OIDCTester) ResolveIP(host string) (net.IP, error) {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("无法解析主机名: %s", host)
	}
	return ips[0], nil
}

const oidcDiscoveryPath = "/.well-known/openid-configuration"

func canonicalIssuerURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return trimmed
	}

	path := strings.TrimSuffix(parsed.Path, "/")
	if !strings.HasSuffix(path, oidcDiscoveryPath) {
		return trimmed
	}
	parsed.Path = strings.TrimSuffix(path, oidcDiscoveryPath)
	parsed.RawPath = ""
	return parsed.String()
}
