package identity

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Manual connection tests probe endpoint availability and client authentication.
// An invalid authorization code is deliberate; a real interactive login is still required.
func (t *OIDCTester) ProbeAuthenticationEndpoints(ctx context.Context, cfg TestConfig, result *TestConnectionResult, callback string) {
	if result == nil || !result.Success || result.Discovery == nil {
		return
	}
	stage := func(name string, passed bool, message string) {
		status := "passed"
		if !passed {
			status = "failed"
			result.Success = false
			result.Error = message
		}
		result.Stages = append(result.Stages, TestStageResult{Name: name, Status: status, Message: message})
	}
	client := t.newHTTPClient()
	doc := result.Discovery
	fetch := func(req *http.Request) (int, []byte, bool) {
		if _, _, err := t.guard.CheckRequestURL(req.URL.String()); err != nil {
			return 0, nil, false
		}
		response, err := client.Do(req)
		if err != nil {
			return 0, nil, false
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, maxDiscoverySize+1))
		return response.StatusCode, raw, err == nil && len(raw) <= maxDiscoverySize
	}
	noSignature := cfg.SignatureMode == "none"
	if noSignature && !isHTTPSURL(doc.TokenEndpoint) {
		// 先拦：不得把 client_secret 发往 http 的 token 端点。
		stage("校验 Token 端点 HTTPS", false, noneRequiresHTTPSMessage)
		return
	}
	if noSignature && doc.JWKSURI == "" {
		stage("获取 JWKS", true, "已选择不校验 id_token 签名，跳过公钥检查")
	} else if !probeJWKS(ctx, doc.JWKSURI, noSignature, fetch, stage) {
		return
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		stage("验证 Token 客户端", false, "请配置应用标识和应用密钥")
		return
	}
	probeTokenClient(ctx, cfg, doc, callback, fetch, stage)
}

// probeJWKS 返回 false 表示应终止后续探测。不校验签名时 JWKS 缺失/为空/不可达只记录，不阻断。
func probeJWKS(ctx context.Context, jwksURI string, noSignature bool,
	fetch func(*http.Request) (int, []byte, bool), stage func(string, bool, string)) bool {
	fail := func(msg string) bool {
		if noSignature {
			stage("获取 JWKS", true, "已选择不校验 id_token 签名，公钥检查未通过但不影响："+msg)
			return true
		}
		stage("获取 JWKS", false, msg)
		return false
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return fail("JWKS 地址无效")
	}
	request.Header.Set("Accept", "application/json")
	status, raw, ok := fetch(request)
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
		} `json:"keys"`
	}
	if !ok || status != 200 || json.Unmarshal(raw, &jwks) != nil || len(jwks.Keys) == 0 {
		return fail("无法获取有效的 JWKS 公钥集合")
	}
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" && key.Kty != "EC" && key.Kty != "OKP" {
			return fail("JWKS 未包含支持的签名公钥")
		}
	}
	stage("获取 JWKS", true, "公钥端点可访问并返回有效集合")
	return true
}

func probeTokenClient(ctx context.Context, cfg TestConfig, doc *DiscoveryDocument, callback string,
	fetch func(*http.Request) (int, []byte, bool), stage func(string, bool, string)) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {"jjdguard-connection-probe-invalid-code"}, "redirect_uri": {callback}}
	method := "client_secret_basic"
	for _, supported := range doc.TokenEndpointAuthMethodsSupported {
		if supported == "client_secret_post" {
			method = supported
			break
		}
	}
	if method == "client_secret_post" {
		form.Set("client_id", cfg.ClientID)
		form.Set("client_secret", cfg.ClientSecret)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		stage("验证 Token 客户端", false, "Token 地址无效")
		return
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	if method == "client_secret_basic" {
		request.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	}
	status, raw, ok := fetch(request)
	var token struct {
		Error string `json:"error"`
	}
	if !ok || json.Unmarshal(raw, &token) != nil {
		stage("验证 Token 客户端", false, "Token 端点暂不可达或返回无效响应")
		return
	}
	if status == 400 && token.Error == "invalid_grant" {
		stage("验证 Token 客户端", true, "应用凭据已被认可；完整授权码登录待现场验证")
		return
	}
	message := "Token 端点未认可客户端探测，请检查应用配置"
	switch token.Error {
	case "invalid_client":
		message = "应用标识或应用密钥未被认可"
	case "redirect_uri_mismatch":
		message = "请将系统生成的真实回调地址加入身份源白名单"
	}
	stage("验证 Token 客户端", false, message)
}
