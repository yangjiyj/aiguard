package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func discoveryServer(t *testing.T, extra map[string]any, withJWKS bool) *httptest.Server {
	t.Helper()
	os.Setenv("JJD_IDP_ALLOW_CIDRS", "127.0.0.0/8")
	t.Cleanup(func() { os.Unsetenv("JJD_IDP_ALLOW_CIDRS") })
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			w.WriteHeader(404)
			return
		}
		doc := map[string]any{
			"issuer":                 "http://" + r.Host,
			"authorization_endpoint": "http://" + r.Host + "/auth",
			"token_endpoint":         "http://" + r.Host + "/token",
		}
		if withJWKS {
			doc["jwks_uri"] = "http://" + r.Host + "/jwks"
		}
		for k, v := range extra {
			if k == "token_https" { // 保持 http 服务，但在 discovery 里公布 https 的 token 端点（只做地址校验，不连接）
				doc["token_endpoint"] = "https://" + r.Host + "/token"
				continue
			}
			doc[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func hintConfig(url, sigMode string) TestConfig {
	return TestConfig{IssuerURL: url, ClientID: "c", Scopes: "openid", SignatureMode: sigMode,
		Claims: ClaimConfig{SubjectClaim: "sub", UsernameClaim: "preferred_username", NameClaim: "name", EmailClaim: "email"}}
}

func joinHints(r *TestConnectionResult) string { return strings.Join(r.Hints, "|") }

func TestDiscoveryHintsSymmetricSigningAndMissingUsernameClaim(t *testing.T) {
	ts := discoveryServer(t, map[string]any{
		"id_token_signing_alg_values_supported": []string{"HS256"},
		"claims_supported":                      []string{"sub", "email", "name"},
		"token_https":                           true,
	}, true)
	result := newLoopbackOIDCTester().TestConnection(context.Background(), hintConfig(ts.URL, ""))
	if !result.Success {
		t.Fatalf("提示必须非阻断: %+v", result)
	}
	h := joinHints(result)
	if !strings.Contains(h, "对称签名") || !strings.Contains(h, "不校验签名") || !strings.Contains(h, "邮箱") {
		t.Fatalf("hints=%v", result.Hints)
	}
}

func TestDiscoveryHintsQuietForStandardIdP(t *testing.T) {
	ts := discoveryServer(t, map[string]any{
		"id_token_signing_alg_values_supported": []string{"RS256", "ES256"},
		"claims_supported":                      []string{"sub", "preferred_username", "email"},
	}, true)
	result := newLoopbackOIDCTester().TestConnection(context.Background(), hintConfig(ts.URL, ""))
	if len(result.Hints) != 0 {
		t.Fatalf("标准 IdP 不应有提示: %v", result.Hints)
	}
	// claims_supported 缺省（不少 IdP 不提供）不提示。
	ts2 := discoveryServer(t, nil, true)
	if r := newLoopbackOIDCTester().TestConnection(context.Background(), hintConfig(ts2.URL, "")); len(r.Hints) != 0 {
		t.Fatalf("hints=%v", r.Hints)
	}
}

func TestDiscoveryHintsSkippedWhenAlreadyNoneAndJWKSOptional(t *testing.T) {
	ts := discoveryServer(t, map[string]any{"id_token_signing_alg_values_supported": []string{"HS256"}, "token_https": true}, false)
	// jwks 模式：缺 jwks_uri 仍失败（行为不变）。
	if r := newLoopbackOIDCTester().TestConnection(context.Background(), hintConfig(ts.URL, "")); r.Success {
		t.Fatal("jwks 模式缺 jwks_uri 必须失败")
	}
	r := newLoopbackOIDCTester().TestConnection(context.Background(), hintConfig(ts.URL, "none"))
	if !r.Success {
		t.Fatalf("none 模式不要求 jwks_uri: %+v", r)
	}
	if strings.Contains(joinHints(r), "对称签名") {
		t.Fatalf("已选择不校验签名，不应再提示: %v", r.Hints)
	}
}

func TestProbeJWKSFailureIsNonBlockingWhenSignatureNone(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"keys":[]}`)) // HS 系 IdP 常见：JWKS 为空
	}))
	defer ts.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original })
	os.Setenv("JJD_IDP_ALLOW_CIDRS", "127.0.0.0/8")
	defer os.Unsetenv("JJD_IDP_ALLOW_CIDRS")
	doc := &DiscoveryDocument{JWKSURI: ts.URL + "/jwks", TokenEndpoint: ts.URL + "/token"}
	for mode, want := range map[string]bool{"": false, "none": true} {
		result := &TestConnectionResult{Success: true, Discovery: doc}
		newLoopbackOIDCTester().ProbeAuthenticationEndpoints(context.Background(),
			TestConfig{ClientID: "c", ClientSecret: "s", SignatureMode: mode}, result, "https://portal/cb")
		if result.Success != want {
			t.Fatalf("mode=%q success=%v stages=%+v", mode, result.Success, result.Stages)
		}
	}
}

func TestDiscoveryHintsSuggestRS256WhenBothSupported(t *testing.T) {
	ts := discoveryServer(t, map[string]any{
		"id_token_signing_alg_values_supported": []string{"RS256", "HS256"},
		"token_https":                           true,
	}, true)
	for _, mode := range []string{"", "none"} {
		r := newLoopbackOIDCTester().TestConnection(context.Background(), hintConfig(ts.URL, mode))
		if !r.Success {
			t.Fatalf("提示必须非阻断: %+v", r)
		}
		h := joinHints(r)
		if !strings.Contains(h, "同时支持 RS256") || !strings.Contains(h, "改为 RS256") || !strings.Contains(h, "仅作兜底") {
			t.Fatalf("mode=%q hints=%v", mode, r.Hints)
		}
		if strings.Contains(h, "无法按公钥验签") {
			t.Fatalf("同时支持 RS256 时不应说「无法按公钥验签」: %v", r.Hints)
		}
	}
}

func TestTestConnectionNoneRequiresHTTPSTokenEndpoint(t *testing.T) {
	ts := discoveryServer(t, nil, true) // token 端点是 http://127.0.0.1:...
	r := newLoopbackOIDCTester().TestConnection(context.Background(), hintConfig(ts.URL, "none"))
	if r.Success {
		t.Fatalf("none + http token 端点必须失败: %+v", r)
	}
	if !strings.Contains(r.Error, "选择「不校验签名」时，token 端点必须是 https") {
		t.Fatalf("error=%q stages=%+v", r.Error, r.Stages)
	}
	// 默认验签方式不受影响。
	if r := newLoopbackOIDCTester().TestConnection(context.Background(), hintConfig(ts.URL, "")); !r.Success {
		t.Fatalf("jwks 模式不应受影响: %+v", r)
	}
}

func TestProbeNeverSendsSecretToHTTPTokenEndpointWhenSignatureNone(t *testing.T) {
	var tokenHits int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokenHits++
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer ts.Close()
	os.Setenv("JJD_IDP_ALLOW_CIDRS", "127.0.0.0/8")
	defer os.Unsetenv("JJD_IDP_ALLOW_CIDRS")
	doc := &DiscoveryDocument{JWKSURI: ts.URL + "/jwks", TokenEndpoint: ts.URL + "/token"}
	result := &TestConnectionResult{Success: true, Discovery: doc}
	newLoopbackOIDCTester().ProbeAuthenticationEndpoints(context.Background(),
		TestConfig{ClientID: "c", ClientSecret: "must-not-be-sent", SignatureMode: "none"}, result, "https://portal/cb")
	if result.Success || tokenHits != 0 {
		t.Fatalf("none + http token 端点必须先拦截，不得发出请求: success=%v hits=%d", result.Success, tokenHits)
	}
	if !strings.Contains(result.Error, "token 端点必须是 https") {
		t.Fatalf("error=%q", result.Error)
	}
	// 非 none 沿用既有行为（会探测）。
	result = &TestConnectionResult{Success: true, Discovery: doc}
	newLoopbackOIDCTester().ProbeAuthenticationEndpoints(context.Background(),
		TestConfig{ClientID: "c", ClientSecret: "s"}, result, "https://portal/cb")
	_ = result
}
