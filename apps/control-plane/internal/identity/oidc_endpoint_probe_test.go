package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOIDCProbeJWKSAndClientAuthenticationWithoutLeakingSecret(t *testing.T) {
	secret := "fixture-only-client-secret"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "fixture", "n": "AQAB", "e": "AQAB"}}})
			return
		}
		if r.URL.Path == "/token" {
			r.ParseForm()
			code := "invalid_client"
			if r.Form.Get("client_secret") == secret {
				code = "invalid_grant"
			}
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": secret})
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original })
	tester := newLoopbackOIDCTester()
	doc := &DiscoveryDocument{JWKSURI: server.URL + "/jwks", TokenEndpoint: server.URL + "/token", TokenEndpointAuthMethodsSupported: []string{"client_secret_post"}}
	for _, value := range []string{secret, "incorrect-fixture-secret"} {
		result := &TestConnectionResult{Success: true, Discovery: doc}
		tester.ProbeAuthenticationEndpoints(context.Background(), TestConfig{ClientID: "fixture-client", ClientSecret: value}, result, "https://portal.fixture/callback")
		if result.Success != (value == secret) {
			t.Fatalf("credential probe accepted incorrect client: success=%v", result.Success)
		}
		if len(result.Stages) != 2 {
			t.Fatalf("missing endpoint stages: %d", len(result.Stages))
		}
		encoded, _ := json.Marshal(result)
		if strings.Contains(string(encoded), secret) {
			t.Fatal("secret leaked in stage output")
		}
	}
}
func TestOIDCRedirectCannotChangeHostEvenToAllowedPrivateAddress(t *testing.T) {
	tester := NewOIDCTester()
	original, _ := http.NewRequest("GET", "https://10.8.184.6/oidc", nil)
	redirect, _ := http.NewRequest("GET", "https://192.168.20.246/oidc", nil)
	if err := tester.newHTTPClient().CheckRedirect(redirect, []*http.Request{original}); err == nil {
		t.Fatal("cross-host redirect accepted")
	}
}
