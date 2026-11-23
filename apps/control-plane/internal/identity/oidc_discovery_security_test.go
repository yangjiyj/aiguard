package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func validDiscoveryTestConfig(issuer string) TestConfig {
	return TestConfig{
		IssuerURL: issuer,
		Claims: ClaimConfig{
			SubjectClaim: "sub", UsernameClaim: "preferred_username",
			NameClaim: "name", EmailClaim: "email",
		},
	}
}

func TestOIDCResolveDiscoveryReturnsValidatedTypedDocument(t *testing.T) {
	t.Setenv("JJD_IDP_ALLOW_CIDRS", "127.0.0.0/8")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := "http://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer": issuer, "authorization_endpoint": issuer + "/auth",
			"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
			"userinfo_endpoint": issuer + "/userinfo", "end_session_endpoint": issuer + "/logout",
		})
	}))
	defer ts.Close()

	doc, err := newLoopbackOIDCTester().ResolveDiscovery(context.Background(), validDiscoveryTestConfig(ts.URL))
	if err != nil {
		t.Fatalf("ResolveDiscovery: %v", err)
	}
	if doc.Issuer != ts.URL || doc.TokenEndpoint == "" || doc.JWKSURI == "" ||
		doc.UserInfoEndpoint == "" || doc.EndSessionEndpoint == "" {
		t.Fatalf("unexpected discovery document: %#v", doc)
	}
}

func TestOIDCRejectsBlockedProtocolEndpoint(t *testing.T) {
	t.Setenv("JJD_IDP_ALLOW_CIDRS", "127.0.0.0/8")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := "http://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer": issuer, "authorization_endpoint": issuer + "/auth",
			"token_endpoint": "http://169.254.169.254/latest/meta-data",
			"jwks_uri":       issuer + "/jwks",
		})
	}))
	defer ts.Close()

	result := newLoopbackOIDCTester().TestConnection(context.Background(), validDiscoveryTestConfig(ts.URL))
	if result.Success || len(result.Stages) < 4 || result.Stages[3].Status != "failed" {
		t.Fatalf("blocked discovery endpoint must fail validation: %+v", result)
	}
}

func TestOIDCRejectsProtocolEndpointFragment(t *testing.T) {
	t.Setenv("JJD_IDP_ALLOW_CIDRS", "127.0.0.0/8")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := "http://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer": issuer, "authorization_endpoint": issuer + "/auth#fragment",
			"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
		})
	}))
	defer ts.Close()

	result := newLoopbackOIDCTester().TestConnection(context.Background(), validDiscoveryTestConfig(ts.URL))
	if result.Success || len(result.Stages) < 4 || result.Stages[3].Status != "failed" {
		t.Fatalf("fragment-bearing discovery endpoint must fail validation: %+v", result)
	}
}
