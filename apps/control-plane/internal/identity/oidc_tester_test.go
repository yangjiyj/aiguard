package identity

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func newLoopbackOIDCTester() *OIDCTester {
	tester := NewOIDCTester()
	tester.guard.alwaysBlocked = nil
	tester.guard.allowNonGlobalForTest = true
	return tester
}

func TestOIDCInvalidURL(t *testing.T) {
	tester := NewOIDCTester()
	result := tester.TestConnection(context.Background(), TestConfig{
		IssuerURL: "://not-a-url",
		Claims: ClaimConfig{
			SubjectClaim: "sub", UsernameClaim: "preferred_username",
			NameClaim: "name", EmailClaim: "email",
		},
	})
	if result.Success {
		t.Fatal("should fail")
	}
	if result.Stages[0].Status != "failed" {
		t.Fatalf("stage 0 should fail, got %+v", result.Stages[0])
	}
}

func TestOIDCSSRFBlocked(t *testing.T) {
	tester := NewOIDCTester()
	result := tester.TestConnection(context.Background(), TestConfig{
		IssuerURL: "http://127.0.0.1:9999",
		Claims: ClaimConfig{
			SubjectClaim: "sub", UsernameClaim: "preferred_username",
			NameClaim: "name", EmailClaim: "email",
		},
	})
	if result.Success {
		t.Fatal("should fail")
	}
	if !strings.Contains(result.Stages[0].Message, "禁止") {
		t.Fatalf("should mention blocked: %v", result.Stages[0])
	}
}

func TestOIDCDiscoveryFetchFail(t *testing.T) {
	tester := NewOIDCTester()
	result := tester.TestConnection(context.Background(), TestConfig{
		IssuerURL: "https://203.0.113.99:9999",
		Claims: ClaimConfig{
			SubjectClaim: "sub", UsernameClaim: "preferred_username",
			NameClaim: "name", EmailClaim: "email",
		},
	})
	if result.Success {
		t.Fatal("should fail")
	}
	if result.Stages[1].Status != "failed" {
		t.Fatalf("stage 1 should fail, got %+v", result.Stages[1])
	}
}

func TestOIDCRejectsPublicHTTPBeforeRequest(t *testing.T) {
	tester := NewOIDCTester()
	tester.guard.lookupIP = func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.40")}, nil
	}
	result := tester.TestConnection(context.Background(), TestConfig{
		IssuerURL: "http://public-idp.example",
		Claims: ClaimConfig{
			SubjectClaim: "sub", UsernameClaim: "preferred_username",
			NameClaim: "name", EmailClaim: "email",
		},
	})
	if result.Success || len(result.Stages) != 1 || result.Stages[0].Status != "failed" {
		t.Fatalf("public HTTP issuer must fail before fetching discovery: %+v", result)
	}
}

func makeDiscoveryHandler(t *testing.T, issuerOverride string, includeEndpoints bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		disc := map[string]interface{}{}
		if issuerOverride != "" {
			disc["issuer"] = issuerOverride
		}
		if includeEndpoints {
			disc["authorization_endpoint"] = issuerOverride + "/auth"
			disc["token_endpoint"] = issuerOverride + "/token"
			disc["jwks_uri"] = issuerOverride + "/jwks"
		}
		json.NewEncoder(w).Encode(disc)
	})
}

func TestOIDCIssuerMismatch(t *testing.T) {
	os.Setenv("JJD_IDP_ALLOW_CIDRS", "127.0.0.0/8")
	defer os.Unsetenv("JJD_IDP_ALLOW_CIDRS")

	ts := httptest.NewServer(makeDiscoveryHandler(t, "https://different-issuer.example.com", true))
	defer ts.Close()

	tester := newLoopbackOIDCTester()
	result := tester.TestConnection(context.Background(), TestConfig{
		IssuerURL: ts.URL,
		Claims: ClaimConfig{
			SubjectClaim: "sub", UsernameClaim: "preferred_username",
			NameClaim: "name", EmailClaim: "email",
		},
	})
	if result.Success {
		t.Fatal("should fail")
	}
	if result.Stages[2].Status != "failed" {
		t.Fatalf("stage 2 should fail, got %+v", result.Stages)
	}
	if !strings.Contains(result.Error, "不一致") {
		t.Fatalf("error should mention mismatch: %v", result.Error)
	}
}

func TestOIDCMissingEndpoints(t *testing.T) {
	os.Setenv("JJD_IDP_ALLOW_CIDRS", "127.0.0.0/8")
	defer os.Unsetenv("JJD_IDP_ALLOW_CIDRS")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer": "http://" + r.Host,
			})
		}
	}))
	defer ts.Close()

	tester := newLoopbackOIDCTester()
	result := tester.TestConnection(context.Background(), TestConfig{
		IssuerURL: ts.URL,
		Claims: ClaimConfig{
			SubjectClaim: "sub", UsernameClaim: "preferred_username",
			NameClaim: "name", EmailClaim: "email",
		},
	})
	if result.Success {
		t.Fatal("should fail")
	}
	if result.Stages[3].Status != "failed" {
		t.Fatalf("stage 3 should fail, got %+v", result.Stages)
	}
}

func TestOIDCSuccess(t *testing.T) {
	os.Setenv("JJD_IDP_ALLOW_CIDRS", "127.0.0.0/8")
	defer os.Unsetenv("JJD_IDP_ALLOW_CIDRS")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 "http://" + r.Host,
				"authorization_endpoint": "http://" + r.Host + "/auth",
				"token_endpoint":         "http://" + r.Host + "/token",
				"jwks_uri":               "http://" + r.Host + "/jwks",
			})
		}
	}))
	defer ts.Close()

	tester := newLoopbackOIDCTester()
	result := tester.TestConnection(context.Background(), TestConfig{
		IssuerURL: ts.URL,
		ClientID:  "test-client",
		Scopes:    "openid profile email",
		Claims: ClaimConfig{
			SubjectClaim:  "sub",
			UsernameClaim: "preferred_username",
			NameClaim:     "name",
			EmailClaim:    "email",
			DeptCodeClaim: "department_code",
		},
	})
	if !result.Success {
		t.Fatalf("should succeed, got: %+v", result)
	}
	if len(result.Stages) != 6 {
		t.Fatalf("expected 6 stages, got %d: %+v", len(result.Stages), result.Stages)
	}
	for _, s := range result.Stages {
		if s.Status != "passed" {
			t.Fatalf("stage %s should be passed, got %s", s.Name, s.Status)
		}
	}
}

func TestOIDCResponseSizeLimit(t *testing.T) {
	os.Setenv("JJD_IDP_ALLOW_CIDRS", "127.0.0.0/8")
	defer os.Unsetenv("JJD_IDP_ALLOW_CIDRS")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"filler":"` + strings.Repeat("x", 2*1024*1024) + `"}`))
		}
	}))
	defer ts.Close()

	tester := newLoopbackOIDCTester()
	result := tester.TestConnection(context.Background(), TestConfig{
		IssuerURL: ts.URL,
		Claims: ClaimConfig{
			SubjectClaim: "sub", UsernameClaim: "preferred_username",
			NameClaim: "name", EmailClaim: "email",
		},
	})
	if result.Success {
		t.Fatal("should fail")
	}
	if result.Stages[1].Status != "failed" {
		t.Fatalf("stage 1 should fail, got %+v", result.Stages[1])
	}
}

func TestOIDCMissingClaims(t *testing.T) {
	os.Setenv("JJD_IDP_ALLOW_CIDRS", "127.0.0.0/8")
	defer os.Unsetenv("JJD_IDP_ALLOW_CIDRS")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 "http://" + r.Host,
				"authorization_endpoint": "http://" + r.Host + "/auth",
				"token_endpoint":         "http://" + r.Host + "/token",
				"jwks_uri":               "http://" + r.Host + "/jwks",
			})
		}
	}))
	defer ts.Close()

	tester := newLoopbackOIDCTester()
	result := tester.TestConnection(context.Background(), TestConfig{
		IssuerURL: ts.URL,
		Claims: ClaimConfig{
			SubjectClaim:  "",
			UsernameClaim: "",
			NameClaim:     "",
			EmailClaim:    "",
		},
	})
	if result.Success {
		t.Fatal("should fail")
	}
	if result.Stages[5].Status != "failed" {
		t.Fatalf("stage 5 should fail, got %+v", result.Stages)
	}
}

func TestOIDCRejectsBlockedRedirectTarget(t *testing.T) {
	tester := NewOIDCTester()
	tester.guard.lookupIP = func(host string) ([]net.IP, error) {
		if host == "public-idp.example" {
			return []net.IP{net.ParseIP("203.0.113.20")}, nil
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	client := tester.newHTTPClient()
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	via, err := http.NewRequest(http.MethodGet, "https://public-idp.example/.well-known/openid-configuration", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := client.CheckRedirect(req, []*http.Request{via}); err == nil {
		t.Fatal("redirect to a blocked target must be rejected")
	}
}

func TestOIDCRejectsRedirectFromHTTPSToPublicHTTP(t *testing.T) {
	tester := NewOIDCTester()
	tester.guard.lookupIP = func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.50")}, nil
	}
	client := tester.newHTTPClient()
	req, err := http.NewRequest(http.MethodGet, "http://redirect-idp.example/discovery", nil)
	if err != nil {
		t.Fatal(err)
	}
	via, err := http.NewRequest(http.MethodGet, "https://public-idp.example/.well-known/openid-configuration", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(req, []*http.Request{via}); err == nil {
		t.Fatal("redirect from HTTPS to public HTTP must be rejected")
	}
}
func TestOIDCRejectsDNSRebindingAtDialTime(t *testing.T) {
	tester := NewOIDCTester()
	lookups := 0
	tester.guard.lookupIP = func(string) ([]net.IP, error) {
		lookups++
		if lookups == 1 {
			return []net.IP{net.ParseIP("203.0.113.30")}, nil
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}

	result := tester.TestConnection(context.Background(), TestConfig{
		IssuerURL: "https://rebind-idp.example:8080",
		Claims: ClaimConfig{
			SubjectClaim: "sub", UsernameClaim: "preferred_username",
			NameClaim: "name", EmailClaim: "email",
		},
	})
	if result.Success || len(result.Stages) < 2 || result.Stages[1].Status != "failed" {
		t.Fatalf("DNS rebinding must fail during discovery fetch: %+v", result)
	}
}

func TestOIDCRejectsHTTPDNSRebindingToPublicAtRequestTime(t *testing.T) {
	t.Setenv("JJD_IDP_ALLOW_CIDRS", "10.0.0.0/8")
	tester := NewOIDCTester()
	lookups := 0
	tester.guard.lookupIP = func(string) ([]net.IP, error) {
		lookups++
		if lookups == 1 {
			return []net.IP{net.ParseIP("10.0.0.10")}, nil
		}
		return []net.IP{net.ParseIP("203.0.113.50")}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	result := tester.TestConnection(ctx, TestConfig{
		IssuerURL: "http://rebind-idp.example:8080",
		Claims: ClaimConfig{
			SubjectClaim: "sub", UsernameClaim: "preferred_username",
			NameClaim: "name", EmailClaim: "email",
		},
	})

	if result.Success || len(result.Stages) < 2 || result.Stages[1].Status != "failed" {
		t.Fatalf("HTTP DNS rebinding must fail during discovery fetch: %+v", result)
	}
	if !strings.Contains(result.Stages[1].Message, "HTTPS") {
		t.Fatalf("HTTP DNS rebinding must be rejected by scheme policy, got: %+v", result.Stages[1])
	}
}
func TestOIDCAcceptsFullDiscoveryURL(t *testing.T) {
	t.Setenv("JJD_IDP_ALLOW_CIDRS", "127.0.0.0/8")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := "http://" + r.Host
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/jwks",
		})
	}))
	defer ts.Close()

	result := newLoopbackOIDCTester().TestConnection(context.Background(), TestConfig{
		IssuerURL: ts.URL + "/.well-known/openid-configuration",
		ClientID:  "test-client",
		Claims: ClaimConfig{
			SubjectClaim: "sub", UsernameClaim: "preferred_username",
			NameClaim: "name", EmailClaim: "email",
		},
	})
	if !result.Success {
		t.Fatalf("full discovery URL should be accepted, got: %+v", result)
	}
}
