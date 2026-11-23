package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNativeIdentityGatewayForwardsUnchangedAndPreservesStatus(t *testing.T) {
	for _, status := range []int{200, 401, 409, 422, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			payload := `{"schema_version":"1.0","producer":{"kind":"service","native_id":"dify-a"},"events":[]}`
			ack := `{"schema_version":"identity-events.ack.v1","accepted":["id"],"duplicates":[]}`
			calls := 0
			cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/admin/v1/internal/agent/endpoints/resolve" {
					io.WriteString(w, `{"tenant_id":"tenant-a","endpoint_id":"ep-a","licensed":true,"revoked":false}`)
					return
				}
				calls++
				b, _ := io.ReadAll(r.Body)
				if r.URL.Path != "/admin/v1/internal/agent/identity-events" || string(b) != payload || r.Header.Get("Authorization") != "Bearer endpoint-token" || r.Header.Get("X-JJDGuard-Internal-Token") != "internal-test-secret" {
					t.Error("native forwarding changed path/body/credential")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				io.WriteString(w, ack)
			}))
			defer cp.Close()
			g := &AgentEndpointGateway{enabled: true, controlURL: cp.URL, secret: "internal-test-secret", client: cp.Client(), auth: make(map[string]endpointAuthCacheEntry), rateLimiter: newEndpointRateLimiter()}
			r := httptest.NewRequest(http.MethodPost, "/agent/v1/identity-events", strings.NewReader(payload))
			r.Header.Set("Authorization", "Bearer endpoint-token")
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			if w.Code != status || w.Body.String() != ack || calls != 1 {
				t.Fatalf("status=%d body=%s calls=%d", w.Code, w.Body.String(), calls)
			}
		})
	}
}
func TestNativeIdentityGatewayBoundsAndNoForwardRedirect(t *testing.T) {
	forwarded := 0
	redirected := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected++; w.WriteHeader(200) }))
	defer target.Close()
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/v1/internal/agent/endpoints/resolve" {
			io.WriteString(w, `{"tenant_id":"tenant-a","endpoint_id":"ep-a","licensed":true,"revoked":false}`)
			return
		}
		forwarded++
		http.Redirect(w, r, target.URL, 302)
	}))
	defer cp.Close()
	g := &AgentEndpointGateway{enabled: true, controlURL: cp.URL, client: cp.Client(), auth: make(map[string]endpointAuthCacheEntry), rateLimiter: newEndpointRateLimiter()}
	for _, tc := range []struct {
		body, encoding, query string
		status                int
	}{
		{strings.Repeat("a", nativeIdentityBodyLimit+1), "", "", 413}, {"{}", "gzip", "", 415}, {"{}", "", "?tenant_id=b", 400}, {"{}", "", "", 502},
	} {
		r := httptest.NewRequest(http.MethodPost, "/agent/v1/identity-events"+tc.query, strings.NewReader(tc.body))
		r.Header.Set("Authorization", "Bearer endpoint-token")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Content-Encoding", tc.encoding)
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("status=%d want=%d", w.Code, tc.status)
		}
	}
	if forwarded != 1 || redirected != 0 {
		t.Fatalf("forwarded=%d redirected=%d", forwarded, redirected)
	}
}
