package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentAuthorizationProxyForwardsOnlyMachineRoutes(t *testing.T) {
	var gotPaths []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotPaths = append(gotPaths, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer principal-token" {
			t.Errorf("authorization header not forwarded: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Cookie") != "" {
			t.Errorf("cookie must not be forwarded: %q", r.Header.Get("Cookie"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"echo":` + string(body) + `}`))
	}))
	defer upstream.Close()
	proxy := AgentAuthorizationProxy(upstream.URL)
	for _, route := range AgentAuthorizationRoutes {
		req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(`{"k":1}`))
		req.Header.Set("Authorization", "Bearer principal-token")
		req.Header.Set("Cookie", "session=admin")
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `{"k":1}`) {
			t.Fatalf("%s status=%d body=%s", route, rec.Code, rec.Body.String())
		}
	}
	if len(gotPaths) != 3 {
		t.Fatalf("upstream paths=%v", gotPaths)
	}
	for _, path := range []string{"/admin/v1/agent/approval-requests/x", "/admin/v1/agent/approvals", "/admin/v1/agent/exceptions", "/admin/v1/agent/authorize?x=1"} {
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s must not be forwarded: status=%d", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/v1/agent/authorize", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status=%d", rec.Code)
	}
	if len(gotPaths) != 3 {
		t.Fatalf("rejected requests reached upstream: %v", gotPaths)
	}
}

func TestAgentAuthorizationProxyFailsClosed(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	downURL := down.URL
	down.Close()
	rec := httptest.NewRecorder()
	AgentAuthorizationProxy(downURL).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/v1/agent/approval-claims", strings.NewReader(`{}`)))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("offline upstream status=%d", rec.Code)
	}
	for _, bad := range []string{"", "not a url", "ftp://cp:21", "http://cp:8081/prefix"} {
		rec := httptest.NewRecorder()
		AgentAuthorizationProxy(bad).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/v1/agent/authorize", strings.NewReader(`{}`)))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("bad url %q status=%d", bad, rec.Code)
		}
	}
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { upstreamHits++ }))
	defer upstream.Close()
	big := strings.NewReader(`{"x":"` + strings.Repeat("a", agentAuthorizationProxyBodyLimit) + `"}`)
	rec = httptest.NewRecorder()
	AgentAuthorizationProxy(upstream.URL).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/v1/agent/authorize", big))
	if rec.Code != http.StatusRequestEntityTooLarge || upstreamHits != 0 {
		t.Fatalf("oversized status=%d hits=%d", rec.Code, upstreamHits)
	}
}
