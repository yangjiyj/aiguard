package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestKubernetesSnapshotGatewayRequiresProductAndForwardsPublicRoute(t *testing.T) {
	forwarded := make([]string, 0, 1)
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = append(forwarded, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer endpoint-token" || r.Header.Get("X-JJDGuard-Internal-Token") != "internal-secret" {
			t.Errorf("missing bound proxy headers")
		}
		if body, err := io.ReadAll(r.Body); err != nil || string(body) != `{"request_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8"}` {
			t.Errorf("unexpected forwarded body=%q err=%v", body, err)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer control.Close()
	const token = "endpoint-token"
	cache := map[string]any{
		"tenant_id": "tenant-a", "endpoint_id": "endpoint-a", "licensed": true, "revoked": false,
		"agent_product": "claude-code",
	}
	gateway := &AgentEndpointGateway{
		enabled: true, controlURL: control.URL, secret: "internal-secret", client: control.Client(),
		auth:        map[string]endpointAuthCacheEntry{endpointTokenHash(token): {value: cache, expires: time.Now().Add(time.Minute)}},
		rateLimiter: newEndpointRateLimiter(),
	}
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/agent/v1/kubernetes/snapshot-runs",
			strings.NewReader(`{"request_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8"}`))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		gateway.ServeHTTP(w, r)
		return w
	}
	denied := request()
	if denied.Code != http.StatusForbidden || len(forwarded) != 0 {
		t.Fatalf("generic product reached Kubernetes route: status=%d forwarded=%#v", denied.Code, forwarded)
	}
	cache["agent_product"] = "aiprobe-kubernetes"
	accepted := request()
	if accepted.Code != http.StatusCreated || len(forwarded) != 1 ||
		forwarded[0] != "/admin/v1/internal/agent/kubernetes/snapshot-runs" {
		t.Fatalf("Kubernetes public route was not forwarded correctly: status=%d forwarded=%#v body=%s", accepted.Code, forwarded, accepted.Body.String())
	}
}

func TestKubernetesSnapshotGatewayRejectsCompressedBody(t *testing.T) {
	const token = "endpoint-token"
	cache := map[string]any{
		"tenant_id": "tenant-a", "endpoint_id": "endpoint-a", "licensed": true, "revoked": false,
		"agent_product": "aiprobe-kubernetes",
	}
	serverCalls := 0
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serverCalls++ }))
	defer control.Close()
	gateway := &AgentEndpointGateway{
		enabled: true, controlURL: control.URL, client: control.Client(),
		auth:        map[string]endpointAuthCacheEntry{endpointTokenHash(token): {value: cache, expires: time.Now().Add(time.Minute)}},
		rateLimiter: newEndpointRateLimiter(),
	}
	r := httptest.NewRequest(http.MethodPost, "/agent/v1/kubernetes/snapshots", strings.NewReader("not-gzipped"))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Encoding", "gzip")
	w := httptest.NewRecorder()
	gateway.ServeHTTP(w, r)
	if w.Code != http.StatusUnsupportedMediaType || serverCalls != 0 {
		t.Fatalf("compressed body reached control plane: status=%d calls=%d", w.Code, serverCalls)
	}
}
