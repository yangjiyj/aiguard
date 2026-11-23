package handler

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type endpointTransportFunc func(*http.Request) (*http.Response, error)

func (fn endpointTransportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func TestEndpointResolveRevocationWithinThirtySeconds(t *testing.T) {
	now := time.Date(2026, time.September, 23, 1, 0, 0, 0, time.UTC)
	revoked := false
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/admin/v1/internal/agent/policy-bundle" {
			_, _ = io.WriteString(w, `{"version":1}`)
			return
		}
		if r.URL.Path != "/admin/v1/internal/agent/endpoints/resolve" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"tenant_id": "tenant-a", "endpoint_id": "ep-a", "revoked": revoked, "licensed": true})
	}))
	defer server.Close()
	g := &AgentEndpointGateway{enabled: true, controlURL: server.URL, client: server.Client(), auth: make(map[string]endpointAuthCacheEntry), resolveNow: func() time.Time { return now }}
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/agent/v1/policy", nil)
		r.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w
	}
	if got := request(); got.Code != http.StatusOK {
		t.Fatalf("initial request status=%d body=%s", got.Code, got.Body.String())
	}
	revoked = true
	now = now.Add(29*time.Second + 999*time.Millisecond)
	if got := request(); got.Code != http.StatusOK || calls != 1 {
		t.Fatalf("cache before deadline status=%d calls=%d", got.Code, calls)
	}
	now = now.Add(time.Millisecond)
	got := request()
	var body map[string]any
	if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if got.Code != http.StatusForbidden || body["code"] != "AGENT_ENDPOINT_REVOKED" || calls != 2 {
		t.Fatalf("revocation at 30s status=%d body=%s calls=%d", got.Code, got.Body.String(), calls)
	}
}

func TestEndpointReceiveMakesNoExternalHTTP(t *testing.T) {
	original := http.DefaultTransport
	calls := 0
	http.DefaultTransport = endpointTransportFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return nil, fmt.Errorf("unexpected external HTTP request to %s", req.URL.Host)
	})
	t.Cleanup(func() { http.DefaultTransport = original })
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/admin/v1/internal/agent/endpoints/resolve":
			_, _ = io.WriteString(w, `{"tenant_id":"tenant-a","endpoint_id":"ep-a","revoked":false,"licensed":true}`)
		case "/admin/v1/internal/agent/events":
			_, _ = io.WriteString(w, `{"accepted":["event-0"]}`)
		default:
			t.Errorf("unexpected internal request %s", r.URL.Path)
		}
	}))
	defer control.Close()
	g := &AgentEndpointGateway{enabled: true, controlURL: control.URL, client: control.Client(), bodyLimit: 1 << 20, auth: make(map[string]endpointAuthCacheEntry), rateLimiter: newEndpointRateLimiter()}
	body := endpointEventBody(1, func(event map[string]any) {
		event["metadata"] = map[string]any{"source": "https://example.invalid/should-not-fetch"}
	})
	req := httptest.NewRequest(http.MethodPost, "/agent/v1/events", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if calls != 0 {
		t.Fatalf("unexpected external HTTP requests=%d", calls)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestEndpointRateLimiterWindowsAndIsolation(t *testing.T) {
	limiter := newEndpointRateLimiter()
	now := time.Date(2026, time.September, 23, 0, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }
	for i := 0; i < endpointEventsPerMinute; i++ {
		if allowed, _ := limiter.allow("tenant-a\x00ep-a", "events", endpointEventsPerMinute, time.Minute); !allowed {
			t.Fatalf("events request %d rejected before 120/min", i)
		}
	}
	if allowed, retry := limiter.allow("tenant-a\x00ep-a", "events", endpointEventsPerMinute, time.Minute); allowed || retry != 60 {
		t.Fatalf("events overflow allowed=%v retry=%d", allowed, retry)
	}
	if allowed, _ := limiter.allow("tenant-b\x00ep-a", "events", endpointEventsPerMinute, time.Minute); !allowed {
		t.Fatal("different tenant must have independent event quota")
	}
	for i := 0; i < endpointDecidePerSecond; i++ {
		if allowed, _ := limiter.allow("tenant-a\x00ep-a", "decide", endpointDecidePerSecond, time.Second); !allowed {
			t.Fatalf("decide request %d rejected before 20/sec", i)
		}
	}
	if allowed, retry := limiter.allow("tenant-a\x00ep-a", "decide", endpointDecidePerSecond, time.Second); allowed || retry != 1 {
		t.Fatalf("decide overflow allowed=%v retry=%d", allowed, retry)
	}
	now = now.Add(time.Second)
	if allowed, _ := limiter.allow("tenant-a\x00ep-a", "decide", endpointDecidePerSecond, time.Second); !allowed {
		t.Fatal("decide quota did not reset after one second")
	}
	now = now.Add(59 * time.Second)
	if allowed, _ := limiter.allow("tenant-a\x00ep-a", "events", endpointEventsPerMinute, time.Minute); !allowed {
		t.Fatal("event quota did not reset after one minute")
	}
}

func TestEndpointRateLimitResponseContract(t *testing.T) {
	g := &AgentEndpointGateway{rateLimiter: newEndpointRateLimiter()}
	ctx := map[string]any{"tenant_id": "tenant-a", "endpoint_id": "ep-a"}
	for i := 0; i < endpointDecidePerSecond; i++ {
		w := httptest.NewRecorder()
		if !g.admitEndpointRequest(w, ctx, "decide", endpointDecidePerSecond, time.Second) {
			t.Fatalf("admission %d rejected: %s", i, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	if g.admitEndpointRequest(w, ctx, "decide", endpointDecidePerSecond, time.Second) {
		t.Fatal("expected request 21 to be rate limited")
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "1" || body["code"] != "AGENT_RATE_LIMITED" {
		t.Fatalf("status=%d retry=%q body=%s", w.Code, w.Header().Get("Retry-After"), w.Body.String())
	}
}

func TestDecideRequestContractFieldsDecode(t *testing.T) {
	var q struct {
		EndpointID string `json:"endpoint_id"`
		SessionID  string `json:"session_id"`
		PromptID   string `json:"prompt_id"`
		ToolUseID  string `json:"tool_use_id"`
		Tool       struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"tool"`
		Context struct {
			Fragments []struct {
				Trust   string `json:"trust"`
				Source  string `json:"source"`
				Hash    string `json:"hash"`
				Preview string `json:"preview"`
			} `json:"fragments"`
		} `json:"context"`
	}
	body := []byte(`{"endpoint_id":"ep_1","session_id":"s_1","prompt_id":"p_1","tool_use_id":"tu_1","tool":{"name":"read_file","type":"filesystem"},"context":{"fragments":[{"trust":"trusted","source":"hook","hash":"sha256:x","preview":"safe"}]}}`)
	if err := json.Unmarshal(body, &q); err != nil {
		t.Fatal(err)
	}
	if q.Tool.Type != "filesystem" || len(q.Context.Fragments) != 1 || q.Context.Fragments[0].Source != "hook" || q.Context.Fragments[0].Hash != "sha256:x" || q.Context.Fragments[0].Preview != "safe" {
		t.Fatalf("contract decode failed: %#v", q)
	}
}

const hookdDecideRequestFixture = "{\"endpoint_id\":\"ep_fixture01\",\"session_id\":\"session_fixture\",\"tool_use_id\":\"toolu_fixture\",\"agent\":{\"product\":\"claude-code\",\"version\":\"2.1.278\"},\"tool\":{\"name\":\"Read\",\"type\":\"file\",\"mcp_server\":\"fixture\"},\"arguments\":{\"file_path\":\"/tmp/fixture\",\"nested\":{\"value\":true}},\"context\":{\"cwd_hash\":\"sha256:abc\",\"permission_mode\":\"default\",\"fragments\":[{\"trust\":\"trusted\",\"source\":\"instruction_file\",\"tool_use_id\":\"toolu_previous\",\"hash\":\"sha256:def\",\"preview\":\"safe context\"}]},\"local_decision\":{\"raw\":\"audit\",\"rule_id\":\"fixture-rule\",\"latency_ms\":2}}"

func TestDecideAcceptsHookdV1Request(t *testing.T) {
	w := runEndpointDecideBody(t, hookdDecideRequestFixture)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestDecideBindsRequestToAuthenticatedEndpoint(t *testing.T) {
	body := strings.Replace(hookdDecideRequestFixture, "\"endpoint_id\":\"ep_fixture01\"", "\"endpoint_id\":\"ep_other01\"", 1)
	w := runEndpointDecideBody(t, body)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "\"code\":\"AGENT_UNAUTHORIZED\"") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestDecideRejectsInvalidHookdRequestShape(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"unknown root field", strings.Replace(hookdDecideRequestFixture, "\"context\":{", "\"unexpected\":true,\"context\":{", 1)},
		{"unknown nested field", strings.Replace(hookdDecideRequestFixture, "\"tool\":{\"name\":\"Read\",\"type\":\"file\",\"mcp_server\":\"fixture\"}", "\"tool\":{\"name\":\"Read\",\"type\":\"file\",\"mcp_server\":\"fixture\",\"unexpected\":true}", 1)},
		{"duplicate root field", strings.Replace(hookdDecideRequestFixture, "\"session_id\":\"session_fixture\",", "\"session_id\":\"session_fixture\",\"session_id\":\"other\",", 1)},
		{"duplicate nested field", strings.Replace(hookdDecideRequestFixture, "\"name\":\"Read\"", "\"name\":\"Read\",\"name\":\"Write\"", 1)},
		{"missing required tool id", strings.Replace(hookdDecideRequestFixture, "\"tool_use_id\":\"toolu_fixture\",", "", 1)},
		{"invalid tool type enum", strings.Replace(hookdDecideRequestFixture, "\"type\":\"file\"", "\"type\":\"unsupported\"", 1)},
		{"invalid fragment source enum", strings.Replace(hookdDecideRequestFixture, "\"source\":\"instruction_file\"", "\"source\":\"unsupported\"", 1)},
		{"invalid local decision enum", strings.Replace(hookdDecideRequestFixture, "\"raw\":\"audit\"", "\"raw\":\"unsupported\"", 1)},
		{"null optional string", strings.Replace(hookdDecideRequestFixture, "\"version\":\"2.1.278\"", "\"version\":null", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := runEndpointDecideBody(t, tc.body)
			if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "\"code\":\"AGENT_INVALID_REQUEST\"") {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
func endpointEventBody(count int, mutate func(map[string]any)) []byte {
	events := make([]any, 0, count)
	for i := 0; i < count; i++ {
		event := map[string]any{
			"event_id": fmt.Sprintf("event-%d", i), "event_type": "tool.pre",
			"occurred_at":  time.Now().UTC().Format(time.RFC3339Nano),
			"tool_call_id": fmt.Sprintf("call-%d", i), "tool_name": "read_file", "tool_type": "filesystem",
		}
		if mutate != nil {
			mutate(event)
		}
		events = append(events, event)
	}
	body, _ := json.Marshal(map[string]any{"schema_version": "events.v1", "events": events})
	return body
}

func newEndpointGatewayTestServer(t *testing.T, bodyLimit int64) (*AgentEndpointGateway, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accepted":[]}`))
	}))
	t.Cleanup(server.Close)
	return &AgentEndpointGateway{controlURL: server.URL, client: server.Client(), bodyLimit: bodyLimit}, calls
}

func runEndpointEvents(g *AgentEndpointGateway, body []byte, encoding string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/agent/v1/events", bytes.NewReader(body))
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	w := httptest.NewRecorder()
	g.events(w, req, "token", map[string]any{})
	return w
}

func TestEndpointEventsRejectsGzipExpandedOverLimit(t *testing.T) {
	body := endpointEventBody(1, func(event map[string]any) { event["result"] = strings.Repeat("x", 4096) })
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	_, _ = z.Write(body)
	_ = z.Close()
	g, calls := newEndpointGatewayTestServer(t, 512)
	w := runEndpointEvents(g, compressed.Bytes(), "gzip")
	if w.Code != http.StatusRequestEntityTooLarge || calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, calls.Load())
	}
}

func TestEndpointEventsRejectsTrailingJSON(t *testing.T) {
	g, calls := newEndpointGatewayTestServer(t, 1<<20)
	body := append(endpointEventBody(1, nil), []byte(` {}`)...)
	w := runEndpointEvents(g, body, "")
	if w.Code != http.StatusUnprocessableEntity || calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, calls.Load())
	}
}

func TestEndpointEventsRejectsBatchOverLimit(t *testing.T) {
	g, calls := newEndpointGatewayTestServer(t, 1<<20)
	w := runEndpointEvents(g, endpointEventBody(maxEndpointEvents+1, nil), "")
	if w.Code != http.StatusUnprocessableEntity || calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, calls.Load())
	}
}

func TestEndpointEventsRejectsWholeBatchBeforeForwardingOnPrivacyFailure(t *testing.T) {
	g, calls := newEndpointGatewayTestServer(t, 1<<20)
	body := endpointEventBody(2, func(event map[string]any) {
		if event["event_id"] == "event-1" {
			event["payload"] = map[string]any{"api-key": "must-not-forward"}
		}
	})
	w := runEndpointEvents(g, body, "")
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "AGENT_PRIVACY_REJECTED") || calls.Load() != 0 {
		t.Fatalf("status=%d body=%q calls=%d", w.Code, w.Body.String(), calls.Load())
	}
}

func TestEndpointEventsKeepsToolPreAndPostAllowlisted(t *testing.T) {
	for _, typ := range []string{"tool.pre", "tool.post"} {
		t.Run(typ, func(t *testing.T) {
			g, calls := newEndpointGatewayTestServer(t, 1<<20)
			body := endpointEventBody(1, func(event map[string]any) { event["event_type"] = typ })
			w := runEndpointEvents(g, body, "")
			if w.Code != http.StatusOK || calls.Load() != 1 {
				t.Fatalf("status=%d body=%q calls=%d", w.Code, w.Body.String(), calls.Load())
			}
		})
	}
}

func TestEndpointEventsRejectsUnknownContentEncoding(t *testing.T) {
	g, calls := newEndpointGatewayTestServer(t, 1<<20)
	w := runEndpointEvents(g, endpointEventBody(1, nil), "br")
	if w.Code != http.StatusUnsupportedMediaType || calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, calls.Load())
	}
}

func TestEndpointDecideRejectsBodyOverLimit(t *testing.T) {
	g := &AgentEndpointGateway{}
	body := `{"arguments":{"value":"` + strings.Repeat("x", endpointDecideBodyLimit) + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/agent/v1/decide", strings.NewReader(body))
	w := httptest.NewRecorder()
	g.decide(w, req, "", map[string]any{})
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestEndpointLicenseChangeWithinThirtySeconds(t *testing.T) {
	now := time.Date(2026, time.September, 23, 1, 0, 0, 0, time.UTC)
	licensed := true
	calls := 0
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/v1/internal/agent/endpoints/resolve" {
			calls++
			_ = json.NewEncoder(w).Encode(map[string]any{"tenant_id": "tenant-a", "endpoint_id": "ep-a", "licensed": licensed})
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer control.Close()
	g := &AgentEndpointGateway{enabled: true, controlURL: control.URL, client: control.Client(), auth: make(map[string]endpointAuthCacheEntry), resolveNow: func() time.Time { return now }}
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/agent/v1/policy", nil)
		r.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w
	}
	if w := request(); w.Code != http.StatusOK {
		t.Fatalf("initial status=%d", w.Code)
	}
	licensed = false
	now = now.Add(29*time.Second + 999*time.Millisecond)
	if w := request(); w.Code != http.StatusOK || calls != 1 {
		t.Fatalf("cached status=%d calls=%d", w.Code, calls)
	}
	now = now.Add(time.Millisecond)
	if w := request(); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AGENT_UNLICENSED") || calls != 2 {
		t.Fatalf("revoked license status=%d body=%s calls=%d", w.Code, w.Body.String(), calls)
	}
}

func TestEndpointMissingLicenseFlagFailsClosed(t *testing.T) {
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"tenant_id":"tenant-a","endpoint_id":"ep-a"}`)
	}))
	defer control.Close()
	g := &AgentEndpointGateway{enabled: true, controlURL: control.URL, client: control.Client(), auth: make(map[string]endpointAuthCacheEntry)}
	r := httptest.NewRequest(http.MethodGet, "/agent/v1/policy", nil)
	r.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AGENT_UNLICENSED") {
		t.Fatalf("missing licensed flag status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestEndpointRegistrationLicenseCache(t *testing.T) {
	now := time.Date(2026, time.September, 23, 1, 0, 0, 0, time.UTC)
	licensed := false
	statusCalls, registerCalls := 0, 0
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agent/license-status":
			statusCalls++
			_ = json.NewEncoder(w).Encode(map[string]bool{"licensed": licensed})
		case "/admin/v1/internal/agent/endpoints/register":
			registerCalls++
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer control.Close()
	g := &AgentEndpointGateway{enabled: true, controlURL: control.URL, client: control.Client(), resolveNow: func() time.Time { return now }}
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/agent/v1/endpoints/register", strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer enrollment")
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w
	}
	if w := request(); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AGENT_UNLICENSED") {
		t.Fatalf("unlicensed registration status=%d body=%s", w.Code, w.Body.String())
	}
	licensed = true
	now = now.Add(29 * time.Second)
	if w := request(); w.Code != http.StatusForbidden || statusCalls != 1 || registerCalls != 0 {
		t.Fatalf("cached registration status=%d checks=%d registrations=%d", w.Code, statusCalls, registerCalls)
	}
	now = now.Add(time.Second)
	if w := request(); w.Code != http.StatusCreated || statusCalls != 2 || registerCalls != 1 {
		t.Fatalf("licensed registration status=%d checks=%d registrations=%d", w.Code, statusCalls, registerCalls)
	}
}

func TestEndpointResolveUnavailableDoesNotReuseExpiredLicense(t *testing.T) {
	now := time.Date(2026, time.September, 23, 1, 0, 0, 0, time.UTC)
	controlAvailable := true
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !controlAvailable {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/admin/v1/internal/agent/endpoints/resolve" {
			_, _ = io.WriteString(w, `{"tenant_id":"tenant-a","endpoint_id":"ep-a","licensed":true}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer control.Close()
	g := &AgentEndpointGateway{enabled: true, controlURL: control.URL, client: control.Client(), auth: make(map[string]endpointAuthCacheEntry), resolveNow: func() time.Time { return now }}
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/agent/v1/policy", nil)
		r.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w
	}
	if w := request(); w.Code != http.StatusOK {
		t.Fatalf("initial status=%d", w.Code)
	}
	controlAvailable = false
	now = now.Add(30 * time.Second)
	if w := request(); w.Code == http.StatusOK {
		t.Fatalf("expired license cache reused after control failure: %s", w.Body.String())
	}
}

func TestEndpointRegistrationUnavailableFailsClosed(t *testing.T) {
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer control.Close()
	g := &AgentEndpointGateway{enabled: true, controlURL: control.URL, client: control.Client()}
	r := httptest.NewRequest(http.MethodPost, "/agent/v1/endpoints/register", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer enrollment")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "AGENT_LICENSE_CHECK_FAILED") {
		t.Fatalf("unavailable license status=%d body=%s", w.Code, w.Body.String())
	}
}
