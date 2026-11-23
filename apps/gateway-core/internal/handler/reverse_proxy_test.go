package handler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testEgressResolver(rawURL string) func(context.Context, string, int, bool, []string) (resolvedEgressTarget, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return func(_ context.Context, host string, port int, _ bool, _ []string) (resolvedEgressTarget, error) {
		return resolvedEgressTarget{
			Host: host, Port: port, DialAddress: parsed.Host,
		}, nil
	}
}

func TestMatchReverseProxyRoute_LongestPrefixWins(t *testing.T) {
	h := &ReverseProxyHandler{
		routes: []ReverseProxyRoute{
			{ID: "short", PathPrefix: "/proxy"},
			{ID: "long", PathPrefix: "/proxy/doubao"},
		},
	}

	route := h.matchRoute("/proxy/doubao/chat/completions")
	if route == nil {
		t.Fatalf("expected a matching route")
	}
	if route.ID != "long" {
		t.Fatalf("expected longest prefix route, got %s", route.ID)
	}
}

func TestReverseProxyServeHTTP_RewritesPathAndForwards(t *testing.T) {
	var gotPath string
	var gotQuery string
	var gotHost string
	var gotBody string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotHost = r.Host
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	handler := &ReverseProxyHandler{
		tenantID:            "tenant_default",
		client:              upstream.Client(),
		resolveEgressTarget: testEgressResolver(upstream.URL),
		routes: []ReverseProxyRoute{
			{
				ID:               "rpr_001",
				PathPrefix:       "/proxy/doubao",
				TargetURL:        upstream.URL,
				TargetPathPrefix: "/api/v3",
				SecurityEnabled:  false,
				StatsEnabled:     false,
				Status:           "active",
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/proxy/doubao/chat/completions?foo=bar", strings.NewReader(`{"hello":"world"}`))
	w := httptest.NewRecorder()

	handled := handler.ServeHTTP(w, req)

	if !handled {
		t.Fatalf("expected request to be handled by reverse proxy")
	}
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d body=%s", w.Code, w.Body.String())
	}
	if gotPath != "/api/v3/chat/completions" {
		t.Fatalf("expected rewritten path /api/v3/chat/completions, got %s", gotPath)
	}
	if gotQuery != "foo=bar" {
		t.Fatalf("expected query foo=bar, got %s", gotQuery)
	}
	if gotHost == "" {
		t.Fatalf("expected rewritten host header to be set")
	}
	if gotBody != `{"hello":"world"}` {
		t.Fatalf("expected body to be forwarded, got %s", gotBody)
	}
}

func TestReverseProxyServeHTTP_WritesAccessRetentionForCompatibleAPI(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("expected upstream path /v1/chat/completions, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"content":"answer from upstream"}}],"usage":{"prompt_tokens":12,"completion_tokens":7}}`))
	}))
	defer upstream.Close()

	audit := &fakeReverseProxyAuditRecorder{}
	handler := &ReverseProxyHandler{
		tenantID:            "tenant_default",
		client:              upstream.Client(),
		resolveEgressTarget: testEgressResolver(upstream.URL),
		auditRecorder:       audit,
		routes: []ReverseProxyRoute{
			{
				ID:              "rpr_examplegw",
				PathPrefix:      "/examplegw",
				TargetURL:       upstream.URL,
				SecurityEnabled: false,
				StatsEnabled:    false,
				Status:          "active",
			},
		},
	}

	body := `{"messages":[{"role":"user","content":"hello from OpenAI Codex"}]}`
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/examplegw/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "codex-cli/0.1")
	w := httptest.NewRecorder()

	if !handler.ServeHTTP(w, req) {
		t.Fatalf("expected request to be handled by reverse proxy")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}
	if len(audit.records) == 0 {
		t.Fatalf("expected reverse proxy to write an access retention request log")
	}
	record := audit.records[len(audit.records)-1]
	if record.Status != "success" || record.StatusCode != http.StatusOK {
		t.Fatalf("expected success audit record, got status=%s status_code=%d", record.Status, record.StatusCode)
	}
	if record.AccessType != "llm" || record.Provider != "openai_compatible" || !record.ContentRetained {
		t.Fatalf("expected compatible API to be retained as llm content, got access_type=%s provider=%s retained=%v", record.AccessType, record.Provider, record.ContentRetained)
	}
	if record.AgentType != "openai-codex" {
		t.Fatalf("expected codex agent type from headers/body, got %q", record.AgentType)
	}
	if record.TargetPath != "/v1/chat/completions" {
		t.Fatalf("expected target path without proxy prefix, got %q", record.TargetPath)
	}
	if len(audit.contents) != 1 {
		t.Fatalf("expected one retained content log, got %d", len(audit.contents))
	}
	content := audit.contents[0]
	if !strings.Contains(string(content.requestBody), "hello from OpenAI Codex") {
		t.Fatalf("expected retained request body to contain user prompt, got %s", string(content.requestBody))
	}
	if !strings.Contains(string(content.responseBody), "answer from upstream") {
		t.Fatalf("expected retained response body to contain model output, got %s", string(content.responseBody))
	}
}

func TestReverseProxyServeHTTP_AuditOnlyAllowsSecurityBlockDecision(t *testing.T) {
	var upstreamCalled bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"content":"answer from upstream"}}]}`))
	}))
	defer upstream.Close()

	security := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/check-input/" {
			w.Write([]byte(`{"action":"block","findings":[{"type":"prompt_injection","category":"structured_template_injection","severity":"high"}]}`))
			return
		}
		if r.URL.Path == "/check-output/" {
			w.Write([]byte(`{"action":"allow","findings":[]}`))
			return
		}
		t.Fatalf("unexpected security check path %s", r.URL.Path)
	}))
	defer security.Close()

	audit := &fakeReverseProxyAuditRecorder{}
	handler := &ReverseProxyHandler{
		tenantID:                  "tenant_default",
		client:                    upstream.Client(),
		securityURL:               security.URL,
		resolveEgressTarget:       testEgressResolver(upstream.URL),
		auditRecorder:             audit,
		securityAuditOnlyFallback: true,
		routes: []ReverseProxyRoute{{
			ID:              "rpr_examplegw",
			PathPrefix:      "/examplegw",
			TargetURL:       upstream.URL,
			SecurityEnabled: true,
			StatsEnabled:    false,
			Status:          "active",
		}},
	}

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/examplegw/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"normal agent request"}]}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	if !handler.ServeHTTP(w, req) {
		t.Fatalf("expected request to be handled by reverse proxy")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("audit-only mode should forward instead of block, got %d body=%s", w.Code, w.Body.String())
	}
	if !upstreamCalled {
		t.Fatalf("expected upstream to be called in audit-only mode")
	}
	if len(audit.records) == 0 {
		t.Fatalf("expected audit record")
	}
	record := audit.records[len(audit.records)-1]
	if record.Status != "success" || record.StatusCode != http.StatusOK {
		t.Fatalf("expected success audit record, got status=%s status_code=%d", record.Status, record.StatusCode)
	}
}

func TestReverseProxyServeHTTP_AuditOnlyAllowsFileAttachmentFinding(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "false")
	var upstreamCalled bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	security := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/check-input/" {
			_, _ = io.WriteString(w, `{"action":"audit","findings":[{"type":"pii","category":"phone_cn","content_source":"file_attachment"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"action":"allow","findings":[]}`)
	}))
	defer security.Close()

	handler := &ReverseProxyHandler{
		tenantID:                  "tenant_default",
		client:                    upstream.Client(),
		securityURL:               security.URL,
		resolveEgressTarget:       testEgressResolver(upstream.URL),
		securityAuditOnlyFallback: true,
		routes: []ReverseProxyRoute{{
			ID: "rpr_file_audit_only", PathPrefix: "/proxy", TargetURL: upstream.URL,
			SecurityEnabled: true, StatsEnabled: false, Status: "active",
		}},
	}

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/proxy/upload/report.pdf",
		strings.NewReader("%PDF-1.7\ncustomer phone 13812345678\n"))
	req.Header.Set("Content-Type", "application/pdf")
	w := httptest.NewRecorder()

	if !handler.ServeHTTP(w, req) {
		t.Fatalf("expected request to be handled by reverse proxy")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("audit-only file finding must block, got %d body=%s", w.Code, w.Body.String())
	}
	if !upstreamCalled {
		t.Fatal("blocked file must not reach reverse-proxy upstream")
	}
}

func TestReverseProxyServeHTTP_AuditOnlyAllowsOrdinaryFindingWithFileAttachment(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "false")
	var upstreamCalled bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	security := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/check-input/" {
			_, _ = io.WriteString(w, `{"action":"block","findings":[{"type":"prompt_injection","category":"structured_template_injection","content_source":"user"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"action":"allow","findings":[]}`)
	}))
	defer security.Close()

	handler := &ReverseProxyHandler{
		tenantID:                  "tenant_default",
		client:                    upstream.Client(),
		securityURL:               security.URL,
		resolveEgressTarget:       testEgressResolver(upstream.URL),
		securityAuditOnlyFallback: true,
		routes: []ReverseProxyRoute{{
			ID: "rpr_file_with_text_finding", PathPrefix: "/proxy", TargetURL: upstream.URL,
			SecurityEnabled: true, StatsEnabled: false, Status: "active",
		}},
	}

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/proxy/upload/report.pdf",
		strings.NewReader("%PDF-1.7\\nnormal user text"))
	req.Header.Set("Content-Type", "application/pdf")
	w := httptest.NewRecorder()

	if !handler.ServeHTTP(w, req) {
		t.Fatalf("expected request to be handled by reverse proxy")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("audit-only ordinary text finding must forward even with an attachment, got %d body=%s", w.Code, w.Body.String())
	}
	if !upstreamCalled {
		t.Fatal("expected ordinary text finding with an attachment to reach upstream in audit-only mode")
	}
}

func TestReverseProxyServeHTTP_RetainsLSECorrelationForAuditOnly(t *testing.T) {
	var forwardedEvalHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedEvalHeader = r.Header.Get("X-LSE-Eval-Run-Id")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"content":"safe"}}]}`))
	}))
	defer upstream.Close()

	audit := &fakeReverseProxyAuditRecorder{}
	handler := &ReverseProxyHandler{
		tenantID:            "tenant_default",
		client:              upstream.Client(),
		resolveEgressTarget: testEgressResolver(upstream.URL),
		auditRecorder:       audit,
		routes: []ReverseProxyRoute{{
			ID:              "rpr_lse",
			PathPrefix:      "/examplegw",
			TargetURL:       upstream.URL,
			SecurityEnabled: false,
			StatsEnabled:    false,
			Status:          "active",
		}},
	}

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/examplegw/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"prompt"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-LSE-Eval-Run-Id", "eval-1")
	req.Header.Set("X-LSE-Task-Id", "task-1")
	req.Header.Set("X-LSE-Sample-Id", "sample-1")
	req.Header.Set("X-LSE-Target-Id", "target-1")
	req.Header.Set("X-LSE-Trace-Id", "trace-1")
	w := httptest.NewRecorder()

	if !handler.ServeHTTP(w, req) {
		t.Fatalf("expected request to be handled by reverse proxy")
	}
	if forwardedEvalHeader != "" {
		t.Fatalf("LSE correlation header must not be forwarded upstream, got %q", forwardedEvalHeader)
	}
	if len(audit.records) != 1 {
		t.Fatalf("expected one audit record, got %d", len(audit.records))
	}
	record := audit.records[0]
	if record.LSEEvalRunID != "eval-1" || record.LSETaskID != "task-1" || record.LSESampleID != "sample-1" || record.LSETargetID != "target-1" || record.TraceID != "trace-1" {
		t.Fatalf("expected audit record to retain LSE correlation, got trace=%q eval=%q task=%q sample=%q target=%q", record.TraceID, record.LSEEvalRunID, record.LSETaskID, record.LSESampleID, record.LSETargetID)
	}
}

type fakeReverseProxyAuditRecorder struct {
	records        []reverseProxyAuditRecord
	contents       []fakeReverseProxyContent
	securityEvents []fakeReverseProxySecurityEvent
}

type fakeReverseProxySecurityEvent struct {
	record      reverseProxyAuditRecord
	stage       string
	actionTaken string
	findings    []SecurityFinding
}

type fakeReverseProxyContent struct {
	record              reverseProxyAuditRecord
	requestBody         []byte
	requestContentType  string
	responseBody        []byte
	responseContentType string
}

func (f *fakeReverseProxyAuditRecorder) WriteReverseProxyAccess(ctx context.Context, record reverseProxyAuditRecord) {
	f.records = append(f.records, record)
}

func (f *fakeReverseProxyAuditRecorder) WriteReverseProxyContent(ctx context.Context, record reverseProxyAuditRecord, requestBody []byte, requestContentType string, responseBody []byte, responseContentType string) {
	f.contents = append(f.contents, fakeReverseProxyContent{record: record, requestBody: requestBody, requestContentType: requestContentType, responseBody: responseBody, responseContentType: responseContentType})
}

func (f *fakeReverseProxyAuditRecorder) WriteReverseProxySecurityEvent(ctx context.Context, record reverseProxyAuditRecord, stage, actionTaken string, findings []SecurityFinding) {
	f.securityEvents = append(f.securityEvents, fakeReverseProxySecurityEvent{record: record, stage: stage, actionTaken: actionTaken, findings: findings})
}

func TestReverseProxyServeHTTP_BlocksPrivateTargetURL(t *testing.T) {
	handler := &ReverseProxyHandler{
		tenantID: "tenant_default",
		client:   http.DefaultClient,
		routes: []ReverseProxyRoute{
			{
				ID:               "rpr_private",
				PathPrefix:       "/proxy/private",
				TargetURL:        "http://127.0.0.1:65535",
				TargetPathPrefix: "/api",
				Status:           "active",
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/proxy/private/status", nil)
	w := httptest.NewRecorder()

	handled := handler.ServeHTTP(w, req)

	if !handled {
		t.Fatalf("expected reverse proxy route to handle request")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected private target to be forbidden, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestForwardProxyServeHTTP_FallsBackWhenNoReverseProxyMatch(t *testing.T) {
	h := &ForwardProxyHandler{
		reverseProxy: &ReverseProxyHandler{},
	}

	req := httptest.NewRequest(http.MethodGet, "/not-matched", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405 for non-matching origin-form request, got %d", w.Code)
	}
}

func TestForwardProxyHostAllowed_DeniesUnconfiguredPublicHost(t *testing.T) {
	h := &ForwardProxyHandler{}

	if h.isHostAllowed("model.vendor.example", 443) {
		t.Fatal("gateway forward proxy requires a configured domain whitelist by default")
	}
}

func TestForwardProxyConnect_BlocksLoopbackEvenWhenWhitelisted(t *testing.T) {
	h := &ForwardProxyHandler{
		whitelist:  []whitelistEntry{{pattern: "127.0.0.1", port: 443}},
		lastReload: time.Now(),
	}

	req := httptest.NewRequest(http.MethodConnect, "http://127.0.0.1:443", nil)
	req.Host = "127.0.0.1:443"
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected loopback CONNECT to be forbidden, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestForwardProxyHTTP_BlocksMetadataAddressEvenWhenWhitelisted(t *testing.T) {
	h := &ForwardProxyHandler{
		whitelist:  []whitelistEntry{{pattern: "169.254.169.254", port: 80}},
		lastReload: time.Now(),
	}

	req := httptest.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected metadata HTTP proxy request to be forbidden, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestRewriteResponseURLs_InjectsProxyScriptBeforeExistingHeadScripts(t *testing.T) {
	route := ReverseProxyRoute{
		ID:         "rpr_doubao",
		PathPrefix: "/doubao",
		TargetURL:  "https://www.doubao.com",
	}
	html := `<html><head><script>window.beforePatch=location.pathname;</script></head><body></body></html>`

	rewritten := string(rewriteResponseURLs([]byte(html), "text/html; charset=utf-8", &route, []ReverseProxyRoute{route}, "100.64.0.21:8082"))

	injectedPos := strings.Index(rewritten, "<script>(function(){")
	if injectedPos < 0 {
		t.Fatalf("expected proxy injection script to be present")
	}
	beforeScriptPos := strings.Index(rewritten, "window.beforePatch=location.pathname;")
	if beforeScriptPos < 0 {
		t.Fatalf("expected original head script to remain present")
	}
	if injectedPos > beforeScriptPos {
		t.Fatalf("expected proxy injection to run before existing head scripts")
	}
}

func TestBuildProxyInjectScript_RewritesSameOriginAbsoluteURLs(t *testing.T) {
	route := &ReverseProxyRoute{
		ID:         "rpr_doubao",
		PathPrefix: "/doubao",
		TargetURL:  "https://www.doubao.com",
	}
	allRoutes := []ReverseProxyRoute{
		*route,
		{
			ID:         "rpr_doubao_cdn",
			PathPrefix: "/doubao-cdn",
			TargetURL:  "https://lf-flow-web-cdn.doubao.com",
		},
	}

	script := buildProxyInjectScript(route, allRoutes, "100.64.0.21:8082")

	for _, want := range []string{
		"new URL(u,location.href)",
		"parsed.host===location.host",
		"pp+parsed.pathname+parsed.search+parsed.hash",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("expected injection script to contain %q, got: %s", want, script)
		}
	}
}

func TestBuildProxyInjectScript_OverridesPathnameOnLocationPrototype(t *testing.T) {
	route := &ReverseProxyRoute{
		ID:         "rpr_doubao",
		PathPrefix: "/doubao",
		TargetURL:  "https://www.doubao.com",
	}

	script := buildProxyInjectScript(route, []ReverseProxyRoute{*route}, "100.64.0.21:8082")

	if strings.Contains(script, "Object.defineProperty(window.location,'pathname'") {
		t.Fatalf("expected pathname override to avoid redefining window.location directly")
	}
	if !strings.Contains(script, "Object.defineProperty(Location.prototype,'pathname'") {
		t.Fatalf("expected pathname override to patch Location.prototype")
	}
	if !strings.Contains(script, "try{") {
		t.Fatalf("expected injection script to isolate fragile browser patches with try/catch")
	}
}

func TestReverseProxyResolverFailuresAreNotPolicyBlocks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		code   int
		status string
	}{
		{"dns", fmt.Errorf("resolve egress host: no addresses"), 502, "target_resolution_failed"},
		{"timeout", fmt.Errorf("resolve egress host: %w", context.DeadlineExceeded), 504, "target_resolution_failed"},
		{"cancelled", fmt.Errorf("resolve egress host: %w", context.Canceled), 408, "cancelled"},
		{"unsafe", fmt.Errorf("%w: private address", errUnsafeEgressTarget), 403, "egress_denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			audit := &fakeReverseProxyAuditRecorder{}
			h := &ReverseProxyHandler{tenantID: "tenant_default", auditRecorder: audit, securityAuditOnlyFallback: true,
				resolveEgressTarget: func(context.Context, string, int, bool, []string) (resolvedEgressTarget, error) {
					return resolvedEgressTarget{}, tc.err
				},
				routes: []ReverseProxyRoute{{ID: "test", PathPrefix: "/proxy", TargetURL: "https://example.com", Status: "active"}}}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("POST", "http://gateway.local/proxy/test", strings.NewReader("{}")))
			if w.Code != tc.code {
				t.Fatalf("HTTP=%d want %d", w.Code, tc.code)
			}
			if len(audit.records) != 1 || audit.records[0].Status != tc.status {
				t.Fatalf("records=%+v", audit.records)
			}
		})
	}
}
