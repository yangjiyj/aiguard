package catalog

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPModelProberNativeMessagesBudgetAndEvidence(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" || r.Header.Get("x-api-key") != "probe-secret" || r.Header.Get("Authorization") != "" || r.Header.Get("Anthropic-Version") != "2023-06-01" {
			t.Errorf("native Messages path/auth mismatch: %s", r.URL.Path)
		}
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["max_tokens"] != float64(128) || payload["stream"] != false {
			t.Errorf("probe budget/stream = %#v", payload)
		}
		time.Sleep(5 * time.Millisecond)
		_, _ = io.WriteString(w, `{"id":"msg_test","type":"message","content":[{"type":"text","text":"OK"}]}`)
	}))
	defer server.Close()
	request := validProbeRequest(server.URL, "x-api-key")
	request.Protocol = "messages"
	request.MaxOutputTokens = 128
	request.Timeout = time.Second
	result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), request)
	if !result.OK || !result.PayloadValidated || result.HTTPStatus != http.StatusOK || result.LatencyMS < 5 {
		t.Fatalf("missing real probe evidence: %+v", result)
	}
}

func TestHTTPModelProberEvidenceDoesNotPromoteHTTP200WithoutPayload(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `<html>login failed probe-secret</html>`)
	}))
	defer server.Close()
	result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), validProbeRequest(server.URL, "bearer"))
	if result.OK || result.PayloadValidated || result.HTTPStatus != 200 || strings.Contains(result.Message, "probe-secret") {
		t.Fatalf("unverified or leaked probe response: %+v", result)
	}
}

func TestHTTPModelProberRejectsEmptyAndIncompleteNativePayloads(t *testing.T) {
	for _, item := range []struct{ protocol, body string }{
		{"responses", `{"id":"resp_test","status":"completed","output":[]}`},
		{"responses", `{"id":"resp_test"}`},
		{"responses", `{"id":"resp_test","status":"incomplete","output":[{"type":"message","content":[{"type":"output_text","text":"OK"}]}]}`},
		{"messages", `{"id":"msg_test","type":"message","content":[{"type":"text","text":" "}]}`},
		{"messages", `{"id":"msg_test","type":"message","content":[{"type":"thinking","thinking":"hidden"}]}`},
	} {
		t.Run(item.protocol+item.body, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, item.body) }))
			defer server.Close()
			request := validProbeRequest(server.URL, "bearer")
			request.Protocol = item.protocol
			result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), request)
			if result.OK || result.PayloadValidated || result.HTTPStatus != 200 {
				t.Fatalf("empty/incomplete payload promoted to usable: %+v", result)
			}
		})
	}
}

func TestHTTPModelProberClassifiesResponseBodyDeadline(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		time.Sleep(120 * time.Millisecond)
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"OK"}}]}`)
	}))
	defer server.Close()
	request := validProbeRequest(server.URL, "bearer")
	request.Timeout = 30 * time.Millisecond
	result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), request)
	if result.OK || result.PayloadValidated || result.HTTPStatus != 200 || result.ErrorKind != ModelProbeErrorTimeout {
		t.Fatalf("body deadline evidence lost: %+v", result)
	}
}

func TestHTTPModelProberBudgetRejectsBeforeNetworkAndHonorsTimeout(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		time.Sleep(150 * time.Millisecond)
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"OK"}}]}`)
	}))
	defer server.Close()
	prober := newHTTPModelProberWithClient(server.Client())
	for _, invalid := range []ModelProbeRequest{
		{BaseURL: server.URL, APIKey: "probe-secret", DeploymentName: "model", AuthMode: "bearer", MaxOutputTokens: 1025},
		{BaseURL: server.URL, APIKey: "probe-secret", DeploymentName: "model", AuthMode: "bearer", MaxOutputTokens: -1},
		{BaseURL: server.URL, APIKey: "probe-secret", DeploymentName: "model", AuthMode: "bearer", Timeout: 121 * time.Second},
	} {
		result := prober.Probe(context.Background(), invalid)
		if result.OK || result.ErrorKind != ModelProbeErrorInvalidRequest || result.HTTPStatus != 0 {
			t.Fatalf("invalid budget accepted: %+v", result)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid probe budget sent a request")
	}
	request := validProbeRequest(server.URL, "bearer")
	request.Timeout = 20 * time.Millisecond
	result := prober.Probe(context.Background(), request)
	if result.OK || result.PayloadValidated || result.ErrorKind != ModelProbeErrorTimeout || result.LatencyMS < 15 || result.LatencyMS > 120 {
		t.Fatalf("configured probe deadline not honored: %+v", result)
	}
}

func TestHTTPModelProberClassifiesResponses(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		wantOK    bool
		wantError string
	}{
		{name: "200 valid chat completion", status: http.StatusOK, body: `{"choices":[{"message":{"content":"OK"}}]}`, wantOK: true},
		{name: "204", status: http.StatusNoContent, wantError: ModelProbeErrorUpstream},
		{name: "200 empty body", status: http.StatusOK, wantError: ModelProbeErrorUpstream},
		{name: "200 html", status: http.StatusOK, body: `<html>login</html>`, wantError: ModelProbeErrorUpstream},
		{name: "200 error envelope", status: http.StatusOK, body: `{"error":{"code":"DeploymentNotFound"}}`, wantError: ModelProbeErrorUpstream},
		{name: "200 malformed json", status: http.StatusOK, body: `{"choices":`, wantError: ModelProbeErrorUpstream},
		{name: "200 empty choices", status: http.StatusOK, body: `{"choices":[]}`, wantError: ModelProbeErrorUpstream},
		{name: "200 missing message", status: http.StatusOK, body: `{"choices":[{}]}`, wantError: ModelProbeErrorUpstream},
		{name: "200 empty content", status: http.StatusOK, body: `{"choices":[{"message":{"content":"  "}}]}`, wantError: ModelProbeErrorUpstream},
		{name: "200 oversized body", status: http.StatusOK, body: `{"choices":[{"message":{"content":"` + strings.Repeat("x", modelProbeResponseBodyLimit) + `"}}]}`, wantError: ModelProbeErrorUpstream},
		{name: "401", status: http.StatusUnauthorized, wantError: ModelProbeErrorUnauthorized},
		{name: "403", status: http.StatusForbidden, wantError: ModelProbeErrorUnauthorized},
		{name: "Azure deployment not found", status: http.StatusNotFound, body: "{\"error\":{\"code\":\"DeploymentNotFound\",\"message\":\"sensitive upstream detail\"}}", wantError: ModelProbeErrorNotDeployed},
		{name: "ordinary 404", status: http.StatusNotFound, body: "{\"error\":\"not found\"}", wantError: ModelProbeErrorUpstream},
		{name: "429", status: http.StatusTooManyRequests, wantError: ModelProbeErrorRateLimited},
		{name: "500", status: http.StatusInternalServerError, wantError: ModelProbeErrorUpstream},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer server.Close()

			result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), validProbeRequest(server.URL, "bearer"))
			if result.OK != tt.wantOK {
				t.Fatalf("OK = %v, want %v; result=%+v", result.OK, tt.wantOK, result)
			}
			if result.ErrorKind != tt.wantError {
				t.Fatalf("ErrorKind = %q, want %q; result=%+v", result.ErrorKind, tt.wantError, result)
			}
			for _, secret := range []string{"sensitive upstream detail", "probe-secret", "deployment-admin-entered"} {
				if strings.Contains(result.Message, secret) {
					t.Fatalf("Message leaked %q: %q", secret, result.Message)
				}
			}
		})
	}
}

func TestHTTPModelProberUsesDeploymentAndRuntimeAuth(t *testing.T) {
	tests := []struct {
		name            string
		authMode        string
		wantHeader      string
		wantHeaderValue string
		absentHeader    string
	}{
		{name: "bearer", authMode: "bearer", wantHeader: "Authorization", wantHeaderValue: "Bearer probe-secret", absentHeader: "api-key"},
		{name: "legacy api_key uses runtime bearer", authMode: "api_key", wantHeader: "Authorization", wantHeaderValue: "Bearer probe-secret", absentHeader: "api-key"},
		{name: "api-key", authMode: "api-key", wantHeader: "api-key", wantHeaderValue: "probe-secret", absentHeader: "Authorization"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method = %q, want POST", r.Method)
				}
				if r.URL.Path != "/v1/chat/completions" {
					t.Errorf("path = %q, want /v1/chat/completions", r.URL.Path)
				}
				if got := r.Header.Get(tt.wantHeader); got != tt.wantHeaderValue {
					t.Errorf("%s = %q, want %q", tt.wantHeader, got, tt.wantHeaderValue)
				}
				if got := r.Header.Get(tt.absentHeader); got != "" {
					t.Errorf("unexpected %s = %q", tt.absentHeader, got)
				}

				var body map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatalf("decode body: %v", err)
				}
				if body["model"] != "deployment-admin-entered" {
					t.Errorf("model = %#v", body["model"])
				}
				messages, ok := body["messages"].([]interface{})
				if !ok || len(messages) != 1 {
					t.Fatalf("messages = %#v", body["messages"])
				}
				message, ok := messages[0].(map[string]interface{})
				if !ok || message["role"] != "user" || message["content"] != "Reply OK." {
					t.Errorf("message = %#v", messages[0])
				}
				if body["max_completion_tokens"] != float64(1024) {
					t.Errorf("max_completion_tokens = %#v", body["max_completion_tokens"])
				}
				if body["stream"] != false {
					t.Errorf("stream = %#v, want false", body["stream"])
				}

				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "{\"choices\":[{\"message\":{\"content\":\"sensitive model output\"}}]}")
			}))
			defer server.Close()

			result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), validProbeRequest(server.URL+"/v1", tt.authMode))
			if !result.OK || result.ErrorKind != "" {
				t.Fatalf("result = %+v, want success", result)
			}
			for _, secret := range []string{"sensitive model output", "probe-secret", "deployment-admin-entered"} {
				if strings.Contains(result.Message, secret) {
					t.Fatalf("Message leaked %q: %q", secret, result.Message)
				}
			}
		})
	}
}

func TestHTTPModelProberUsesExactBoundedReasoningCompatibleBody(t *testing.T) {
	bodyCh := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			bodyCh <- "read error: " + err.Error()
		} else {
			bodyCh <- string(body)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"OK"}}]}`)
	}))
	defer server.Close()

	result := newHTTPModelProberWithClient(server.Client()).Probe(
		context.Background(),
		validProbeRequest(server.URL, "bearer"),
	)
	if !result.OK {
		t.Fatalf("result = %+v, want success", result)
	}
	want := `{"max_completion_tokens":1024,"messages":[{"content":"Reply OK.","role":"user"}],"model":"deployment-admin-entered","stream":false}`
	if got := <-bodyCh; got != want {
		t.Fatalf("request body = %s, want %s", got, want)
	}
}

func TestHTTPModelProberSupportsExplicitResponsesProtocol(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Fatalf("path = %q, want /v1/responses", r.URL.Path)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body["model"] != "deployment-admin-entered" || body["input"] != "Reply OK." || body["stream"] != false {
			t.Fatalf("unexpected Responses probe body: %#v", body)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"id":"resp_probe","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"OK"}]}]}`)
	}))
	defer server.Close()

	result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), ModelProbeRequest{
		BaseURL: server.URL + "/v1", APIKey: "probe-secret", AuthMode: "bearer",
		DeploymentName: "deployment-admin-entered", Protocol: "responses",
	})
	if !result.OK || result.ErrorKind != "" {
		t.Fatalf("result = %+v, want Responses verification success", result)
	}
}

func TestHTTPModelProberSupportsNativeMessagesProtocol(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Fatalf("path = %q, want /v1/messages", r.URL.Path)
		}
		if got := r.Header.Get("Anthropic-Version"); got != "2023-06-01" {
			t.Fatalf("Anthropic-Version = %q", got)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["model"] != "claude-opus-4-8" || body["max_tokens"] != float64(modelProbeMessagesMaxTokens) || body["stream"] != false {
			t.Fatalf("unexpected Messages probe body: %#v", body)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"id":"msg_probe","type":"message","content":[{"type":"text","text":"OK"}]}`)
	}))
	defer server.Close()

	result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), ModelProbeRequest{
		BaseURL: server.URL + "/v1", APIKey: "probe-secret", AuthMode: "bearer",
		DeploymentName: "claude-opus-4-8", Protocol: "messages",
	})
	if !result.OK || result.ErrorKind != "" {
		t.Fatalf("result = %+v, want native Messages verification success", result)
	}
}

func TestHTTPModelProberAcceptsLargeValidResponsesEnvelope(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		payload := map[string]interface{}{
			"id":       "resp_probe_large",
			"status":   "completed",
			"output":   []map[string]interface{}{{"type": "message", "content": []map[string]string{{"type": "output_text", "text": "OK"}}}},
			"metadata": map[string]string{"provider_envelope": strings.Repeat("x", 24<<10)},
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer server.Close()

	result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), ModelProbeRequest{
		BaseURL: server.URL + "/v1", APIKey: "probe-secret", AuthMode: "bearer",
		DeploymentName: "deployment-admin-entered", Protocol: "responses",
	})
	if !result.OK || result.ErrorKind != "" {
		t.Fatalf("result = %+v, want large Responses envelope to verify", result)
	}
}

func TestJoinModelProbePathNormalizesAzureBaseURLForms(t *testing.T) {
	const (
		host       = "https://resource.openai.azure.com"
		deployment = "gpt-5.6-sol"
		chatWant   = host + "/openai/deployments/" + deployment + "/chat/completions?api-version=2024-10-21"
		respWant   = host + "/openai/v1/responses"
	)

	tests := []struct {
		name string
		base string
	}{
		{name: "bare host", base: host},
		{name: "openai prefix", base: host + "/openai"},
		{name: "openai v1 prefix", base: host + "/openai/v1"},
		{name: "trailing slash", base: host + "/openai/v1/"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/chat", func(t *testing.T) {
			if got := joinModelProbePath(tt.base, deployment, "chat_completions"); got != chatWant {
				t.Fatalf("got %q, want %q", got, chatWant)
			}
		})
		t.Run(tt.name+"/responses", func(t *testing.T) {
			if got := joinModelProbePath(tt.base, deployment, "responses"); got != respWant {
				t.Fatalf("got %q, want %q", got, respWant)
			}
		})
	}
}

func TestHTTPModelProberTimeoutAndCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(200 * time.Millisecond):
		}
	}))
	defer server.Close()

	t.Run("deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		result := newHTTPModelProberWithClient(server.Client()).Probe(ctx, validProbeRequest(server.URL, "bearer"))
		if result.OK || result.ErrorKind != ModelProbeErrorTimeout {
			t.Fatalf("result = %+v, want timeout", result)
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result := newHTTPModelProberWithClient(server.Client()).Probe(ctx, validProbeRequest(server.URL, "bearer"))
		if result.OK || result.ErrorKind != ModelProbeErrorCancelled {
			t.Fatalf("result = %+v, want cancelled", result)
		}
	})
}

func TestHTTPModelProberDoesNotFollowRedirects(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/stolen", http.StatusFound)
	}))
	defer origin.Close()

	result := newHTTPModelProberWithClient(origin.Client()).Probe(context.Background(), validProbeRequest(origin.URL, "bearer"))
	if result.OK || result.ErrorKind != ModelProbeErrorUpstream {
		t.Fatalf("result = %+v, want redirect failure", result)
	}
	if got := targetCalls.Load(); got != 0 {
		t.Fatalf("redirect target received %d requests, want 0", got)
	}
}

func TestHTTPModelProberClassifiesUnauthorizedBeforeReadingBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		select {
		case <-r.Context().Done():
		case <-time.After(400 * time.Millisecond):
		}
	}))
	defer server.Close()

	startedAt := time.Now()
	result := newHTTPModelProberWithClient(server.Client()).Probe(
		context.Background(),
		validProbeRequest(server.URL, "bearer"),
	)
	elapsed := time.Since(startedAt)
	if result.OK || result.ErrorKind != ModelProbeErrorUnauthorized {
		t.Fatalf("result = %+v, want unauthorized", result)
	}
	if elapsed >= 200*time.Millisecond {
		t.Fatalf("probe waited for response body: elapsed=%s", elapsed)
	}
}

func TestHTTPModelProberRejectsUnsafeOrUnsupportedRequestsWithoutNetwork(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("{\"ok\":true}")),
			Header:     make(http.Header),
		}, nil
	})}
	prober := newHTTPModelProberWithClient(client)

	tests := []struct {
		name string
		req  ModelProbeRequest
	}{
		{name: "userinfo", req: validProbeRequest("https://user:secret@example.com", "bearer")},
		{name: "cleartext HTTP", req: validProbeRequest("http://example.com", "bearer")},
		{name: "Azure metadata host", req: validProbeRequest("http://metadata.azure.internal", "bearer")},
		{name: "Azure metadata normalized bypass", req: validProbeRequest("http://MeTaDaTa.Azure.Internal.", "bearer")},
		{name: "Azure metadata IP", req: validProbeRequest("http://169.254.169.254", "bearer")},
		{name: "BaseURL query", req: validProbeRequest("https://example.com/path?x=y", "bearer")},
		{name: "BaseURL force query", req: validProbeRequest("https://example.com?", "bearer")},
		{name: "leading BaseURL whitespace", req: validProbeRequest(" https://example.com", "bearer")},
		{name: "trailing BaseURL whitespace", req: validProbeRequest("https://example.com ", "bearer")},
		{name: "surrounding auth whitespace", req: validProbeRequest("https://example.com", " bearer ")},
		{name: "legacy auth trailing newline", req: validProbeRequest("https://example.com", "api_key\n")},
		{name: "unsupported auth mode", req: validProbeRequest("https://example.com", "basic")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := calls.Load()
			result := prober.Probe(context.Background(), tt.req)
			if result.OK || result.ErrorKind != ModelProbeErrorInvalidRequest {
				t.Fatalf("result = %+v, want invalid_request", result)
			}
			if after := calls.Load(); after != before {
				t.Fatalf("network calls changed from %d to %d", before, after)
			}
		})
	}
}

func TestHTTPModelProberProductionConstructorRejectsLoopbackWithoutNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := NewHTTPModelProber().Probe(context.Background(), validProbeRequest(server.URL, "bearer"))
	if result.OK || result.ErrorKind != ModelProbeErrorInvalidRequest {
		t.Fatalf("result = %+v, want invalid_request", result)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("loopback target received %d requests, want 0", got)
	}
}

func TestHTTPModelProberAuthorizationRawUsesCompleteURLAndRawHeader(t *testing.T) {
	const credential = "raw-probe-key"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/private/chat/V2?tenant=demo" {
			t.Errorf("request URI = %q", r.URL.RequestURI())
		}
		if got := r.Header.Get("Authorization"); got != credential {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("api-key"); got != "" {
			t.Errorf("api-key = %q", got)
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"OK"}}]}`)
	}))
	defer server.Close()

	result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), ModelProbeRequest{
		BaseURL: server.URL + "/private/chat/V2?tenant=demo", APIKey: credential,
		AuthMode: "authorization_raw", DeploymentName: "vendor-model", Protocol: "chat_completions",
	})
	if !result.OK {
		t.Fatalf("Probe() = %+v", result)
	}
}

func TestAuthorizationRawProbeURLValidation(t *testing.T) {
	for _, rawURL := range []string{
		"ftp://upstream.example.test/chat",
		"http://user:pass@upstream.example.test/chat",
		"http:///chat",
		"http://upstream.example.test/chat#fragment",
		"http://upstream.example.test:bad/chat",
	} {
		t.Run(rawURL, func(t *testing.T) {
			_, _, _, err := validateModelProbeRequest(ModelProbeRequest{
				BaseURL: rawURL, APIKey: "secret", AuthMode: "authorization_raw",
				DeploymentName: "model", Protocol: "chat_completions",
			})
			if err == nil {
				t.Fatalf("validateModelProbeRequest(%q) succeeded", rawURL)
			}
		})
	}
}

func validProbeRequest(baseURL, authMode string) ModelProbeRequest {
	return ModelProbeRequest{
		BaseURL:        baseURL,
		APIKey:         "probe-secret",
		AuthMode:       authMode,
		DeploymentName: "deployment-admin-entered",
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
