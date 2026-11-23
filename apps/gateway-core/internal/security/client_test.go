package security

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSecurityClientCheckInput verifies CheckInput behavior
func TestSecurityClientCheckInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type header")
		}
		if r.URL.Path != "/check-input/" {
			t.Errorf("Expected path /check-input/, got %s", r.URL.Path)
		}

		// Parse request
		var req CheckInputRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request: %v", err)
		}

		// Return mock response based on content
		resp := CheckInputResponse{
			RequestID: req.RequestID,
			Action:    "allow",
			LatencyMs: 10,
		}

		// Simulate PII detection for specific content
		if req.Content == "My SSN is 123-45-6789" {
			resp.Action = "mask"
			resp.MaskedContent = "My SSN is <MASKED>"
			resp.Findings = []SecurityFinding{
				{
					Type:               "pii",
					Category:           "ssn",
					Severity:           "high",
					MatchedTextPreview: "123-45-6789",
					RuleID:             "pii-ssn",
					Confidence:         0.95,
				},
			}
		}

		// Simulate secret detection
		if req.Content == "password=secret123" {
			resp.Action = "block"
			resp.Findings = []SecurityFinding{
				{
					Type:               "secret",
					Category:           "password",
					Severity:           "critical",
					MatchedTextPreview: "secret123",
					RuleID:             "secret-password",
					Confidence:         0.99,
				},
			}
		}

		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)

	tests := []struct {
		name           string
		content        string
		expectedAction string
		expectMasked   bool
		expectFindings bool
	}{
		{"safe_content", "Hello world", "allow", false, false},
		{"pii_content", "My SSN is 123-45-6789", "mask", true, true},
		{"secret_content", "password=secret123", "block", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			req := &CheckInputRequest{
				RequestID:   "req-123",
				Content:     tt.content,
				ContentType: "text",
			}

			resp, err := client.CheckInput(ctx, req)
			if err != nil {
				t.Fatalf("CheckInput failed: %v", err)
			}

			if resp.Action != tt.expectedAction {
				t.Errorf("Expected action='%s', got '%s'", tt.expectedAction, resp.Action)
			}

			if tt.expectMasked && resp.MaskedContent == "" {
				t.Error("Expected masked content")
			}

			if tt.expectFindings && len(resp.Findings) == 0 {
				t.Error("Expected findings")
			}
		})
	}
}

func TestSecurityClientFileBindingTokenRoundTrip(t *testing.T) {
	var bindBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/check-input/":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"request_id": "r1", "action": "allow", "findings": []map[string]interface{}{}, "latency_ms": 1,
				"file_bindings": []map[string]string{{"token": "one-time", "sha256": "sha1"}},
			})
		case "/scan-objects/bind":
			if err := json.NewDecoder(r.Body).Decode(&bindBody); err != nil {
				t.Fatalf("decode binding request: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "bound"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)
	checked, err := client.CheckInput(context.Background(), &CheckInputRequest{RequestID: "r1", Content: ""})
	if err != nil || len(checked.FileBindings) != 1 || checked.FileBindings[0].Token != "one-time" {
		t.Fatalf("file bindings = %+v, err=%v", checked.FileBindings, err)
	}
	if err := client.BindScannedFile(context.Background(), "t1", "u1", "openai", "one-time", "file-x"); err != nil {
		t.Fatalf("bind scanned file: %v", err)
	}
	if bindBody["tenant_id"] != "t1" || bindBody["subject"] != "u1" || bindBody["provider"] != "openai" || bindBody["file_id"] != "file-x" || bindBody["object"] != "file" {
		t.Fatalf("binding request = %#v", bindBody)
	}
}

// TestCheckSemanticOnlySendsFlag verifies CheckSemanticOnly sets semantic_only=true
// in the request body so the engine runs only the semantic block (async-bypass path).
func TestCheckSemanticOnlySendsFlag(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Write([]byte(`{"request_id":"r","findings":[],"action":"audit","latency_ms":1}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL)
	_, err := c.CheckSemanticOnly(context.Background(), &CheckInputRequest{RequestID: "r", Content: "x"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if gotBody["semantic_only"] != true {
		t.Fatalf("应带 semantic_only=true, got %#v", gotBody)
	}
	if gotBody["semantic_stage"] != "input" {
		t.Fatalf("异步输入语义必须显式带 semantic_stage=input, got %#v", gotBody)
	}
}

func TestCheckSemanticStageSendsStrictAgentStage(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Write([]byte(`{"request_id":"r","findings":[],"action":"audit","latency_ms":1}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL)

	_, err := c.CheckSemanticStage(context.Background(), &CheckInputRequest{
		RequestID: "r",
		Content:   "x",
	}, "agent")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if gotBody["semantic_only"] != true || gotBody["semantic_stage"] != "agent" {
		t.Fatalf("Agent 语义必须发送 semantic_only=true, semantic_stage=agent, got %#v", gotBody)
	}
}

func TestCheckSemanticStageRejectsUnknownStageBeforeNetwork(t *testing.T) {
	c := NewClient("http://127.0.0.1:1")
	_, err := c.CheckSemanticStage(
		context.Background(),
		&CheckInputRequest{RequestID: "r", Content: "x"},
		"output",
	)
	if err == nil {
		t.Fatal("未知 semantic stage 必须在客户端边界拒绝")
	}
}

// TestCheckInputCarriesSkipSemantic verifies the SkipSemantic field is serialized as
// skip_semantic=true on the wire when callers want the fast (non-semantic) layers only.
func TestCheckInputCarriesSkipSemantic(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Write([]byte(`{"request_id":"r","findings":[],"action":"allow","latency_ms":1}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL)
	_, _ = c.CheckInput(context.Background(), &CheckInputRequest{RequestID: "r", Content: "x", SkipSemantic: true})
	if gotBody["skip_semantic"] != true {
		t.Fatalf("应带 skip_semantic=true, got %#v", gotBody)
	}
}

// TestSecurityClientCheckOutput verifies CheckOutput behavior
func TestSecurityClientCheckOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/check-output/" {
			t.Errorf("Expected path /check-output/, got %s", r.URL.Path)
		}

		resp := CheckInputResponse{
			RequestID: "req-123",
			Action:    "allow",
			LatencyMs: 5,
		}

		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)

	ctx := context.Background()
	resp, err := client.CheckOutput(ctx, "req-123", "Output content", map[string]interface{}{
		"model": "gpt-4",
	})

	if err != nil {
		t.Fatalf("CheckOutput failed: %v", err)
	}

	if resp.Action != "allow" {
		t.Errorf("Expected action='allow', got '%s'", resp.Action)
	}
}

func TestSecurityClientSendsInternalSecretHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := (func() string {
			if legacy := r.Header.Get("X-NewAPI-Internal-Token"); legacy != "" {
				t.Errorf("legacy internal token header must be absent")
			}
			return r.Header.Get("X-JJDGuard-Internal-Token")
		})(); got != "secret-token" {
			t.Fatalf("internal token header = %q, want secret-token", got)
		}
		_ = json.NewEncoder(w).Encode(CheckInputResponse{
			RequestID: "req-123",
			Action:    "allow",
		})
	}))
	defer server.Close()

	client := NewClientWithSecret(server.URL, "secret-token")

	_, err := client.CheckInput(context.Background(), &CheckInputRequest{
		RequestID: "req-123",
		Content:   "hello",
	})
	if err != nil {
		t.Fatalf("CheckInput failed: %v", err)
	}
}

// TestSecurityClientHTTPError verifies error handling for HTTP errors
func TestSecurityClientHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal error"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL)

	ctx := context.Background()
	req := &CheckInputRequest{
		Content: "test",
	}

	_, err := client.CheckInput(ctx, req)
	if err == nil {
		t.Error("Expected error for HTTP 500")
	}
}

// TestSecurityClientNetworkError verifies error handling for network errors
func TestSecurityClientNetworkError(t *testing.T) {
	client := NewClient("http://invalid-host")

	ctx := context.Background()
	req := &CheckInputRequest{
		Content: "test",
	}

	_, err := client.CheckInput(ctx, req)
	if err == nil {
		t.Error("Expected network error")
	}
}

// TestShouldBlock verifies ShouldBlock method
func TestShouldBlock(t *testing.T) {
	tests := []struct {
		action   string
		expected bool
	}{
		{"block", true},
		{"mask", false},
		{"allow", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			resp := &CheckInputResponse{Action: tt.action}
			if resp.ShouldBlock() != tt.expected {
				t.Errorf("ShouldBlock() for action='%s' expected %v, got %v", tt.action, tt.expected, resp.ShouldBlock())
			}
		})
	}
}

// TestShouldMask verifies ShouldMask method
func TestShouldMask(t *testing.T) {
	tests := []struct {
		action   string
		expected bool
	}{
		{"mask", true},
		{"block", false},
		{"allow", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			resp := &CheckInputResponse{Action: tt.action}
			if resp.ShouldMask() != tt.expected {
				t.Errorf("ShouldMask() for action='%s' expected %v, got %v", tt.action, tt.expected, resp.ShouldMask())
			}
		})
	}
}

// TestHasFindings verifies HasFindings method
func TestHasFindings(t *testing.T) {
	tests := []struct {
		name     string
		findings []SecurityFinding
		expected bool
	}{
		{"no_findings", nil, false},
		{"empty_findings", []SecurityFinding{}, false},
		{"has_findings", []SecurityFinding{{Type: "pii"}}, true},
		{"multiple_findings", []SecurityFinding{{Type: "pii"}, {Type: "secret"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &CheckInputResponse{Findings: tt.findings}
			if resp.HasFindings() != tt.expected {
				t.Errorf("HasFindings() expected %v, got %v", tt.expected, resp.HasFindings())
			}
		})
	}
}

// TestGetCriticalFindings verifies GetCriticalFindings method
func TestGetCriticalFindings(t *testing.T) {
	resp := &CheckInputResponse{
		Findings: []SecurityFinding{
			{Type: "pii", Severity: "low"},
			{Type: "secret", Severity: "critical"},
			{Type: "pii", Severity: "high"},
		},
	}

	critical := resp.GetCriticalFindings()
	if len(critical) != 1 {
		t.Errorf("Expected 1 critical finding, got %d", len(critical))
	}
	if critical[0].Type != "secret" {
		t.Errorf("Expected critical finding type='secret'")
	}
}

// TestGetHighFindings verifies GetHighFindings method
func TestGetHighFindings(t *testing.T) {
	resp := &CheckInputResponse{
		Findings: []SecurityFinding{
			{Type: "pii", Severity: "low"},
			{Type: "secret", Severity: "high"},
			{Type: "pii", Severity: "medium"},
		},
	}

	high := resp.GetHighFindings()
	if len(high) != 1 {
		t.Errorf("Expected 1 high finding, got %d", len(high))
	}
	if high[0].Type != "secret" {
		t.Errorf("Expected high finding type='secret'")
	}
}

// TestSecurityFindingFields verifies SecurityFinding struct
func TestSecurityFindingFields(t *testing.T) {
	finding := SecurityFinding{
		Type:               "pii",
		Category:           "email",
		Severity:           "high",
		MatchedTextPreview: "test@example.com",
		RuleID:             "pii-email",
		Confidence:         0.85,
	}

	// Verify JSON serialization
	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("Failed to marshal SecurityFinding: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse finding: %v", err)
	}

	if parsed["type"] != "pii" {
		t.Errorf("Expected type='pii'")
	}
	if parsed["severity"] != "high" {
		t.Errorf("Expected severity='high'")
	}
}

// TestCheckInputRequestFields verifies CheckInputRequest struct
func TestCheckInputRequestFields(t *testing.T) {
	req := CheckInputRequest{
		RequestID:   "req-123",
		Content:     "Hello",
		ContentType: "text",
		ProjectID:   "proj-456",
		Model:       "gpt-4",
		AgentType:   "chatbot",
		ClientType:  "api",
		Context: map[string]interface{}{
			"tenant_id": "tenant-789",
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal CheckInputRequest: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse request: %v", err)
	}

	if parsed["request_id"] != "req-123" {
		t.Errorf("Expected request_id='req-123'")
	}
	if parsed["content"] != "Hello" {
		t.Errorf("Expected content='Hello'")
	}
	if parsed["project_id"] != "proj-456" {
		t.Errorf("Expected project_id='proj-456'")
	}
}

// TestCheckInputResponseFields verifies CheckInputResponse struct
func TestCheckInputResponseFields(t *testing.T) {
	resp := CheckInputResponse{
		RequestID: "req-123",
		Findings: []SecurityFinding{
			{Type: "pii", Severity: "high"},
		},
		Action:        "mask",
		MaskedContent: "Hello <MASKED>",
		LatencyMs:     15,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal CheckInputResponse: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if parsed["request_id"] != "req-123" {
		t.Errorf("Expected request_id='req-123'")
	}
	if parsed["action"] != "mask" {
		t.Errorf("Expected action='mask'")
	}
	if parsed["masked_content"] != "Hello <MASKED>" {
		t.Errorf("Expected masked_content='Hello <MASKED>'")
	}
}

// TestSecurityClientTimeout verifies client timeout configuration.
//
// 超时不再挂在 http.Client 上（那是含读体的全局墙钟，无法按请求区分预算），
// 而由 check() 按 payload 体量施加 per-request context deadline。
// 这里验证「一定存在有限的超时预算」这一原意。
func TestSecurityClientTimeout(t *testing.T) {
	client := NewClient("http://localhost")
	if client.httpClient.Timeout != 0 {
		t.Errorf("超时应由 per-request context 施加，http.Client.Timeout 须为 0, got %v", client.httpClient.Timeout)
	}
	budget := client.timeoutForPayload(1024)
	if budget <= 0 {
		t.Errorf("必须存在有限的超时预算，否则会无限等待: got %v", budget)
	}
	if budget > defaultSecurityMaxTimeout {
		t.Errorf("预算不得超过上限 %v: got %v", defaultSecurityMaxTimeout, budget)
	}
}

// TestNewClient verifies client creation
func TestNewClient(t *testing.T) {
	baseURL := "http://security-engine:8000"
	client := NewClient(baseURL)

	if client.baseURL != baseURL {
		t.Errorf("Expected baseURL='%s', got '%s'", baseURL, client.baseURL)
	}
	if client.httpClient == nil {
		t.Error("Expected httpClient to be initialized")
	}
}

// TestSecurityFinding_DecodesEnrichmentFields verifies the engine's enrichment
// fields (rule_name/rule_type/action/matched_location/redacted_evidence) survive
// JSON decode into SecurityFinding. These drive the closed-loop UI and the
// evidence red-line (redacted_evidence is the explicit safe field).
func TestSecurityFinding_DecodesEnrichmentFields(t *testing.T) {
	body := []byte(`{
		"type": "custom",
		"category": "medical_id",
		"severity": "high",
		"matched_text_preview": "BA****34 (sha256:deadbeef)",
		"rule_id": "rule_bah_001",
		"confidence": 0.9,
		"rule_name": "病案号正则",
		"rule_type": "regex",
		"action": "block",
		"matched_location": "content[10:18]",
		"redacted_evidence": "BA****34 (sha256:deadbeef)"
	}`)
	var f SecurityFinding
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f.RuleName != "病案号正则" {
		t.Errorf("RuleName: got %q want 病案号正则", f.RuleName)
	}
	if f.RuleType != "regex" {
		t.Errorf("RuleType: got %q want regex", f.RuleType)
	}
	if f.Action != "block" {
		t.Errorf("Action: got %q want block", f.Action)
	}
	if f.MatchedLocation != "content[10:18]" {
		t.Errorf("MatchedLocation: got %q want content[10:18]", f.MatchedLocation)
	}
	if f.RedactedEvidence != "BA****34 (sha256:deadbeef)" {
		t.Errorf("RedactedEvidence: got %q", f.RedactedEvidence)
	}
}

func TestSecurityFindingJSONPreservesZeroIndexes(t *testing.T) {
	body := []byte(`{"type":"file","category":"file_content_uninspected","message_index":0,"message_role":"user","attachment_index":0}`)
	var finding SecurityFinding
	if err := json.Unmarshal(body, &finding); err != nil {
		t.Fatalf("unmarshal finding: %v", err)
	}
	if finding.MessageIndex == nil || *finding.MessageIndex != 0 {
		t.Fatalf("message_index=%v, want pointer to 0", finding.MessageIndex)
	}
	if finding.AttachmentIndex == nil || *finding.AttachmentIndex != 0 {
		t.Fatalf("attachment_index=%v, want pointer to 0", finding.AttachmentIndex)
	}
	if finding.MessageRole != "user" {
		t.Fatalf("message_role=%q, want user", finding.MessageRole)
	}
}
