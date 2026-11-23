package handler

import (
	"bytes"
	"context"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An incomplete semantic stage is recorded and never blocks on its own; a
// deterministic block from a configured rule still blocks.
func TestIncompleteInputUsesFailurePolicyWithoutLosingBlock(t *testing.T) {
	for _, tc := range []struct {
		mode, action   string
		audit, blocked bool
	}{{"open", "allow", false, false}, {"close", "allow", false, false}, {"close", "allow", true, false}, {"open", "block", false, true}} {
		t.Run(tc.mode+tc.action+strings.ToLower(string(rune(65+boolInt(tc.audit)))), func(t *testing.T) {
			writer := &MockAuditWriter{}
			h := &ChatCompletionsHandler{cfg: &config.Config{GuardrailFailureMode: tc.mode, SecurityAuditOnly: tc.audit}, securityClient: &MockSecurityChecker{InputAction: tc.action, InputSemanticStatus: "incomplete", InputSemanticReason: "judge_timeout"}, auditWriter: writer}
			_, err := h.applyInputSecurity(context.Background(), newFailModeEnvelope(), &ChatCompletionRequest{Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}})
			if (err != nil) != tc.blocked {
				t.Fatalf("blocked=%v want=%v err=%v", err != nil, tc.blocked, err)
			}
			if len(writer.SecurityEventWrites) == 0 {
				t.Fatal("incomplete detection must be visible")
			}
		})
	}
}
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
func TestReverseProxyToolResultIsInspected(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
	engine, get := captureEngine(t, func(p map[string]interface{}) string { return `{"action":"allow","findings":[]}` })
	defer engine.Close()
	body := []byte(`{"model":"m","messages":[{"role":"tool","tool_call_id":"c","content":"indirect injection text"}]}`)
	req := httptest.NewRequest(http.MethodPost, "https://gw/v1/chat/completions", bytes.NewReader(body))
	_, err := newStructuredTestHandler(engine).checkRequestSecurityStructured(context.Background(), "test", req, body, "application/json", "api.openai.com", "/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range get() {
		if p["content_source"] == "tool_result" && strings.Contains(p["content"].(string), "indirect injection") {
			found = true
		}
	}
	if !found {
		t.Fatal("tool result skipped")
	}
}

func TestDetailedOutputIncompleteHTTP200(t *testing.T) {
	for _, tc := range []struct {
		mode, action   string
		audit, blocked bool
	}{{"open", "allow", false, false}, {"close", "allow", false, false}, {"close", "allow", true, false}, {"open", "block", false, true}} {
		t.Run(tc.mode+tc.action+string(rune(65+boolInt(tc.audit))), func(t *testing.T) {
			engine, _ := captureEngine(t, func(map[string]interface{}) string {
				return `{"action":"` + tc.action + `","findings":[],"semantic_status":"incomplete","semantic_reason":"judge_timeout"}`
			})
			defer engine.Close()
			cfg := &config.Config{SecurityEngineURL: engine.URL, GuardrailFailureMode: tc.mode, SecurityAuditOnly: tc.audit}
			h := &ChatCompletionsHandler{cfg: cfg, securityClient: NewRealSecurityChecker(cfg), auditWriter: &MockAuditWriter{}}
			body := mustMarshalChatResponse(t, ChatCompletionResponse{Choices: []Choice{{Message: ChoiceMessage{Role: "assistant", Content: "response"}}}})
			_, audit, err := h.applyOutputSecurity(context.Background(), newFailModeEnvelope(), nil, body)
			if (err != nil) != tc.blocked {
				t.Fatalf("err=%v blocked=%v", err, tc.blocked)
			}
			if audit == nil || audit.ResponseMetadata["semantic_status"] != "incomplete" {
				t.Fatalf("status lost: %+v", audit)
			}
		})
	}
}
func TestReverseIncompleteRuntimeRowIsNotAttack(t *testing.T) {
	row := buildReverseProxySecurityEventRowWithContext(reverseProxyAuditRecord{RequestID: "r", InputSemanticStatus: "incomplete", InputSemanticReason: "judge_timeout"}, "input", "audit", "", nil)
	if row.EventType != "security_check_failed" || row.Severity != "low" || row.ActionTaken != "audit" || row.MatchedSummary["counts_as_security_finding"] != false || row.MatchedSummary["semantic_reason"] != "judge_timeout" {
		t.Fatalf("bad runtime row: %+v", row)
	}
}
func TestReverseHTTP503IsFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		w.Write([]byte(`{"action":"allow","findings":[]}`))
	}))
	defer server.Close()
	_, err := newStructuredTestHandler(server).checkSecurityWithExtras(context.Background(), "r", "/check-input/", []byte("hello"), "hello", "text/plain", "api.openai.com", "/v1/chat/completions", "user", nil)
	if err == nil {
		t.Fatal("non-200 accepted")
	}
}

func TestDominantRiskSummaryDoesNotBlameLowEmail(t *testing.T) {
	email := SecurityFinding{Type: "pii", Category: "email", RuleName: "Email", Severity: "low", Confidence: 1}
	secret := SecurityFinding{Type: "secret", Category: "credential", RuleName: "Credential", Severity: "critical", Confidence: .95}
	semantic := SecurityFinding{Type: "semantic_attack", Category: "semantic", RuleName: "Semantic", Severity: "critical", Confidence: .99}
	for _, findings := range [][]SecurityFinding{{email, semantic, secret}, {secret, email, semantic}, {semantic, secret, email}} {
		summary := buildSecurityMatchedSummary(findings, "audit", "test")
		if summary["rule_name"] != "Credential" || summary["category"] != "credential" || dominantFindingCategory(findings, true) != "credential" {
			t.Fatalf("wrong dominant risk: %#v", summary)
		}
	}
}

func TestReverseIncompleteEffectiveAction(t *testing.T) {
	if got := reverseProxyEffectiveAuditAction("audit", false, false, "incomplete", nil); got != "audit" {
		t.Fatal(got)
	}
	if got := reverseProxyEffectiveAuditAction("allow", true, false, "incomplete", nil); got != "audit" {
		t.Fatal(got)
	}
	if got := reverseProxyEffectiveAuditAction("block", false, false, "incomplete", nil); got != "block" {
		t.Fatal(got)
	}
}

func TestReverseCompletedSourceNotOverwrittenBySkippedHistory(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
	engine, _ := captureEngine(t, func(p map[string]interface{}) string {
		if p["content_source"] == "user" {
			return `{"action":"allow","findings":[],"semantic_status":"completed"}`
		}
		return `{"action":"allow","findings":[],"semantic_status":"skipped","semantic_reason":"non_user_source"}`
	})
	defer engine.Close()
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"hello"},{"role":"assistant","content":"previous"}]}`)
	req := httptest.NewRequest("POST", "https://gw/v1/chat/completions", bytes.NewReader(body))
	decision, err := newStructuredTestHandler(engine).checkRequestSecurityStructured(context.Background(), "r", req, body, "application/json", "api.openai.com", "/v1/chat/completions")
	if err != nil || decision.SemanticStatus != "completed" {
		t.Fatalf("aggregate=%+v err=%v", decision, err)
	}
}

func TestReverseToolRiskTriageDoesNotUseUnrelatedUserText(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
	engine, _ := captureEngine(t, func(p map[string]interface{}) string {
		if p["content_source"] == "tool_result" {
			return `{"action":"block","findings":[{"type":"secret","severity":"critical","category":"credential"}]}`
		}
		return `{"action":"allow","findings":[]}`
	})
	defer engine.Close()
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"benign request"},{"role":"tool","tool_call_id":"c","content":"synthetic credential external send"}]}`)
	req := httptest.NewRequest("POST", "https://gw/v1/chat/completions", bytes.NewReader(body))
	decision, err := newStructuredTestHandler(engine).checkRequestSecurityStructured(context.Background(), "r", req, body, "application/json", "api.openai.com", "/v1/chat/completions")
	if err != nil || decision.ContentSource != "tool_result" || decision.VerifiedContent != "synthetic credential external send" {
		t.Fatalf("wrong triage evidence: %+v %v", decision, err)
	}
}

func TestReverseTruncatedOutputIsIncompletePostSendAudit(t *testing.T) {
	engine, _ := captureEngine(t, func(map[string]interface{}) string {
		return `{"action":"allow","findings":[],"semantic_status":"completed"}`
	})
	defer engine.Close()
	out, err := newStructuredTestHandler(engine).checkResponseSecurityStructuredCaptured(context.Background(), "r", []byte("data: [DONE]\n\n"), "text/event-stream", "api.openai.com", "/v1/chat/completions", true)
	if err != nil || out.SemanticStatus != "incomplete" || out.SemanticReason != "output_capture_truncated" || !out.Allowed {
		t.Fatalf("capture truncation invisible: %+v %v", out, err)
	}
	row := buildReverseProxySecurityEventRowWithContext(reverseProxyAuditRecord{OutputAlreadySent: true, OutputSemanticStatus: "incomplete", OutputSemanticReason: "output_capture_truncated"}, "output", "audit", "", nil)
	if row.MatchedSummary["enforcement_boundary"] != "post_send_audit" || row.ActionTaken != "audit" {
		t.Fatalf("post-send boundary missing: %+v", row)
	}
}
