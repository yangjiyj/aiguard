package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
)

func TestAssessEndpointToolIntentKeepsTaskContextWhenCurrentCallCannotResolveT13(t *testing.T) {
	taskID := "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	purpose := "inspect approved source and produce a summary"
	scope := agentintent.IntentTaskSourceScope{AllowedKinds: []string{"web"}}
	task := &agentintent.ResolvedIntentTask{
		ID: taskID, Purpose: purpose, PurposeSHA256: agentintent.DigestString(purpose),
		SourceScope: scope, SourceScopeSHA256: agentintent.DigestString(string(agentintent.CanonicalIntentTaskSourceScopeBytes(scope))),
		ScopeSHA256: strings.Repeat("b", 64), FacetScopeState: "unverifiable",
		History: []agentintent.IntentTaskHistoryStep{}, HistorySHA256: agentintent.IntentTaskHistoryHash([]agentintent.IntentTaskHistoryStep{}, false),
	}
	response := agentintent.AuthorizationResolveResponse{
		AuthorizationStatus: "unresolved", TaskStatus: "resolved", Task: task,
		Resolutions: []agentintent.AuthorizationResolution{},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request agentintent.AuthorizationResolveRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode resolver request: %v", err)
		}
		if request.IntentTaskID != taskID || len(request.Facets) != 0 {
			t.Errorf("expected unsupported call locator with no facets: %+v", request)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	gateway := &AgentEndpointGateway{controlURL: server.URL, secret: "test-internal", client: server.Client()}
	q := endpointDecideRequest{
		IntentTaskID: taskID, EndpointID: "endpoint", SessionID: "session", PromptID: "prompt", ToolUseID: "call",
		Agent:     &endpointDecideAgent{Product: "claude-code"},
		Tool:      &endpointDecideTool{Name: "opaque_plugin_tool", Type: "other"},
		Arguments: map[string]any{}, Context: &endpointDecideContext{},
	}
	report, _ := gateway.assessEndpointToolIntent(t.Context(), "endpoint-token", "endpoint", "tenant", "claude-code", q)
	if report == nil {
		t.Fatal("expected T16 report")
	}
	approvedTask, ok := report["approved_task"].(map[string]any)
	if !ok || approvedTask["state"] != "resolved" || approvedTask["facet_scope_state"] != "unverifiable" {
		t.Fatalf("non-authorizing task context was lost: %#v", report["approved_task"])
	}
	assessment, ok := report["assessment"].(agentguard.IntentFlowAssessment)
	if !ok || assessment.Task.State != "resolved" || assessment.Task.TaskScopeState != "unverifiable" ||
		assessment.Steps[0].AuthorizationState != "unresolved" {
		t.Fatalf("task context must not grant permission: %#v", report["assessment"])
	}
}

func TestAssessEndpointToolIntentRequiresEveryMCPAuthorizationFacet(t *testing.T) {
	tool := &endpointDecideTool{Name: "mcp__files__read_file", Type: "file", MCPServer: "files"}
	arguments := map[string]any{"filePath": "/workspace/notes.txt"}
	var received agentintent.AuthorizationResolveRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode resolver request: %v", err)
		}
		resolutions := make([]agentintent.AuthorizationResolution, 0, len(received.Facets))
		for _, facet := range received.Facets {
			allowed := facet.Action != "mcp_invoke"
			grantID := ""
			if allowed {
				grantID = "grant-" + facet.Action
			}
			key, err := agentintent.AuthorizationIdempotencyKey(received.Product, "endpoint", received.SessionID,
				received.ToolUseID, received.ArgumentsHash, received.ToolName, facet)
			if err != nil {
				t.Errorf("build facet key: %v", err)
			}
			resolutions = append(resolutions, agentintent.AuthorizationResolution{
				Facet: facet, IdempotencyKey: key, Allowed: allowed,
				PrincipalID: "principal-1", GrantID: grantID,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(agentintent.AuthorizationResolveResponse{
			AuthorizationStatus: "resolved", TaskStatus: "missing", Resolutions: resolutions,
		})
	}))
	defer server.Close()

	gateway := &AgentEndpointGateway{controlURL: server.URL, secret: "test-internal", client: server.Client()}
	q := endpointDecideRequest{
		EndpointID: "endpoint", SessionID: "session", PromptID: "prompt", ToolUseID: "call",
		Agent: &endpointDecideAgent{Product: "claude-code"}, Tool: tool,
		Arguments: arguments, Context: &endpointDecideContext{},
	}
	report, _ := gateway.assessEndpointToolIntent(t.Context(), "endpoint-token", "endpoint", "tenant", "claude-code", q)
	if report == nil {
		t.Fatal("expected T16 report")
	}
	if received.ToolName != tool.Name || received.ToolUseID != "call" || len(received.Facets) != 3 {
		t.Fatalf("expected exact tool-use tuple and all required T14 facets, got %#v", received)
	}
	assessment, ok := report["assessment"].(agentguard.IntentFlowAssessment)
	if !ok || len(assessment.Steps) != 1 {
		t.Fatalf("missing assessment step: %#v", report["assessment"])
	}
	step := assessment.Steps[0]
	if step.AuthorizationState != "denied" || assessment.Alignment != "deviation" || !assessment.ReviewRequired {
		t.Fatalf("denied required mcp_invoke facet must deny the whole step: step=%#v assessment=%#v", step, assessment)
	}
	if !containsIntentIssue(step.Issues, "required_authorization_facet_denied") {
		t.Fatalf("missing explicit required-facet denial issue: %#v", step.Issues)
	}
	bindings, ok := report["authorization_bindings"].([]map[string]any)
	if !ok {
		t.Fatalf("unexpected binding projection: %#v", report["authorization_bindings"])
	}
	decisions := make(map[string]string, len(bindings))
	for _, binding := range bindings {
		decisions[binding["action"].(string)] = binding["decision"].(string)
	}
	if decisions["mcp_invoke"] != "denied" || decisions["file_read"] != "allowed" || decisions["tool_execute"] != "allowed" {
		t.Fatalf("per-facet decisions were not preserved: %#v", decisions)
	}
}

func containsIntentIssue(issues []string, expected string) bool {
	for _, issue := range issues {
		if issue == expected {
			return true
		}
	}
	return false
}

func TestIntentTaskSourceClaimsBindPreviewDigest(t *testing.T) {
	preview := "server computes digest from transient preview bytes"
	claims := intentTaskSourceClaims([]endpointDecideFragment{{Source: "web_page", Hash: agentintent.DigestString(preview), Preview: preview}})
	if len(claims) != 1 || claims[0].PreviewHash != "sha256:"+agentintent.DigestString(preview) {
		t.Fatalf("preview digest was not bound into resolver claim: %#v", claims)
	}
	withoutPreview := intentTaskSourceClaims([]endpointDecideFragment{{Source: "web_page", Hash: agentintent.DigestString(preview)}})
	if len(withoutPreview) != 1 || withoutPreview[0].PreviewHash != "" {
		t.Fatalf("absent preview must not claim a byte digest: %#v", withoutPreview)
	}
}
