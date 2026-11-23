package handler

import (
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/principal"
)

func TestBuildChatPartialEnvelopePreservesAuthAndCorrelationFields(t *testing.T) {
	authInfo := &auth.AuthInfo{
		UserAgent:            "client/1",
		AgentIdentityHeaders: `{"declared_type":"main"}`,
		TenantID:             "tenant-1",
		ProjectID:            "project-1",
		UserID:               "user-1",
		KeyID:                "key-1",
		AgentType:            "agent",
		SessionID:            "session-1",
		WorkspaceID:          "workspace-1",
		TraceID:              "trace-1",
		LSEEvalRunID:         "eval-1",
		LSETaskID:            "task-1",
		LSESampleID:          "sample-1",
		LSETargetID:          "target-1",
		Principal: &principal.Context{
			SchemaVersion: 1, TenantID: "tenant-1", ProjectID: "project-1", ApplicationID: "project-1",
			KeyID: "key-1", KeyOwnerUserID: "user-1", IdentitySource: principal.SourceAPIKey, TrustLevel: principal.TrustKeyBound,
		},
	}

	envelope := buildChatPartialEnvelope("req-1", authInfo, "gpt-4", "chat")
	if envelope.UserAgent != authInfo.UserAgent || envelope.AgentIdentityHeaders != authInfo.AgentIdentityHeaders {
		t.Fatal("identity observations lost")
	}

	if envelope.RequestID != "req-1" || envelope.EndpointType != "chat" || envelope.Model != "gpt-4" {
		t.Fatalf("partial envelope lost request fields: %+v", envelope)
	}
	if envelope.TenantID != "tenant-1" || envelope.ProjectID != "project-1" || envelope.UserID != "user-1" || envelope.ClientID != "key-1" {
		t.Fatalf("partial envelope lost identity fields: %+v", envelope)
	}
	if envelope.SessionID != "session-1" || envelope.WorkspaceID != "workspace-1" || envelope.TraceID != "trace-1" {
		t.Fatalf("partial envelope lost session/correlation fields: %+v", envelope)
	}
	if envelope.LSEEvalRunID != "eval-1" || envelope.LSETaskID != "task-1" || envelope.LSESampleID != "sample-1" || envelope.LSETargetID != "target-1" {
		t.Fatalf("partial envelope lost LSE fields: %+v", envelope)
	}
}

func TestTrustedPrincipalIgnoresSpoofedActorHeaders(t *testing.T) {
	base, err := principal.Normalize(principal.Context{
		TenantID: "tenant-1", ProjectID: "project-1", ApplicationID: "project-1",
		KeyID: "key-1", KeyOwnerUserID: "owner-1",
		IdentitySource: principal.SourceAPIKey, TrustLevel: principal.TrustKeyBound,
	})
	if err != nil {
		t.Fatal(err)
	}
	authInfo := &auth.AuthInfo{
		TenantID: "tenant-1", ProjectID: "project-1", UserID: "owner-1", KeyID: "key-1", Principal: &base,
	}
	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	req.Header.Set("X-User-ID", "attacker")
	req.Header.Set("X-Department-ID", "dept-attacker")
	envelope := buildChatPartialEnvelope("req-1", authInfo, "gpt-4", "chat")
	if envelope.Principal == nil {
		t.Fatal("trusted principal missing")
	}
	if envelope.Principal.ActorUserID != "" || envelope.Principal.KeyOwnerUserID != "owner-1" {
		t.Fatalf("spoofed actor or owner promotion: %+v", envelope.Principal)
	}
	if envelope.Principal.Protocol != "chat" || envelope.Principal.EntryPoint != "gateway_api" {
		t.Fatalf("endpoint identity missing: %+v", envelope.Principal)
	}
	check := buildInputCheckRequest(req.Context(), envelope, "hello", 0, "user", "user")
	if check.Principal == nil || check.Principal.ActorUserID != "" || check.Principal.KeyOwnerUserID != "owner-1" {
		t.Fatalf("security request did not preserve trusted principal: %+v", check.Principal)
	}
}

func TestBuildChatRuntimeEnvelopePopulatesRoutingContext(t *testing.T) {
	authInfo := &auth.AuthInfo{
		TenantID:     "tenant-1",
		ProjectID:    "project-1",
		UserID:       "user-1",
		KeyID:        "key-1",
		KeyPrefix:    "key-prefix-test",
		AgentType:    "agent",
		SessionID:    "session-1",
		WorkspaceID:  "workspace-1",
		TraceID:      "trace-1",
		LSEEvalRunID: "eval-1",
		LSETaskID:    "task-1",
		LSESampleID:  "sample-1",
		LSETargetID:  "target-1",
		Principal: &principal.Context{
			SchemaVersion: 1, TenantID: "tenant-1", ProjectID: "project-1", ApplicationID: "project-1",
			KeyID: "key-1", KeyOwnerUserID: "user-1", IdentitySource: principal.SourceAPIKey, TrustLevel: principal.TrustKeyBound,
		},
	}
	req := &ChatCompletionRequest{
		Model: "gpt-4",
		Messages: []Message{
			{Role: "system", Content: jsonQuote("You are concise.")},
			{Role: "user", Content: jsonQuote("Please summarize the incident response evidence.")},
			{Role: "assistant", Content: jsonQuote("")},
		},
	}
	modelRecord := &modelrouter.ModelRecord{
		ID:           "model-1",
		ProviderID:   "provider-1",
		ProviderType: "openai",
	}

	envelope := buildChatRuntimeEnvelope(chatRuntimeContextInput{
		requestID:   "req-1",
		authInfo:    authInfo,
		request:     req,
		modelRecord: modelRecord,
		teamID:      "team-1",
		routeHint:   "low-latency",
	})

	if envelope.RequestID != "req-1" || envelope.EndpointType != "chat" || envelope.Model != "gpt-4" || envelope.ModelID != "model-1" {
		t.Fatalf("runtime envelope lost request/model fields: %+v", envelope)
	}
	if envelope.TenantID != "tenant-1" || envelope.TeamID != "team-1" || envelope.ProjectID != "project-1" || envelope.UserID != "user-1" {
		t.Fatalf("runtime envelope lost identity fields: %+v", envelope)
	}
	if envelope.ClientID != "key-1" || envelope.KeyPrefix != "key-prefix-test" || envelope.AgentType != "agent" {
		t.Fatalf("runtime envelope lost client fields: %+v", envelope)
	}
	if envelope.ProviderID != "provider-1" || envelope.Provider != "openai" {
		t.Fatalf("runtime envelope lost provider fields: %+v", envelope)
	}
	if envelope.Principal == nil || envelope.Principal.ApplicationDepartmentID != "team-1" || envelope.Principal.ActorUserID != "" {
		t.Fatalf("runtime principal did not preserve key-owner/application boundary: %+v", envelope.Principal)
	}
	if envelope.RouteHint != "low-latency" {
		t.Fatalf("expected route hint low-latency, got %q", envelope.RouteHint)
	}
	expectedTokens := len("You are concise.")/4 + len("Please summarize the incident response evidence.")/4
	if envelope.PromptTokens != expectedTokens {
		t.Fatalf("expected prompt tokens %d, got %d", expectedTokens, envelope.PromptTokens)
	}
	if len(envelope.ContentSegments) != 2 {
		t.Fatalf("expected two non-empty content segments, got %+v", envelope.ContentSegments)
	}
	if envelope.ContentSegments[0].Type != "text" || envelope.ContentSegments[0].Content != "You are concise." {
		t.Fatalf("unexpected first content segment: %+v", envelope.ContentSegments[0])
	}
	if envelope.LSEEvalRunID != "eval-1" || envelope.LSETaskID != "task-1" || envelope.LSESampleID != "sample-1" || envelope.LSETargetID != "target-1" {
		t.Fatalf("runtime envelope lost LSE fields: %+v", envelope)
	}
}

func TestBuildChatRuntimeEnvelopeUsesCurrentAuthIdentity(t *testing.T) {
	authInfo := &auth.AuthInfo{
		TenantID:  "tenant-proxy",
		ProjectID: "project-proxy",
		UserID:    "system_proxy:1.2.3.4",
		KeyID:     "key-original",
	}
	req := &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}}
	modelRecord := &modelrouter.ModelRecord{ID: "model-1", ProviderID: "provider-1", ProviderType: "openai"}

	envelope := buildChatRuntimeEnvelope(chatRuntimeContextInput{
		requestID:   "req-1",
		authInfo:    authInfo,
		request:     req,
		modelRecord: modelRecord,
	})

	if envelope.TenantID != "tenant-proxy" || envelope.ProjectID != "project-proxy" || envelope.UserID != "system_proxy:1.2.3.4" {
		t.Fatalf("runtime envelope should use current auth identity after proxy switch, got %+v", envelope)
	}
}
