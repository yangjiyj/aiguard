package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
)

type endpointIntentAuthorizationRepo struct {
	called   bool
	tenant   string
	endpoint string
	request  agentintent.AuthorizationResolveRequest
	resolved *repository.AgentIntentAuthorizationContext
}

func (f *endpointIntentAuthorizationRepo) ResolveIntentAuthorizationContext(_ context.Context, tenant, endpoint string, request agentintent.AuthorizationResolveRequest) (repository.AgentIntentAuthorizationContext, error) {
	f.called, f.tenant, f.endpoint, f.request = true, tenant, endpoint, request
	if f.resolved != nil {
		return *f.resolved, nil
	}
	result := repository.AgentIntentAuthorizationContext{
		AuthorizationStatus: "resolved", TaskStatus: "missing",
	}
	if len(request.Facets) > 0 {
		result.Resolutions = []agentintent.AuthorizationResolution{{
			Facet: request.Facets[0], IdempotencyKey: "server-key", Allowed: true,
			PrincipalID: "server-principal", GrantID: "server-grant",
		}}
	}
	return result, nil
}

func TestResolveIntentAuthorizationsUsesAuthenticatedEndpointContext(t *testing.T) {
	repo := &endpointIntentAuthorizationRepo{}
	body := `{"product":"claude-code","session_id":"session-client","tool_use_id":"call-client","arguments_hash":"sha256:` + strings.Repeat("a", 64) + `","tool_name":"Read","facets":[{"action":"file_read","resource_type":"file","resource_id":"/workspace/readme.txt"}]}`
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/agent/intent-authorizations/resolve", strings.NewReader(body))
	request = request.WithContext(contextWithEndpoint(request.Context(), &repository.AgentEndpointContext{
		TenantID: "tenant-authenticated", EndpointID: "endpoint-authenticated", AgentProduct: "claude-code",
	}))
	w := httptest.NewRecorder()
	(&AgentEndpointAPI{AuthorizationRepo: repo}).ResolveIntentAuthorizations(w, request)
	if w.Code != http.StatusOK || !repo.called || repo.tenant != "tenant-authenticated" || repo.endpoint != "endpoint-authenticated" ||
		repo.request.SessionID != "session-client" || repo.request.ToolUseID != "call-client" {
		t.Fatalf("status=%d called=%v scope=%q/%q request=%+v body=%s", w.Code, repo.called, repo.tenant, repo.endpoint, repo.request, w.Body.String())
	}
}

func TestResolveIntentAuthorizationsRejectsProductMismatchBeforeRepository(t *testing.T) {
	repo := &endpointIntentAuthorizationRepo{}
	body := `{"product":"openclaw","session_id":"session-client","tool_use_id":"call-client","arguments_hash":"sha256:` + strings.Repeat("a", 64) + `","tool_name":"read","facets":[{"action":"file_read","resource_type":"file","resource_id":"/workspace/readme.txt"}]}`
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/agent/intent-authorizations/resolve", strings.NewReader(body))
	request = request.WithContext(contextWithEndpoint(request.Context(), &repository.AgentEndpointContext{
		TenantID: "tenant-authenticated", EndpointID: "endpoint-authenticated", AgentProduct: "claude-code",
	}))
	w := httptest.NewRecorder()
	(&AgentEndpointAPI{AuthorizationRepo: repo}).ResolveIntentAuthorizations(w, request)
	if w.Code != http.StatusConflict || repo.called {
		t.Fatalf("status=%d repository_called=%v", w.Code, repo.called)
	}
}

func TestResolveIntentAuthorizationsRequiresEndpointContext(t *testing.T) {
	repo := &endpointIntentAuthorizationRepo{}
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/agent/intent-authorizations/resolve", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	(&AgentEndpointAPI{AuthorizationRepo: repo}).ResolveIntentAuthorizations(w, request)
	if w.Code != http.StatusServiceUnavailable || repo.called {
		t.Fatalf("status=%d repository_called=%v", w.Code, repo.called)
	}
}

func TestResolveIntentAuthorizationsReturnsNonAuthorizingTaskContextWhenT13Unresolved(t *testing.T) {
	taskID := "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	purpose := "review source before writing"
	scope := agentintent.IntentTaskSourceScope{AllowedKinds: []string{"web"}}
	task := &repository.AgentIntentTask{
		ID: taskID, Purpose: purpose, PurposeSHA256: agentintent.DigestString(purpose),
		SourceScope:       repository.AgentIntentTaskSourceScope{AllowedKinds: []string{"web"}},
		SourceScopeSHA256: agentintent.DigestString(string(agentintent.CanonicalIntentTaskSourceScopeBytes(scope))),
		ScopeSHA256:       strings.Repeat("b", 64), State: "approved",
	}
	repo := &endpointIntentAuthorizationRepo{resolved: &repository.AgentIntentAuthorizationContext{
		AuthorizationStatus: "unresolved", TaskStatus: "resolved", Task: task,
		Resolutions: []agentintent.AuthorizationResolution{},
	}}
	body := `{"product":"claude-code","intent_task_id":"` + taskID + `","session_id":"session-client","tool_use_id":"call-client","arguments_hash":"sha256:` + strings.Repeat("a", 64) + `","tool_name":"opaque_tool","facets":[]}`
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/agent/intent-authorizations/resolve", strings.NewReader(body))
	request = request.WithContext(contextWithEndpoint(request.Context(), &repository.AgentEndpointContext{
		TenantID: "tenant-authenticated", EndpointID: "endpoint-authenticated", AgentProduct: "claude-code",
	}))
	w := httptest.NewRecorder()
	(&AgentEndpointAPI{AuthorizationRepo: repo}).ResolveIntentAuthorizations(w, request)
	var response agentintent.AuthorizationResolveResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || response.AuthorizationStatus != "unresolved" ||
		response.TaskStatus != "resolved" || response.Task == nil || response.Task.ID != taskID ||
		len(response.Resolutions) != 0 {
		t.Fatalf("task context should remain available without T13 authority: status=%d response=%+v", w.Code, response)
	}
}
