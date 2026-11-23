package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	securityrules "github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
	"github.com/yangjiyj/aiguard/packages/shared-go/principal"
)

type fakePolicyPreviewEngine struct {
	request securityPolicyPreviewEngineRequest
	result  *securityPolicyPreviewEngineResponse
	err     error
	calls   int
}

func (f *fakePolicyPreviewEngine) PreviewPolicies(_ context.Context, request securityPolicyPreviewEngineRequest) (*securityPolicyPreviewEngineResponse, error) {
	f.calls++
	f.request = request
	if f.err != nil {
		return nil, f.err
	}
	if f.result != nil {
		return f.result, nil
	}
	conditionalAction := "block"
	return &securityPolicyPreviewEngineResponse{
		TenantID: request.TenantID, Stage: request.Stage,
		RulePackVersion: "engine-current", IdentityVersion: request.Principal.IdentityVersion,
		Policies: []securityPolicyPreviewEngineItem{{
			PolicyID: "policy-a", PolicyCode: "policy.a", PolicyName: "策略 A",
			PolicyVersion: "policy-version", Enabled: true, Matched: true,
			SubjectMatched: true, Stage: request.Stage, StageSupported: true,
			ConfiguredAction: "block", ConditionalAction: &conditionalAction,
			RequiresFinding: true, ActionBasis: "finding_required",
		}},
	}, nil
}

type fakePolicyPreviewKeyLookup struct {
	key *repository.InternalKey
}

func (f fakePolicyPreviewKeyLookup) GetByID(context.Context, string, string) (*repository.InternalKey, error) {
	return f.key, nil
}

func previewDesiredPack(_ context.Context, tenantID string) (*securityrules.RulePack, rulePackConvergence, error) {
	return &securityrules.RulePack{
			TenantID: tenantID,
			Version:  "desired-current",
			Policies: []securityrules.CompiledPolicy{{PolicyID: "policy-a"}},
		}, rulePackConvergence{
			AuthoritativeVersion: "desired-current",
			NodeCount:            2, FreshCount: 2, ConvergedCount: 2,
			FreshConvergedCount: 2, AllConverged: true,
		}, nil
}

func TestSecurityPolicyPreviewDerivesTenantAndReturnsDeliveryTruth(t *testing.T) {
	engine := &fakePolicyPreviewEngine{}
	handler := newSecurityPolicyPreviewHandler(&Dependencies{}, engine, previewDesiredPack)
	recorder := httptest.NewRecorder()
	request := policyHandlerRequest(
		http.MethodPost,
		"/admin/v1/security/policies/preview",
		`{"stage":"input","protocol":"chat","entry_point":"gateway_api"}`,
		"auditor",
	)

	handler.preview(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if engine.request.TenantID != "tenant-a" || engine.request.Principal.TenantID != "tenant-a" {
		t.Fatalf("preview tenant was not derived from auth: %+v", engine.request)
	}
	if engine.request.Principal.ActorUserID != "" || engine.request.Principal.TrustLevel != principal.TrustUnknown {
		t.Fatalf("preview must not manufacture an actor: %+v", engine.request.Principal)
	}
	if engine.request.Principal.Protocol != "chat" || engine.request.Principal.EntryPoint != "gateway_api" {
		t.Fatalf("preview selectors were not preserved: %+v", engine.request.Principal)
	}
	var response securityPolicyPreviewResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.DesiredVersion != "desired-current" || response.EngineRulePackVersion != "engine-current" {
		t.Fatalf("version truth was not separated: %+v", response)
	}
	if !response.Nodes.AllConverged || response.Nodes.NodeCount != 2 {
		t.Fatalf("node receipt truth missing: %+v", response.Nodes)
	}
	if len(response.PublishedPolicyIDs) != 1 || response.PublishedPolicyIDs[0] != "policy-a" {
		t.Fatalf("published policy IDs missing: %+v", response.PublishedPolicyIDs)
	}
}

func TestSecurityPolicyPreviewRejectsBrowserTenantAndActorFields(t *testing.T) {
	for _, body := range []string{
		`{"stage":"input","tenant_id":"tenant-other"}`,
		`{"stage":"input","actor_user_id":"user-other"}`,
	} {
		engine := &fakePolicyPreviewEngine{}
		handler := newSecurityPolicyPreviewHandler(&Dependencies{}, engine, previewDesiredPack)
		recorder := httptest.NewRecorder()
		handler.preview(recorder, policyHandlerRequest(
			http.MethodPost, "/admin/v1/security/policies/preview", body, "auditor",
		))

		if recorder.Code != http.StatusBadRequest || engine.calls != 0 {
			t.Fatalf("untrusted identity field accepted: status=%d calls=%d body=%s", recorder.Code, engine.calls, recorder.Body.String())
		}
	}
}

func TestSecurityPolicyPreviewBoundsBrowserRequest(t *testing.T) {
	engine := &fakePolicyPreviewEngine{}
	handler := newSecurityPolicyPreviewHandler(&Dependencies{}, engine, previewDesiredPack)
	recorder := httptest.NewRecorder()
	body := `{"stage":"input","protocol":"` + strings.Repeat("x", maxSecurityPolicyPreviewRequestBytes) + `"}`

	handler.preview(recorder, policyHandlerRequest(
		http.MethodPost, "/admin/v1/security/policies/preview", body, "auditor",
	))

	if recorder.Code != http.StatusRequestEntityTooLarge || engine.calls != 0 {
		t.Fatalf("oversized request was not bounded: status=%d calls=%d body=%s", recorder.Code, engine.calls, recorder.Body.String())
	}
}

func TestSecurityPolicyPreviewRejectsImpossibleProtocolEntryPair(t *testing.T) {
	engine := &fakePolicyPreviewEngine{}
	handler := newSecurityPolicyPreviewHandler(&Dependencies{}, engine, previewDesiredPack)
	recorder := httptest.NewRecorder()

	handler.preview(recorder, policyHandlerRequest(
		http.MethodPost, "/admin/v1/security/policies/preview",
		`{"stage":"input","protocol":"mcp","entry_point":"gateway_api"}`, "auditor",
	))

	if recorder.Code != http.StatusUnprocessableEntity || engine.calls != 0 {
		t.Fatalf("impossible runtime pair reached engine: status=%d calls=%d body=%s", recorder.Code, engine.calls, recorder.Body.String())
	}
}

func TestSecurityPolicyPreviewRejectsCrossTenantKeyBeforeEngine(t *testing.T) {
	engine := &fakePolicyPreviewEngine{}
	deps := &Dependencies{ContentExceptionKeyLookup: fakePolicyPreviewKeyLookup{
		key: &repository.InternalKey{ID: "key-other", TenantID: "tenant-other", Status: "active"},
	}}
	handler := newSecurityPolicyPreviewHandler(deps, engine, previewDesiredPack)
	recorder := httptest.NewRecorder()

	handler.preview(recorder, policyHandlerRequest(
		http.MethodPost,
		"/admin/v1/security/policies/preview",
		`{"stage":"input","key_id":"key-other"}`,
		"auditor",
	))

	if recorder.Code != http.StatusUnprocessableEntity || engine.calls != 0 {
		t.Fatalf("cross-tenant key reached engine: status=%d calls=%d body=%s", recorder.Code, engine.calls, recorder.Body.String())
	}
}

func TestSecurityPolicyPreviewDoesNotLeakEngineErrors(t *testing.T) {
	engine := &fakePolicyPreviewEngine{err: errors.New("backend secret detail")}
	handler := newSecurityPolicyPreviewHandler(&Dependencies{}, engine, previewDesiredPack)
	recorder := httptest.NewRecorder()

	handler.preview(recorder, policyHandlerRequest(
		http.MethodPost,
		"/admin/v1/security/policies/preview",
		`{"stage":"output"}`,
		"auditor",
	))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "backend secret detail") {
		t.Fatalf("engine error leaked: %s", recorder.Body.String())
	}
}

func TestSecurityPolicyPreviewDeadlineCoversDesiredPackCompilation(t *testing.T) {
	engine := &fakePolicyPreviewEngine{}
	slowCompile := func(ctx context.Context, _ string) (*securityrules.RulePack, rulePackConvergence, error) {
		<-ctx.Done()
		return nil, rulePackConvergence{}, ctx.Err()
	}
	handler := newSecurityPolicyPreviewHandler(&Dependencies{}, engine, slowCompile)
	handler.timeout = 10 * time.Millisecond
	recorder := httptest.NewRecorder()
	started := time.Now()

	handler.preview(recorder, policyHandlerRequest(
		http.MethodPost, "/admin/v1/security/policies/preview",
		`{"stage":"input"}`, "auditor",
	))

	if recorder.Code != http.StatusServiceUnavailable || engine.calls != 0 {
		t.Fatalf("slow compile was not cancelled: status=%d calls=%d body=%s", recorder.Code, engine.calls, recorder.Body.String())
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("preview deadline did not cover compilation: %s", elapsed)
	}
}

func TestSecurityEnginePreviewClientUsesInternalTokenAndStrictResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/internal/policies/preview/" {
			t.Fatalf("path=%q", r.URL.Path)
		}
		if r.Header.Get(InternalAPISecretHeader) != "internal-token" {
			t.Fatalf("missing internal token")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tenant_id":"tenant-a","stage":"input","rule_pack_version":"pack","identity_version":"identity","content_evaluated":false,"policies":[]}`))
	}))
	defer server.Close()
	client := newSecurityEngineClient(server.URL, "internal-token")
	principalContext, err := principal.Normalize(principal.Context{
		TenantID: "tenant-a", IdentityVersion: "identity",
	})
	if err != nil {
		t.Fatalf("normalize principal: %v", err)
	}

	response, err := client.PreviewPolicies(context.Background(), securityPolicyPreviewEngineRequest{
		TenantID: "tenant-a", Stage: "input", Principal: principalContext,
	})

	if err != nil || response.RulePackVersion != "pack" {
		t.Fatalf("PreviewPolicies response=%+v err=%v", response, err)
	}
}
