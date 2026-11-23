package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
	"github.com/yangjiyj/aiguard/packages/shared-go/principal"
)

func TestPersonalModelGateCannotBeBypassedByQuotaModeOrAlias(t *testing.T) {
	for _, mode := range []string{"soft", "bypass", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			audit := &MockAuditWriter{}
			resolver := &MockModelResolver{ModelPolicy: &modelrouter.ModelPolicy{}, QuotaPolicy: &modelrouter.QuotaPolicy{EnforcementMode: mode}}
			h := &ChatCompletionsHandler{modelResolver: resolver, rateLimiter: &MockRateLimitChecker{}, auditWriter: audit}
			gate := auth.UserModelAuthorization(func(context.Context, string, string) (*modelaccess.Access, error) {
				return &modelaccess.Access{Role: "chat_user", ChatAllowed: true, EffectiveModels: []string{"allowed"}}, nil
			})
			next := gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				req := &ChatCompletionRequest{Model: "forbidden-alias"}
				info := auth.GetAuthInfo(r)
				_, err := h.runChatPolicyPreflight(chatPolicyPreflightInput{ctx: r.Context(), w: w, r: r, requestID: "personal-denial", authInfo: info, startedAt: time.Now(), request: req, modelRecord: &modelrouter.ModelRecord{ID: "model-1", ModelName: "allowed"}, partialEnvelope: buildChatPartialEnvelope("personal-denial", info, req.Model, "chat")})
				if err == nil {
					w.WriteHeader(http.StatusOK)
				}
			}))
			r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			ctx := context.WithValue(r.Context(), auth.TenantKey, "tenant-a")
			ctx = context.WithValue(ctx, auth.UserKey, "user-a")
			ctx = context.WithValue(ctx, auth.ProjectKey, "project-a")
			w := httptest.NewRecorder()
			next.ServeHTTP(w, r.WithContext(ctx))
			if w.Code != 403 {
				t.Fatalf("personal denial bypassed in %s: %d %s", mode, w.Code, w.Body.String())
			}
			if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "forbidden_model" {
				t.Fatalf("denial audit missing: %+v", audit.RequestLogFinalizes)
			}
		})
	}
}

func TestPersonalModelGateRechecksLegacyAndGovernorFinalModel(t *testing.T) {
	for _, change := range []string{"legacy", "governor"} {
		t.Run(change, func(t *testing.T) {
			finalModel := "forbidden/model"
			selected := route("p1", "openai", "https://fixture.invalid", "vendor-model")
			selected.ModelName = finalModel
			engine := &executionTestEngine{policyByRef: map[string]bool{finalModel: true}, applied: true, plan: modelrouter.RoutePlan{Primary: selected}}
			caller := &MockProviderCaller{}
			factory := &MockProviderAdapterFactory{MockProviderCaller: caller, CallersByProviderID: map[string]ProviderCaller{"p1": caller}}
			h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, factory, nil, nil)
			h.modelRouteEngine = engine
			if change == "legacy" {
				h.legacyModelResolver = func(_ context.Context, e *modelrouter.RequestEnvelope) *modelrouter.ModelDecision {
					e.Model = finalModel
					return &modelrouter.ModelDecision{TargetModel: finalModel}
				}
			} else {
				h.SetGovernor(executionGovernor{decision: governor.Decision{Action: governor.ActionDowngradeMod, DowngradeTo: finalModel}})
			}
			gate := auth.UserModelAuthorization(func(context.Context, string, string) (*modelaccess.Access, error) {
				return &modelaccess.Access{Role: "chat_user", ChatAllowed: true, EffectiveModels: []string{"original/model"}}, nil
			})
			body, _ := json.Marshal(ChatCompletionRequest{Model: "original/model", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}})
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)).WithContext(setAuthInfo(context.Background(), "tenant-a", "project-a", "user-a", "key-a", ""))
			w := httptest.NewRecorder()
			gate(h.Handler()).ServeHTTP(w, req)
			if w.Code != 403 || len(caller.CallCalls) != 0 || engine.planCalls != 0 {
				t.Fatalf("final model bypassed grant: status=%d calls=%d plans=%d body=%s", w.Code, len(caller.CallCalls), engine.planCalls, w.Body.String())
			}
		})
	}
}

func TestOwnedKeyExtraGrantOverridesProjectModelPolicy(t *testing.T) {
	for _, user := range []string{"user-a", ""} {
		t.Run("owner="+user, func(t *testing.T) {
			audit := &MockAuditWriter{}
			resolver := &MockModelResolver{ModelPolicy: &modelrouter.ModelPolicy{AllowList: []string{"department-model"}}, QuotaPolicy: &modelrouter.QuotaPolicy{EnforcementMode: "bypass"}}
			h := &ChatCompletionsHandler{modelResolver: resolver, rateLimiter: &MockRateLimitChecker{}, auditWriter: audit}
			gate := auth.UserModelAuthorization(func(context.Context, string, string) (*modelaccess.Access, error) {
				return &modelaccess.Access{ChatAllowed: true, EffectiveModels: []string{"extra"}}, nil
			})
			next := gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				req := &ChatCompletionRequest{Model: "extra"}
				info := auth.GetAuthInfo(r)
				_, err := h.runChatPolicyPreflight(chatPolicyPreflightInput{ctx: r.Context(), w: w, r: r, requestID: "extra", authInfo: info, startedAt: time.Now(), request: req, modelRecord: &modelrouter.ModelRecord{}, partialEnvelope: buildChatPartialEnvelope("extra", info, req.Model, "chat")})
				if err == nil {
					w.WriteHeader(200)
				}
			}))
			r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil).WithContext(setAuthInfo(context.Background(), "tenant-a", "project-a", user, "key-a", ""))
			w := httptest.NewRecorder()
			next.ServeHTTP(w, r)
			want := 403
			if user != "" {
				want = 200
			}
			if w.Code != want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body.String())
			}
		})
	}
}

func TestPersonalModelGateRechecksV2PrimaryLogicalModel(t *testing.T) {
	caller := &MockProviderCaller{}
	selected := route("p1", "openai", "https://fixture.invalid", "vendor-model")
	selected.ModelName = "forbidden/model"
	engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: selected}}
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &MockProviderAdapterFactory{MockProviderCaller: caller, CallersByProviderID: map[string]ProviderCaller{"p1": caller}}, nil, nil)
	h.modelRouteEngine = engine
	gate := auth.UserModelAuthorization(func(context.Context, string, string) (*modelaccess.Access, error) {
		return &modelaccess.Access{ChatAllowed: true, EffectiveModels: []string{"original/model"}}, nil
	})
	body, _ := json.Marshal(ChatCompletionRequest{Model: "original/model", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}})
	r := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body)).WithContext(setAuthInfo(context.Background(), "tenant-a", "project-a", "user-a", "key-a", ""))
	w := httptest.NewRecorder()
	gate(h.Handler()).ServeHTTP(w, r)
	if w.Code != 403 || len(caller.CallCalls) != 0 {
		t.Fatalf("V2 final model status=%d upstream=%d", w.Code, len(caller.CallCalls))
	}
}

type ownerGateQuota struct{}

func (ownerGateQuota) GetEnforcementMode(context.Context, governor.ScopeRef) string { return "enforce" }
func (ownerGateQuota) EffectiveQuota(context.Context, governor.ScopeRef) (governor.EffectiveQuotaInput, error) {
	return governor.EffectiveQuotaInput{}, nil
}

type ownerGateSnapshot struct{}

func (ownerGateSnapshot) GetMulti(context.Context, governor.ScopeRef) (map[string]governor.Snapshot, error) {
	return map[string]governor.Snapshot{}, nil
}

type ownerGateModelChecker struct{}

func (ownerGateModelChecker) IsModelAllowedForTeam(context.Context, string, string) (bool, error) {
	return false, nil
}

type ownerGateDecider struct {
	d *governor.Decider
	t *testing.T
}

func (d ownerGateDecider) Decide(ctx context.Context, ref governor.ScopeRef) governor.Decision {
	if ref.UserID != "" {
		d.t.Fatal("API key owner must not be fabricated as authenticated billing actor")
	}
	ref.TeamID = "department"
	ref.ModelID = "extra-model"
	return d.d.Decide(ctx, ref)
}
func TestPersonalExtraGrantDoesNotRequireAnAuthenticatedActor(t *testing.T) {
	caller := &MockProviderCaller{}
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &MockProviderAdapterFactory{MockProviderCaller: caller}, nil, nil)
	h.SetGovernor(ownerGateDecider{d: governor.New(ownerGateSnapshot{}, ownerGateQuota{}).WithModelChecker(ownerGateModelChecker{}), t: t})
	gate := auth.UserModelAuthorization(func(context.Context, string, string) (*modelaccess.Access, error) {
		return &modelaccess.Access{ChatAllowed: true, EffectiveModels: []string{"extra"}}, nil
	})
	p, err := principal.Normalize(principal.Context{TenantID: "tenant-a", ProjectID: "project-a", KeyID: "key-a", KeyOwnerUserID: "user-a", IdentitySource: principal.SourceAPIKey, TrustLevel: principal.TrustKeyBound})
	if err != nil {
		t.Fatal(err)
	}
	ctx := setAuthInfo(context.Background(), "tenant-a", "project-a", "user-a", "key-a", "")
	ctx = context.WithValue(ctx, auth.PrincipalKey, &p)
	body, _ := json.Marshal(ChatCompletionRequest{Model: "extra", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}})
	r := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body)).WithContext(ctx)
	w := httptest.NewRecorder()
	gate(h.Handler()).ServeHTTP(w, r)
	if w.Code != 200 || len(caller.CallCalls) != 1 {
		t.Fatalf("owned extra grant status=%d upstream=%d", w.Code, len(caller.CallCalls))
	}
}
