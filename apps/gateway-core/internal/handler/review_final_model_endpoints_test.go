package handler

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestReviewEveryEndpointChecksFinalLogicalModel(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "false")
	for _, endpoint := range []string{"messages", "responses", "embeddings", "images/generations"} {
		t.Run(endpoint, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
			defer upstream.Close()
			selected := route("p1", "openai", upstream.URL, "vendor-model")
			selected.ModelName = "forbidden/model"
			selected.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true, AnthropicMessages: true, ResponsesNative: true, Embeddings: true, Images: true}
			engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: selected}}
			resolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{EnforcementMode: "bypass"}}
			factory := &RealProviderAdapterFactory{}
			cfg := &config.Config{SecurityAuditOnly: true}
 audit:=&MockAuditWriter{}
			var handler http.Handler
			var body string
			switch endpoint {
			case "messages":
				h := NewMessagesHandler(cfg, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, factory, nil, nil)
				h.SetModelRoutingEngine(engine)
				handler = h.Handler()
				body = `{"model":"original/model","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`
			case "responses":
				h := NewResponsesHandler(cfg, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, factory, nil, nil)
				h.SetModelRoutingEngine(engine)
				handler = h.Handler()
				body = `{"model":"original/model","input":"hello"}`
			case "embeddings":
				h := NewEmbeddingsHandler(cfg, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, factory)
				h.SetModelRoutingEngine(engine)
				handler = h.Handler()
				body = `{"model":"original/model","input":"hello"}`
			case "images/generations":
				h := NewImagesHandler(cfg, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, factory, nil)
				h.SetModelRoutingEngine(engine)
				handler = h.Handler()
				body = `{"model":"original/model","prompt":"hello","n":1,"size":"1024x1024"}`
			}
			gate := auth.UserModelAuthorization(func(context.Context, string, string) (*modelaccess.Access, error) {
				return &modelaccess.Access{ChatAllowed: true, EffectiveModels: []string{"original/model"}}, nil
			})
			req := httptest.NewRequest("POST", "/v1/"+endpoint, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
			w := httptest.NewRecorder()
			gate(handler).ServeHTTP(w, req)
			if w.Code != 403 || calls.Load()!=0 || engine.planCalls!=1 || len(audit.RequestLogFinalizes)!=1 || audit.RequestLogFinalizes[0].Status!="forbidden_model" || (endpoint!="messages"&&!strings.Contains(w.Body.String(),"forbidden_model")) || (endpoint=="messages"&&!strings.Contains(w.Body.String(),"model is not allowed by user policy")) {
				t.Fatalf("status=%d upstream=%d body=%s", w.Code, calls.Load(), w.Body.String())
			}
		})
	}
}
