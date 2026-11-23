package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
)

const nfAnthropicReply = `{"id":"msg_1","type":"message","role":"assistant","model":"kiro-opus","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`

// nfRequest 描述一次打到某个端点的请求。access 非空时经过用户模型授权闸门（owned key）；
// keyAllowlist 非空时模拟密钥白名单。
type nfRequest struct {
	endpoint     string // chat / messages / responses / embeddings / images
	model        string
	resolver     *MockModelResolver
	caller       *MockProviderCaller
	access       *modelaccess.Access
	keyAllowlist []string
	body         string
}

func nfPath(endpoint string) string {
	switch endpoint {
	case "chat":
		return "/v1/chat/completions"
	case "images":
		return "/v1/images/generations"
	default:
		return "/v1/" + endpoint
	}
}

func nfBody(endpoint, model string) string {
	switch endpoint {
	case "chat":
		return `{"model":"` + model + `","messages":[{"role":"user","content":"hello"}]}`
	case "messages":
		return `{"model":"` + model + `","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`
	case "responses":
		return `{"model":"` + model + `","input":"hello"}`
	case "embeddings":
		return `{"model":"` + model + `","input":"hello"}`
	default:
		return `{"model":"` + model + `","prompt":"hello","n":1,"size":"1024x1024"}`
	}
}

func serveNF(t *testing.T, in nfRequest) (*httptest.ResponseRecorder, *MockAuditWriter) {
	t.Helper()
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	audit := &MockAuditWriter{}
	if in.resolver == nil {
		in.resolver = &MockModelResolver{}
	}
	if in.caller == nil {
		in.caller = &MockProviderCaller{}
	}
	factory := &MockProviderAdapterFactory{MockProviderCaller: in.caller}
	cfg := &config.Config{}
	var handler http.Handler
	switch in.endpoint {
	case "chat":
		handler = NewChatCompletionsHandler(cfg, in.resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, factory, nil, nil).Handler()
	case "messages":
		handler = NewMessagesHandler(cfg, in.resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, factory, nil, nil).Handler()
	case "responses":
		handler = NewResponsesHandler(cfg, in.resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, factory, nil, nil).Handler()
	case "embeddings":
		handler = NewEmbeddingsHandler(cfg, in.resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, factory).Handler()
	case "images":
		handler = NewImagesHandler(cfg, in.resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, factory, nil).Handler()
	default:
		t.Fatalf("unknown endpoint %q", in.endpoint)
	}
	if in.access != nil {
		gate := auth.UserModelAuthorization(func(context.Context, string, string) (*modelaccess.Access, error) { return in.access, nil })
		handler = gate(handler)
	}
	body := in.body
	if body == "" {
		body = nfBody(in.endpoint, in.model)
	}
	req := httptest.NewRequest(http.MethodPost, nfPath(in.endpoint), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", "")
	if len(in.keyAllowlist) > 0 {
		ctx = context.WithValue(ctx, auth.KeyModelAllowlistKey, in.keyAllowlist)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req.WithContext(ctx))
	return rec, audit
}

// nfErrorCode 同时兼容 OpenAI 风格 {"error":{"code","message"}} 与 Anthropic 风格
// {"type":"error","error":{"type","code","message"}}。
func nfErrorCode(t *testing.T, rec *httptest.ResponseRecorder) (code, errType, message string) {
	t.Helper()
	var body struct {
		Error struct {
			Type    string `json:"type"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v body=%s", err, rec.Body.String())
	}
	return body.Error.Code, body.Error.Type, body.Error.Message
}

func nfFinalizes(audit *MockAuditWriter) []string {
	var statuses []string
	for _, f := range audit.RequestLogFinalizes {
		statuses = append(statuses, f.Status)
	}
	return statuses
}

func nfOwnedAccess(models ...string) *modelaccess.Access {
	return &modelaccess.Access{ChatAllowed: true, EffectiveModels: models, KnownModelNames: models}
}

// ---- 2a：模型名不在目录 -> 404 model_not_found（每个端点按各自协议返回） ----

func TestUnknownModelReturns404ModelNotFoundOnEveryEndpoint(t *testing.T) {
	for _, endpoint := range []string{"chat", "messages", "responses", "embeddings", "images"} {
		for _, owned := range []bool{true, false} {
			name := endpoint + "/service-key"
			var access *modelaccess.Access
			if owned {
				name = endpoint + "/owned-key"
				access = nfOwnedAccess("anthropic/claude-opus-4-8")
			}
			t.Run(name, func(t *testing.T) {
				resolver := &MockModelResolver{ResolveError: &modelrouter.ModelNotFoundError{TenantID: "tenant-a", Requested: "claude-x", Reason: modelrouter.ModelMissNotFound}}
				rec, audit := serveNF(t, nfRequest{endpoint: endpoint, model: "claude-x", resolver: resolver, access: access})
				if rec.Code != http.StatusNotFound {
					t.Fatalf("status=%d want 404 body=%s", rec.Code, rec.Body.String())
				}
				code, errType, message := nfErrorCode(t, rec)
				if code != "model_not_found" {
					t.Fatalf("code=%q want model_not_found body=%s", code, rec.Body.String())
				}
				if !strings.Contains(message, "claude-x") || !strings.Contains(message, modelNotFoundHint) {
					t.Fatalf("message must name the model and carry the hint: %q", message)
				}
				if endpoint == "messages" && errType != "not_found_error" {
					t.Fatalf("Anthropic error type=%q want not_found_error", errType)
				}
				if endpoint == "messages" {
					assertAnthropicMessagesError(t, rec, http.StatusNotFound, "not_found_error")
				}
				if len(audit.RequestLogFinalizes) != 1 {
					t.Fatalf("finalizes=%v", nfFinalizes(audit))
				}
				final := audit.RequestLogFinalizes[0]
				if final.Status != "model_not_found" || final.StatusCode != http.StatusNotFound {
					t.Fatalf("request log status=%q code=%d want model_not_found/404", final.Status, final.StatusCode)
				}
				if final.Envelope.ClientModel != "claude-x" || final.Envelope.ModelResolution != modelrouter.ModelMissNotFound {
					t.Fatalf("envelope must record the requested name: %+v", final.Envelope)
				}
			})
		}
	}
}

// 数据库等基础设施故障不是「模型不存在」：保持原有 503 语义，不能被 404 掩盖。
func TestResolverInfrastructureErrorKeepsLegacyUnavailableSemantics(t *testing.T) {
	resolver := &MockModelResolver{ResolveError: errors.New("connection refused")}
	rec, audit := serveNF(t, nfRequest{endpoint: "chat", model: "claude-x", resolver: resolver, access: nfOwnedAccess("claude-x")})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if code, _, _ := nfErrorCode(t, rec); code != "model_route_unavailable" {
		t.Fatalf("enforced access keeps model_route_unavailable, got %q", code)
	}
	if got := nfFinalizes(audit); len(got) != 1 || got[0] != "model_route_unavailable" {
		t.Fatalf("finalizes=%v", got)
	}
	rec, audit = serveNF(t, nfRequest{endpoint: "chat", model: "claude-x", resolver: &MockModelResolver{ResolveError: errors.New("connection refused")}})
	if code, _, _ := nfErrorCode(t, rec); rec.Code != http.StatusServiceUnavailable || code != "model_not_configured" {
		t.Fatalf("service key keeps model_not_configured: %d %q", rec.Code, code)
	}
}

// 模型存在但没有可用线路（没有凭证）：仍是 503 model_route_unavailable。
func TestExistingModelWithoutCredentialStays503RouteUnavailable(t *testing.T) {
	resolver := &MockModelResolver{ReturnEmptyKey: true}
	rec, audit := serveNF(t, nfRequest{endpoint: "chat", model: "anthropic/claude-opus-4-8", resolver: resolver, access: nfOwnedAccess("anthropic/claude-opus-4-8")})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if code, _, _ := nfErrorCode(t, rec); code != "model_route_unavailable" {
		t.Fatalf("code=%q", code)
	}
	if got := nfFinalizes(audit); len(got) != 1 || got[0] != "model_route_unavailable" {
		t.Fatalf("finalizes=%v", got)
	}
}

func TestAmbiguousUnprefixedNameIs404WithoutLeakingCandidatesToClient(t *testing.T) {
	resolver := &MockModelResolver{ResolveError: &modelrouter.ModelNotFoundError{
		TenantID: "tenant-a", Requested: "claude-opus-4-8", Reason: modelrouter.ModelMissAmbiguous,
		Candidates: []string{"anthropic/claude-opus-4-8", "vendor-b/claude-opus-4-8"},
	}}
	rec, audit := serveNF(t, nfRequest{endpoint: "messages", model: "claude-opus-4-8", resolver: resolver, access: nfOwnedAccess("anthropic/claude-opus-4-8")})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	_, _, message := nfErrorCode(t, rec)
	if strings.Contains(message, "vendor-b/") || strings.Contains(message, "anthropic/claude-opus-4-8") {
		t.Fatalf("candidates must stay in the audit record only: %q", message)
	}
	if !strings.Contains(message, "claude-opus-4-8") || !strings.Contains(message, modelNotFoundHint) {
		t.Fatalf("message=%q", message)
	}
	env := audit.RequestLogFinalizes[0].Envelope
	if env.ModelResolution != modelrouter.ModelMissAmbiguous || len(env.ModelCandidates) != 2 {
		t.Fatalf("audit envelope=%+v", env)
	}
}

func TestDisabledModelIs404WithDistinctReason(t *testing.T) {
	resolver := &MockModelResolver{ResolveError: &modelrouter.ModelNotFoundError{TenantID: "tenant-a", Requested: "anthropic/claude-opus-4-8", Reason: modelrouter.ModelMissInactive}}
	rec, audit := serveNF(t, nfRequest{endpoint: "chat", model: "anthropic/claude-opus-4-8", resolver: resolver, access: nfOwnedAccess("anthropic/claude-opus-4-8")})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	_, _, message := nfErrorCode(t, rec)
	if !strings.Contains(message, "disabled") || !strings.Contains(message, modelNotFoundHint) {
		t.Fatalf("message=%q", message)
	}
	if got := audit.RequestLogFinalizes[0].Envelope.ModelResolution; got != modelrouter.ModelMissInactive {
		t.Fatalf("resolution=%q", got)
	}
}

// ---- 3：未加前缀的名字（唯一后缀匹配）与全名行为完全一致 ----

func nfAliasResolver() *MockModelResolver {
	return &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID: "model-opus", ModelName: "anthropic/claude-opus-4-8", AliasFrom: "claude-opus-4-8",
		ProviderID: "provider-1", ProviderType: "openai", ProviderBaseURL: "https://boflow.example", Status: "active",
	}}
}

func TestAliasBehavesLikeFullNameOnNativeMessages(t *testing.T) {
	caller := &MockProviderCaller{CallResponse: []byte(nfAnthropicReply)}
	rec, audit := serveNF(t, nfRequest{
		endpoint: "messages", model: "claude-opus-4-8", resolver: nfAliasResolver(), caller: caller,
		access: nfOwnedAccess("anthropic/claude-opus-4-8"),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(caller.TransformRequestCalls) != 1 {
		t.Fatalf("transform calls=%d", len(caller.TransformRequestCalls))
	}
	call := caller.TransformRequestCalls[0]
	if call.Envelope.Model != "anthropic/claude-opus-4-8" {
		t.Fatalf("billing/routing model=%q want the full name", call.Envelope.Model)
	}
	var upstream struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(call.RawBody, &upstream); err != nil || upstream.Model != "anthropic/claude-opus-4-8" {
		t.Fatalf("upstream body model=%q err=%v body=%s", upstream.Model, err, call.RawBody)
	}
	found := false
	for _, f := range audit.RequestLogFinalizes {
		if f.Envelope != nil && f.Envelope.ClientModel == "claude-opus-4-8" && f.Envelope.ModelResolution == "suffix_alias" {
			found = true
		}
	}
	if !found {
		t.Fatalf("original request name not recorded: %v", nfFinalizes(audit))
	}
}

func TestAliasBehavesLikeFullNameOnChat(t *testing.T) {
	caller := &MockProviderCaller{}
	rec, _ := serveNF(t, nfRequest{
		endpoint: "chat", model: "claude-opus-4-8", resolver: nfAliasResolver(), caller: caller,
		access: nfOwnedAccess("anthropic/claude-opus-4-8"),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var upstream struct {
		Model string `json:"model"`
	}
	if len(caller.TransformRequestCalls) != 1 || json.Unmarshal(caller.TransformRequestCalls[0].RawBody, &upstream) != nil || upstream.Model != "anthropic/claude-opus-4-8" {
		t.Fatalf("upstream must see the full name: %+v", caller.TransformRequestCalls)
	}
}

// 授权必须按解析后的全名判断：简写名解析到用户没有的模型 => 照样 403。
func TestAliasIsAuthorizedAgainstTheResolvedFullName(t *testing.T) {
	for _, endpoint := range []string{"chat", "messages", "responses", "embeddings", "images"} {
		t.Run(endpoint, func(t *testing.T) {
			rec, audit := serveNF(t, nfRequest{
				endpoint: endpoint, model: "claude-opus-4-8", resolver: nfAliasResolver(),
				access: nfOwnedAccess("claude-opus-4-8"), // 只授权了简写：不能借别名绕过全名授权
			})
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			code, _, message := nfErrorCode(t, rec)
			if code != "forbidden_model" || !strings.Contains(message, "anthropic/claude-opus-4-8") {
				t.Fatalf("code=%q message=%q", code, message)
			}
			if got := nfFinalizes(audit); len(got) == 0 || got[len(got)-1] != "forbidden_model" {
				t.Fatalf("finalizes=%v", got)
			}
		})
	}
}

// ---- 5：403 的消息说清楚是哪个模型、什么原因，并记录请求名 ----

func TestForbiddenModelMessageNamesModelAndReason(t *testing.T) {
	cases := []struct {
		name         string
		access       *modelaccess.Access
		keyAllowlist []string
		wantCode     string
		wantInMsg    string
		wantReason   string
	}{
		{"user grant", nfOwnedAccess("other/model"), nil, "forbidden_model", "grant", "user_grant"},
		{"key allowlist", nfOwnedAccess("anthropic/claude-opus-4-8"), []string{"other/model"}, "key_model_not_allowed", "allowlist", "key_allowlist"},
	}
	for _, endpoint := range []string{"chat", "messages", "responses", "embeddings", "images"} {
		for _, tc := range cases {
			t.Run(endpoint+"/"+tc.name, func(t *testing.T) {
				rec, audit := serveNF(t, nfRequest{
					endpoint: endpoint, model: "anthropic/claude-opus-4-8", access: tc.access, keyAllowlist: tc.keyAllowlist,
				})
				if rec.Code != http.StatusForbidden {
					t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
				}
				code, _, message := nfErrorCode(t, rec)
				if endpoint == "messages" {
					assertAnthropicMessagesError(t, rec, http.StatusForbidden, "permission_error")
				}
				if code != tc.wantCode {
					t.Fatalf("code=%q want %q body=%s", code, tc.wantCode, rec.Body.String())
				}
				if !strings.Contains(message, "anthropic/claude-opus-4-8") || !strings.Contains(message, tc.wantInMsg) {
					t.Fatalf("message must name the model and the reason (%s): %q", tc.wantInMsg, message)
				}
				env := audit.RequestLogFinalizes[0].Envelope
				if env.ClientModel != "anthropic/claude-opus-4-8" || env.RejectReason != tc.wantReason {
					t.Fatalf("audit envelope client_model=%q reject_reason=%q", env.ClientModel, env.RejectReason)
				}
			})
		}
	}
}

// ---- 1(b)：能力契约不满足 -> 把缺失的特征写进决策与客户端错误 ----

func nfNoCacheTokensResolver() *MockModelResolver {
	caps := modelrouter.ProtocolCapabilities{
		Explicit: true, AnthropicMessages: true, ChatCompletions: true,
		FeatureDeclared: map[string]bool{"cache_tokens": true}, CacheTokens: false,
	}
	return &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID: "model-opus", ModelName: "anthropic/claude-opus-4-8", ProviderID: "provider-1", ProviderType: "anthropic",
		ProviderBaseURL: "https://api.anthropic.example", Status: "active", ProtocolCapabilities: caps,
	}}
}

func TestFeatureContractRejectionNamesMissingFeature(t *testing.T) {
	body := `{"model":"anthropic/claude-opus-4-8","max_tokens":32,"system":[{"type":"text","text":"s","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"hello"}]}`
	rec, audit := serveNF(t, nfRequest{endpoint: "messages", resolver: nfNoCacheTokensResolver(), body: body, access: nfOwnedAccess("anthropic/claude-opus-4-8")})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	_, _, message := nfErrorCode(t, rec)
	if !strings.Contains(message, "cache_tokens") {
		t.Fatalf("client message must name the missing feature: %q", message)
	}
	final := audit.RequestLogFinalizes[len(audit.RequestLogFinalizes)-1]
	if final.Status != "model_route_unavailable" || final.Envelope.RejectReason != "feature_contract:cache_tokens" {
		t.Fatalf("status=%q reject_reason=%q", final.Status, final.Envelope.RejectReason)
	}
}

func TestV2NoRouteAdmittedRecordsRejectReason(t *testing.T) {
	selected := route("p1", "anthropic", "https://api.anthropic.example", "up")
	selected.ModelName = "logical/model"
	selected.ProtocolCapabilities = modelrouter.ProtocolCapabilities{
		Explicit: true, AnthropicMessages: true, FeatureDeclared: map[string]bool{"cache_tokens": true},
	}
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: selected}}
	env := &modelrouter.RequestEnvelope{RequestID: "r1", TenantID: "tenant-a", Model: "logical/model", EndpointType: "messages"}
	body := []byte(`{"model":"logical/model","system":[{"type":"text","text":"s","cache_control":{"type":"ephemeral"}}],"messages":[]}`)
	_, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine: engine, CredentialResolver: executionCredentialResolver{"p1": "k"}, Factory: &MockProviderAdapterFactory{},
		Envelope: env, SecuredBody: body,
	})
	if !errors.Is(err, errModelRouteUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(env.RejectReason, "cache_tokens") {
		t.Fatalf("reject reason must name the missing feature, got %q", env.RejectReason)
	}
	// 拒绝原因只进审计和日志，客户端仍是原来的固定文案。
	const fixed = "no usable upstream route for requested model"
	if msg := routeUnavailableMessage(env); msg != fixed {
		t.Fatalf("client message must stay fixed, got %q", msg)
	}
	if msg := routeUnavailableMessage(nil); msg != fixed {
		t.Fatalf("base message changed: %q", msg)
	}
}

// ---- 4：request_logs.routing_decision_json 里能看到客户端请求的模型名 ----

func TestAuditRoutingDecisionRecordsRequestedModelOnFailures(t *testing.T) {
	env := &modelrouter.RequestEnvelope{Model: "claude-x", ClientModel: "claude-x", ModelResolution: modelrouter.ModelMissNotFound, RejectReason: "model_not_found"}
	decision := auditRoutingDecision(env, http.StatusNotFound)
	if decision == nil || decision.ClientModel != "claude-x" || decision.ModelResolution != "not_found" || decision.RejectReason != "model_not_found" {
		t.Fatalf("decision=%+v", decision)
	}
	raw := marshalRoutingDecisionForAudit(decision, json.Marshal)
	if !strings.Contains(string(raw), `"client_model":"claude-x"`) {
		t.Fatalf("json=%s", raw)
	}

	// 已有路由决策时只叠加字段，不改动原对象（它可能被其他 goroutine 持有）。
	existing := &modelrouter.RoutingDecision{IngressProtocol: "messages", UpstreamProtocol: "messages"}
	env = &modelrouter.RequestEnvelope{ClientModel: "claude-opus-4-8", ModelResolution: "suffix_alias", RoutingDecision: existing}
	decision = auditRoutingDecision(env, http.StatusOK)
	if decision.ClientModel != "claude-opus-4-8" || decision.IngressProtocol != "messages" {
		t.Fatalf("decision=%+v", decision)
	}
	if existing.ClientModel != "" {
		t.Fatal("original routing decision was mutated")
	}

	// 没有别名、没有拒绝原因、原本也没有路由决策：即使是 >=400 也不凭空造一份决策。
	for _, status := range []int{http.StatusOK, http.StatusBadGateway, http.StatusServiceUnavailable} {
		env = &modelrouter.RequestEnvelope{Model: "m", ClientModel: "m"}
		if got := auditRoutingDecision(env, status); got != nil {
			t.Fatalf("status %d must not invent a decision: %+v", status, got)
		}
	}
}

func TestGetStatusCodeModelNotFoundIs404(t *testing.T) {
	if got := getStatusCode("model_not_found"); got != http.StatusNotFound {
		t.Fatalf("status=%d", got)
	}
}

func TestRewriteRequestBodyModelOnlyTouchesTheModelField(t *testing.T) {
	in := []byte(`{"model":"claude-opus-4-8","max_tokens":9007199254740993123456789,"messages":[{"role":"user","content":"hi"}]}`)
	out, err := rewriteRequestBodyModel(in, "anthropic/claude-opus-4-8")
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(out, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["model"]) != `"anthropic/claude-opus-4-8"` || string(fields["max_tokens"]) != "9007199254740993123456789" {
		t.Fatalf("out=%s", out)
	}
	if _, err := rewriteRequestBodyModel([]byte("not json"), "x"); err == nil {
		t.Fatal("invalid JSON must fail")
	}
}
