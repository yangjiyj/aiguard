package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

type memoryResponseCache struct {
	mu      sync.Mutex
	values  map[string][]byte
	ttls    map[string]time.Duration
	sets    chan string
	failGet bool
}

func newMemoryResponseCache() *memoryResponseCache {
	return &memoryResponseCache{values: map[string][]byte{}, ttls: map[string]time.Duration{}, sets: make(chan string, 16)}
}

func (m *memoryResponseCache) Get(_ context.Context, key string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failGet {
		return nil, false
	}
	v, ok := m.values[key]
	return v, ok
}

func (m *memoryResponseCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) {
	m.mu.Lock()
	m.values[key] = append([]byte(nil), value...)
	m.ttls[key] = ttl
	m.mu.Unlock()
	m.sets <- key
}

func (m *memoryResponseCache) waitSet(t *testing.T) string {
	t.Helper()
	select {
	case key := <-m.sets:
		return key
	case <-time.After(2 * time.Second):
		t.Fatal("cache write did not happen")
		return ""
	}
}

func (m *memoryResponseCache) noSet(t *testing.T) {
	t.Helper()
	select {
	case key := <-m.sets:
		t.Fatalf("unexpected cache write %s", key)
	case <-time.After(150 * time.Millisecond):
	}
}

func cacheOnSettings() responseCacheSettings {
	s := defaultResponseCacheSettings()
	s.Enabled = true
	return s
}

var testCacheVersions = responseCacheVersions{rulePack: "rp1", engineBuild: "eb1", semantic: "sr1", gatewayRevision: "gr1"}

func cacheEnvelope(user string) *modelrouter.RequestEnvelope {
	return &modelrouter.RequestEnvelope{RequestID: "req_x", TenantID: "t_1", ProjectID: "p_1", UserID: user, ClientID: "key_1", Model: "gpt-4", ModelID: "m_1", EnvironmentScope: "customer", EndpointType: "chat"}
}

func TestResponseCacheKeyIsolationAndNormalization(t *testing.T) {
	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"  你好  "}],"stream":true,"stream_options":{"include_usage":true}}`)
	same := []byte(`{"messages":[{"content":"你好","role":"user"}],"model":"gpt-4","stream":false}`)
	settings := cacheOnSettings()

	k1, shared, err := responseCacheKey(settings, cacheEnvelope("u_1"), testCacheVersions, body)
	if err != nil || shared {
		t.Fatalf("key err=%v shared=%v", err, shared)
	}
	if k2, _, _ := responseCacheKey(settings, cacheEnvelope("u_1"), testCacheVersions, same); k2 != k1 {
		t.Fatal("stream flag, whitespace and key order must not change the key")
	}
	if k, _, _ := responseCacheKey(settings, cacheEnvelope("u_2"), testCacheVersions, body); k == k1 {
		t.Fatal("different users must not share a key by default")
	}
	other := cacheEnvelope("u_1")
	other.TenantID = "t_2"
	if k, _, _ := responseCacheKey(settings, other, testCacheVersions, body); k == k1 {
		t.Fatal("different tenants must not share a key")
	}
	for name, v := range map[string]responseCacheVersions{
		"rule pack": {"rp2", "eb1", "sr1", "gr1"}, "engine": {"rp1", "eb2", "sr1", "gr1"},
		"semantic": {"rp1", "eb1", "sr2", "gr1"}, "gateway": {"rp1", "eb1", "sr1", "gr2"},
	} {
		if k, _, _ := responseCacheKey(settings, cacheEnvelope("u_1"), v, body); k == k1 {
			t.Fatalf("%s version change must change the key", name)
		}
	}
	bumped := settings
	bumped.Generation = 1
	if k, _, _ := responseCacheKey(bumped, cacheEnvelope("u_1"), testCacheVersions, body); k == k1 {
		t.Fatal("generation bump must invalidate")
	}
	if _, _, err := responseCacheKey(settings, cacheEnvelope("u_1"), responseCacheVersions{}, body); err == nil {
		t.Fatal("unknown detection versions must disable caching")
	}
	if !strings.HasPrefix(k1, responseCacheKeyPrefix) {
		t.Fatalf("key prefix: %s", k1)
	}

	sharedSettings := settings
	sharedSettings.SharedProjectIDs = map[string]bool{"p_1": true}
	ka, sharedA, _ := responseCacheKey(sharedSettings, cacheEnvelope("u_1"), testCacheVersions, body)
	kb, _, _ := responseCacheKey(sharedSettings, cacheEnvelope("u_2"), testCacheVersions, body)
	if !sharedA || ka != kb {
		t.Fatal("shared project should share across users")
	}
	keyOnly := cacheEnvelope("")
	if _, _, err := responseCacheKey(settings, keyOnly, testCacheVersions, body); err != nil {
		t.Fatalf("key-only caller should still be cacheable: %v", err)
	}
	keyOnly.ClientID = ""
	if _, _, err := responseCacheKey(settings, keyOnly, testCacheVersions, body); err == nil {
		t.Fatal("caller without user or key must not be cached")
	}
}

func TestResponseCacheEligibility(t *testing.T) {
	settings := cacheOnSettings()
	base := func() *ChatCompletionRequest {
		return &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: json.RawMessage(`"hi"`)}}}
	}
	ctx := context.Background()
	if !responseCacheRequestEligible(ctx, cacheEnvelope("u"), base(), "", settings) {
		t.Fatal("plain text request should be eligible")
	}
	if responseCacheRequestEligible(ctx, cacheEnvelope("u"), base(), "", defaultResponseCacheSettings()) {
		t.Fatal("disabled settings must not cache")
	}
	cases := map[string]func(*ChatCompletionRequest, *modelrouter.RequestEnvelope) (string, context.Context){
		"tools": func(r *ChatCompletionRequest, _ *modelrouter.RequestEnvelope) (string, context.Context) {
			r.Tools = []ToolDef{{}}
			return "", ctx
		},
		"tool_choice": func(r *ChatCompletionRequest, _ *modelrouter.RequestEnvelope) (string, context.Context) {
			r.ToolChoice = "auto"
			return "", ctx
		},
		"tool message": func(r *ChatCompletionRequest, _ *modelrouter.RequestEnvelope) (string, context.Context) {
			r.Messages = append(r.Messages, Message{Role: "tool", ToolCallID: "c1", Content: json.RawMessage(`"x"`)})
			return "", ctx
		},
		"image": func(r *ChatCompletionRequest, _ *modelrouter.RequestEnvelope) (string, context.Context) {
			r.Messages[0].Content = json.RawMessage(`[{"type":"text","text":"看图"},{"type":"image_url","image_url":{"url":"data:x"}}]`)
			return "", ctx
		},
		"high temperature": func(r *ChatCompletionRequest, _ *modelrouter.RequestEnvelope) (string, context.Context) {
			r.Temperature = 1.5
			return "", ctx
		},
		"no-store": func(*ChatCompletionRequest, *modelrouter.RequestEnvelope) (string, context.Context) {
			return "no-store", ctx
		},
		"messages endpoint": func(_ *ChatCompletionRequest, e *modelrouter.RequestEnvelope) (string, context.Context) {
			e.EndpointType = "messages"
			return "", ctx
		},
		"evaluation": func(_ *ChatCompletionRequest, e *modelrouter.RequestEnvelope) (string, context.Context) {
			e.LSEEvalRunID = "run"
			return "", ctx
		},
		"proxy": func(*ChatCompletionRequest, *modelrouter.RequestEnvelope) (string, context.Context) {
			return "", context.WithValue(ctx, auth.ProxyRequestKey, true)
		},
		"reversible masking": func(_ *ChatCompletionRequest, e *modelrouter.RequestEnvelope) (string, context.Context) {
			rctx := withRequestRedaction(ctx)
			ph := "<JJD_手机号_0123456789abcdef0123456789abcdef_1>"
			addRequestRedaction(rctx, e, "x "+ph, map[string]string{ph: "13800138000"})
			return "", rctx
		},
	}
	for name, mutate := range cases {
		req, env := base(), cacheEnvelope("u")
		cc, c := mutate(req, env)
		if responseCacheRequestEligible(c, env, req, cc, settings) {
			t.Fatalf("%s should not be cached", name)
		}
	}
	if !rawBodyRequestsMultipleOrLogprobs([]byte(`{"n":2}`)) || !rawBodyRequestsMultipleOrLogprobs([]byte(`{"logprobs":true}`)) {
		t.Fatal("n>1 and logprobs must be rejected")
	}
	if rawBodyRequestsMultipleOrLogprobs([]byte(`{"n":1,"logprobs":false}`)) {
		t.Fatal("n=1 without logprobs is fine")
	}
}

func TestResponseCacheStorable(t *testing.T) {
	settings := cacheOnSettings()
	env := cacheEnvelope("u")
	env.QuotaActualCostMicros, env.QuotaActualCostAvailable, env.QuotaCostCurrency = 1200, true, "CNY"
	ok := []byte(`{"model":"gpt-4","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"答"}}],"usage":{"prompt_tokens":3,"completion_tokens":5}}`)
	entry, stored := responseCacheStorable(settings, env, ok, &AuditResult{OutputAction: "allow"})
	if !stored || entry.CostMicros != 1200 || entry.Currency != "CNY" || entry.SourceRequestID != "req_x" {
		t.Fatalf("entry = %+v stored=%v", entry, stored)
	}
	for name, c := range map[string]struct {
		body  string
		audit *AuditResult
	}{
		"length":     {`{"choices":[{"finish_reason":"length","message":{"content":"半"}}]}`, nil},
		"empty":      {`{"choices":[{"finish_reason":"stop","message":{"content":"  "}}]}`, nil},
		"tools":      {`{"choices":[{"finish_reason":"stop","message":{"content":"x","tool_calls":[{"id":"1"}]}}]}`, nil},
		"masked":     {string(ok), &AuditResult{OutputAction: "mask"}},
		"findings":   {string(ok), &AuditResult{OutputFindings: []map[string]interface{}{{"type": "pii"}}}},
		"incomplete": {string(ok), &AuditResult{ResponseMetadata: map[string]interface{}{"output_scan_incomplete": true}}},
	} {
		if _, stored := responseCacheStorable(settings, env, []byte(c.body), c.audit); stored {
			t.Fatalf("%s should not be stored", name)
		}
	}
	small := settings
	small.MaxEntryBytes = 10
	if _, stored := responseCacheStorable(small, env, ok, nil); stored {
		t.Fatal("oversized entry should not be stored")
	}
}

func TestParseResponseCacheSettings(t *testing.T) {
	s := parseResponseCacheSettings(map[string]string{
		responseCacheEnabledKey: "true", responseCacheTTLKey: "600", responseCacheMaxEntryBytesKey: "2048",
		responseCacheMaxTemperatureKey: "0.5", responseCacheSharedProjectsKey: `["p_1"," p_2 ",""]`, responseCacheGenerationKey: "3",
	})
	if !s.Enabled || s.TTL != 10*time.Minute || s.MaxEntryBytes != 2048 || s.MaxTemperature != 0.5 || s.Generation != 3 ||
		strings.Join(sortedKeys(s.SharedProjectIDs), ",") != "p_1,p_2" {
		t.Fatalf("settings = %+v", s)
	}
	d := parseResponseCacheSettings(map[string]string{responseCacheTTLKey: "5", responseCacheMaxEntryBytesKey: "9999999", responseCacheMaxTemperatureKey: "9", responseCacheSharedProjectsKey: "bad"})
	if d.Enabled || d.TTL != time.Hour || d.MaxEntryBytes != 64<<10 || d.MaxTemperature != 1 || len(d.SharedProjectIDs) != 0 {
		t.Fatalf("invalid values should fall back: %+v", d)
	}
}

// ---- 经真实 chat handler 走一遍 ----

type cacheTestRig struct {
	handler *ChatCompletionsHandler
	caller  *MockProviderCaller
	audit   *MockAuditWriter
	billing *recordingBillingPreflight
	cache   *memoryResponseCache
}

func newCacheTestRig(t *testing.T, settings responseCacheSettings) *cacheTestRig {
	t.Helper()
	upstream := []byte(`{"id":"chatcmpl-up","object":"chat.completion","created":1,"model":"gpt-4","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"缓存的回答"}}],"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`)
	rig := &cacheTestRig{
		caller:  &MockProviderCaller{CallResponse: upstream},
		audit:   &MockAuditWriter{},
		billing: &recordingBillingPreflight{},
		cache:   newMemoryResponseCache(),
	}
	client := NewToolRiskClient("http://127.0.0.1:1", "synthetic-secret")
	client.setResponseCacheSettings(settings)
	security := &MockSecurityChecker{InputRulePackVersion: "rp1", InputEngineBuild: "eb1"}
	rig.handler = NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, security, rig.audit,
		&MockProviderAdapterFactory{MockProviderCaller: rig.caller}, client, nil)
	rig.handler.SetBillingPreflight(rig.billing)
	rig.handler.SetResponseCache(rig.cache)
	return rig
}

func (rig *cacheTestRig) do(t *testing.T, user string, stream bool) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"model": "gpt-4", "messages": []map[string]string{{"role": "user", "content": "什么是零信任"}}, "stream": stream})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-1", "project-1", user, "key-"+user, ""))
	w := httptest.NewRecorder()
	rig.handler.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	return w
}

func lastFinalize(audit *MockAuditWriter) (string, *AuditResult, *modelrouter.RequestEnvelope, []byte) {
	f := audit.RequestLogFinalizes[len(audit.RequestLogFinalizes)-1]
	return f.Status, f.AuditResult, f.Envelope, f.RespBody
}

func TestChatHandlerResponseCacheMissThenHit(t *testing.T) {
	for _, stream := range []bool{false, true} {
		rig := newCacheTestRig(t, cacheOnSettings())

		first := rig.do(t, "user-1", stream)
		if first.Header().Get("X-JJDGuard-Cache") != "" || len(rig.caller.CallCalls) != 1 || rig.billing.reserveCalls != 1 {
			t.Fatalf("stream=%v miss: calls=%d reserve=%d", stream, len(rig.caller.CallCalls), rig.billing.reserveCalls)
		}
		key := rig.cache.waitSet(t)
		if rig.cache.ttls[key] != time.Hour {
			t.Fatalf("ttl = %v", rig.cache.ttls[key])
		}

		second := rig.do(t, "user-1", stream)
		if second.Header().Get("X-JJDGuard-Cache") != "hit" {
			t.Fatalf("stream=%v: second request should hit", stream)
		}
		if len(rig.caller.CallCalls) != 1 || rig.billing.reserveCalls != 1 {
			t.Fatalf("stream=%v: hit must not call upstream or reserve billing (calls=%d reserve=%d)", stream, len(rig.caller.CallCalls), rig.billing.reserveCalls)
		}
		content := chatContentFromResponse(t, second, stream)
		if content != "缓存的回答" {
			t.Fatalf("stream=%v: cached content = %q", stream, content)
		}
		if stream {
			raw := second.Body.String()
			if !strings.Contains(raw, `"usage"`) || !strings.Contains(raw, "data: [DONE]") {
				t.Fatalf("stream hit must end with usage frame and [DONE]: %s", raw)
			}
		} else {
			m := decodeJSONMap(t, second.Body.Bytes())
			if !strings.HasSuffix(m["id"].(string), rig.audit.RequestLogFinalizes[len(rig.audit.RequestLogFinalizes)-1].Envelope.RequestID) {
				t.Fatalf("hit id must use this request id: %v", m["id"])
			}
			if m["usage"].(map[string]any)["completion_tokens"].(float64) != 4 {
				t.Fatalf("client should see original usage: %v", m["usage"])
			}
		}
		status, audit, env, respBody := lastFinalize(rig.audit)
		if status != "success" || !env.CacheHit || env.BillingUsageSource != "synthetic_no_upstream" {
			t.Fatalf("stream=%v: finalize status=%s cacheHit=%v source=%s", stream, status, env.CacheHit, env.BillingUsageSource)
		}
		meta := audit.ResponseMetadata["cache"].(map[string]any)
		if meta["hit"] != true || meta["saved_output_tokens"].(int64) != 4 {
			t.Fatalf("cache metadata = %v", meta)
		}
		if !strings.Contains(string(respBody), `"completion_tokens":0`) {
			t.Fatalf("audit usage must be zero on a hit: %s", respBody)
		}
		rig.cache.noSet(t)
	}
}

func TestChatHandlerResponseCacheIsolationAndFailOpen(t *testing.T) {
	rig := newCacheTestRig(t, cacheOnSettings())
	rig.do(t, "user-1", false)
	rig.cache.waitSet(t)
	if w := rig.do(t, "user-2", false); w.Header().Get("X-JJDGuard-Cache") == "hit" {
		t.Fatal("another user must not hit user-1's cache")
	}
	if len(rig.caller.CallCalls) != 2 {
		t.Fatalf("calls = %d", len(rig.caller.CallCalls))
	}
	rig.cache.waitSet(t)

	rig.cache.failGet = true
	if w := rig.do(t, "user-1", false); w.Header().Get("X-JJDGuard-Cache") == "hit" {
		t.Fatal("cache failure must behave as a miss")
	}
	if len(rig.caller.CallCalls) != 3 {
		t.Fatalf("cache failure should fall through to upstream, calls=%d", len(rig.caller.CallCalls))
	}
}

func TestChatHandlerResponseCacheDisabledByDefault(t *testing.T) {
	rig := newCacheTestRig(t, defaultResponseCacheSettings())
	rig.do(t, "user-1", false)
	rig.cache.noSet(t)
	rig.do(t, "user-1", false)
	if len(rig.caller.CallCalls) != 2 {
		t.Fatalf("disabled cache must always call upstream, calls=%d", len(rig.caller.CallCalls))
	}
}
