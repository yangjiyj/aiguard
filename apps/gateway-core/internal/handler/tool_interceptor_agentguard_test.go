package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

func TestToolRiskClientLogToolCallSendsAgentGuardFields(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/internal/tools/logs" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if (func() string {
			if legacy := r.Header.Get("X-NewAPI-Internal-Token"); legacy != "" {
				t.Errorf("legacy internal token header must be absent")
			}
			return r.Header.Get("X-JJDGuard-Internal-Token")
		})() != "secret" {
			t.Fatalf("missing internal token")
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := NewToolRiskClient(server.URL, "secret")
	envelope := &modelrouter.RequestEnvelope{
		RequestID:    "req-1",
		TenantID:     "tenant-1",
		UserID:       "user-1",
		SessionID:    "session-1",
		ProjectID:    "application-1",
		AgentType:    "codex",
		Model:        "gpt-5",
		EndpointType: "responses",
	}

	err := client.LogToolCall(context.Background(), envelope, ToolAuditLogPayload{
		ToolName:          "network.upload",
		ToolType:          "network",
		RiskLevel:         "critical",
		Parameters:        map[string]any{"url": "https://evil.example/upload"},
		Status:            "blocked",
		RawDecision:       "confirm",
		EffectiveDecision: "block",
		Mode:              "strict",
		EffectiveReason:   "confirm_without_channel_fail_closed",
		PolicyVersion:     "policy-v1",
		TraceID:           "trace-1",
		Confidence:        0.91,
		EvidenceJSON:      []map[string]any{{"rule_id": "argument_tainted", "masked_preview": "<redacted:27>"}},
		NormalizedTarget:  "https://evil.example/upload",
		Provenance:        "tainted",
		TaintedArguments:  []string{"url"},
	})
	if err != nil {
		t.Fatalf("LogToolCall returned error: %v", err)
	}

	assertJSONField(t, received, "raw_decision", "confirm")
	assertJSONField(t, received, "effective_decision", "block")
	assertJSONField(t, received, "mode", "strict")
	assertJSONField(t, received, "effective_reason", "confirm_without_channel_fail_closed")
	assertJSONField(t, received, "policy_version", "policy-v1")
	assertJSONField(t, received, "trace_id", "trace-1")
	assertJSONField(t, received, "normalized_target", "https://evil.example/upload")
	assertJSONField(t, received, "provenance", "tainted")
	assertJSONField(t, received, "application_id", "application-1")
	assertJSONField(t, received, "agent_type", "codex")
	assertJSONField(t, received, "model", "gpt-5")
	assertJSONField(t, received, "protocol", "responses")
	if got := received["confidence"]; got != 0.91 {
		t.Fatalf("confidence = %#v, want 0.91", got)
	}
	if _, ok := received["evidence_json"].([]any); !ok {
		t.Fatalf("evidence_json should be JSON array, got %#v", received["evidence_json"])
	}
	if _, ok := received["tainted_arguments"].([]any); !ok {
		t.Fatalf("tainted_arguments should be JSON array, got %#v", received["tainted_arguments"])
	}
}

func TestMCPPolicyMissCarriesToolAssetID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/internal/mcp/effective-policy" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"matched":false,"tool_id":"mcpt-visible","mode":"audit","action":"audit"}`))
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, "secret")
	policy := client.GetMCPEffectivePolicy(context.Background(), &modelrouter.RequestEnvelope{TenantID: "tenant-1"}, "server-1", "tool-1")
	if policy.Matched || policy.ToolID != "mcpt-visible" {
		t.Fatalf("policy miss asset correlation = %#v", policy)
	}
}

func TestToolRiskClientCachesAgentGuardEffectivePolicyByScope(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/internal/agentguard/effective-policy" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if (func() string {
			if legacy := r.Header.Get("X-NewAPI-Internal-Token"); legacy != "" {
				t.Errorf("legacy internal token header must be absent")
			}
			return r.Header.Get("X-JJDGuard-Internal-Token")
		})() != "secret" {
			t.Fatalf("missing internal token")
		}
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"policy-1","name":"默认策略","policy_version":"v` + string(rune('0'+calls)) + `","mode":"strict","default_action":"audit","fail_policy":"closed","confirm_channel_enabled":true,"rules":[],"exceptions":[]}}`))
	}))
	defer server.Close()

	client := NewToolRiskClient(server.URL, "secret")
	client.agentGuardPolicyCache.ttl = 20 * time.Millisecond
	envelope := &modelrouter.RequestEnvelope{
		TenantID:  "tenant-1",
		ProjectID: "project-1",
		UserID:    "user-1",
		KeyPrefix: "sk-app",
		AgentType: "browser-agent",
		SessionID: "session-1",
	}

	first, err := client.GetAgentGuardPolicy(context.Background(), envelope)
	if err != nil {
		t.Fatalf("first GetAgentGuardPolicy: %v", err)
	}
	second, err := client.GetAgentGuardPolicy(context.Background(), envelope)
	if err != nil {
		t.Fatalf("second GetAgentGuardPolicy: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected same scope to use cache once, got %d calls", calls)
	}
	if first.PolicyVersion != "v1" || second.PolicyVersion != "v1" {
		t.Fatalf("expected cached v1 policy, got %q and %q", first.PolicyVersion, second.PolicyVersion)
	}

	otherScope := *envelope
	otherScope.SessionID = "session-2"
	if _, err := client.GetAgentGuardPolicy(context.Background(), &otherScope); err != nil {
		t.Fatalf("different-scope GetAgentGuardPolicy: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected different scope to bypass cache, got %d calls", calls)
	}

	time.Sleep(25 * time.Millisecond)
	refreshed, err := client.GetAgentGuardPolicy(context.Background(), envelope)
	if err != nil {
		t.Fatalf("expired GetAgentGuardPolicy: %v", err)
	}
	if calls != 3 || refreshed.PolicyVersion != "v3" {
		t.Fatalf("expected expired cache refresh to v3 with 3 calls, got version %q and %d calls", refreshed.PolicyVersion, calls)
	}
}

func TestToolRiskClientAgentGuardPolicyRefreshFallsBackToDeepCopiedStale(t *testing.T) {
	phase := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch phase {
		case 0:
			_, _ = w.Write([]byte(`{"data":{"id":"block","policy_version":"v1","mode":"strict","default_action":"allow","confirm_channel_enabled":true,"rules":[{"id":"rule-v1","tool_pattern":"*","action":"block","enabled":true}],"exceptions":[],"config_source":"tenant_policy","destructive":{"mode":"strict","action":"block","scope_type":"tenant"}}}`))
		case 1:
			http.Error(w, "temporary", http.StatusInternalServerError)
		case 2:
			_, _ = w.Write([]byte(`{"data":{"id":"alert","policy_version":"v2","mode":"light","default_action":"allow","confirm_channel_enabled":true,"rules":[],"exceptions":[],"config_source":"tenant_policy","destructive":{"mode":"light","action":"alert_allow","scope_type":"tenant"}}}`))
		}
	}))
	defer server.Close()

	client := NewToolRiskClient(server.URL, "test-value")
	client.agentGuardPolicyCache.ttl = 10 * time.Millisecond
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-1", ProjectID: "project-1"}
	first, err := client.GetAgentGuardPolicy(context.Background(), envelope)
	if err != nil || first == nil || first.PolicyVersion != "v1" {
		t.Fatalf("first policy=%#v err=%v", first, err)
	}
	first.ID = "caller-mutated"
	first.Destructive.Action = agentguard.DestructiveActionRecord
	first.Rules[0].ID = "caller-mutated"

	time.Sleep(15 * time.Millisecond)
	phase = 1
	stale, err := client.GetAgentGuardPolicy(context.Background(), envelope)
	if err != nil || stale == nil {
		t.Fatalf("stale policy=%#v err=%v", stale, err)
	}
	if stale.ID != "block" || stale.PolicyVersion != "v1" || stale.Destructive == nil ||
		stale.Destructive.Action != agentguard.DestructiveActionBlock || len(stale.Rules) != 1 || stale.Rules[0].ID != "rule-v1" {
		t.Fatalf("stale snapshot was mutated: %#v", stale)
	}
	stale.ID = "stale-caller-mutated"
	stale.Destructive.Action = agentguard.DestructiveActionRecord

	phase = 2
	recovered, err := client.GetAgentGuardPolicy(context.Background(), envelope)
	if err != nil || recovered == nil || recovered.ID != "alert" || recovered.PolicyVersion != "v2" ||
		recovered.Destructive == nil || recovered.Destructive.Action != agentguard.DestructiveActionAlertAllow {
		t.Fatalf("recovered policy=%#v err=%v", recovered, err)
	}
	recovered.ID = "recovered-caller-mutated"
	got, ok := client.agentGuardPolicyCache.get(agentGuardPolicyScopeCacheKey(envelope))
	if !ok || got.ID != "alert" || got.PolicyVersion != "v2" {
		t.Fatalf("recovery did not replace cache with a deep copy: %#v hit=%v", got, ok)
	}
}

func TestToolRiskClientConcurrentFailedRefreshUsesNewerFreshPolicy(t *testing.T) {
	aStarted := make(chan struct{})
	bStarted := make(chan struct{})
	releaseA := make(chan struct{})
	releaseB := make(chan struct{})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch calls.Add(1) {
		case 1:
			_, _ = w.Write([]byte(`{"data":{"id":"record","policy_version":"v1","mode":"audit","default_action":"allow","confirm_channel_enabled":true,"rules":[],"exceptions":[],"config_source":"tenant_policy","destructive":{"mode":"audit","action":"record","scope_type":"tenant"}}}`))
		case 2:
			close(aStarted)
			<-releaseA
			_, _ = w.Write([]byte(`{"data":{"id":"block","policy_version":"v2","mode":"strict","default_action":"allow","confirm_channel_enabled":true,"rules":[],"exceptions":[],"config_source":"tenant_policy","destructive":{"mode":"strict","action":"block","scope_type":"tenant"}}}`))
		case 3:
			close(bStarted)
			<-releaseB
			http.Error(w, "temporary", http.StatusInternalServerError)
		default:
			t.Errorf("unexpected refresh call %d", calls.Load())
		}
	}))
	defer server.Close()

	client := NewToolRiskClient(server.URL, "test-value")
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-concurrent", ProjectID: "project-1"}
	initial, err := client.GetAgentGuardPolicy(context.Background(), envelope)
	if err != nil || initial == nil || initial.Destructive == nil ||
		initial.Destructive.Action != agentguard.DestructiveActionRecord {
		t.Fatalf("initial=%#v err=%v", initial, err)
	}
	cacheKey := agentGuardPolicyScopeCacheKey(envelope)
	client.agentGuardPolicyCache.mu.Lock()
	client.agentGuardPolicyCache.entries[cacheKey].expiresAt = time.Now().Add(-time.Hour)
	client.agentGuardPolicyCache.mu.Unlock()

	type result struct {
		policy *agentguard.EffectivePolicy
		err    error
	}
	aResult := make(chan result, 1)
	bResult := make(chan result, 1)
	go func() {
		policy, refreshErr := client.GetAgentGuardPolicy(context.Background(), envelope)
		aResult <- result{policy: policy, err: refreshErr}
	}()
	<-aStarted
	go func() {
		policy, refreshErr := client.GetAgentGuardPolicy(context.Background(), envelope)
		bResult <- result{policy: policy, err: refreshErr}
	}()
	<-bStarted

	close(releaseA)
	a := <-aResult
	if a.err != nil || a.policy == nil || a.policy.Destructive == nil ||
		a.policy.Destructive.Action != agentguard.DestructiveActionBlock {
		t.Fatalf("A refresh=%#v err=%v", a.policy, a.err)
	}
	close(releaseB)
	b := <-bResult
	if b.err != nil || b.policy == nil || b.policy.Destructive == nil ||
		b.policy.Destructive.Action != agentguard.DestructiveActionBlock {
		t.Fatalf("B fallback must use A's newer block: policy=%#v err=%v", b.policy, b.err)
	}
	b.policy.ID = "caller-mutated"
	b.policy.Destructive.Action = agentguard.DestructiveActionRecord

	final, ok := client.agentGuardPolicyCache.get(cacheKey)
	if !ok || final == nil || final.ID != "block" || final.PolicyVersion != "v2" ||
		final.Destructive == nil || final.Destructive.Action != agentguard.DestructiveActionBlock {
		t.Fatalf("final cache=%#v hit=%v", final, ok)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestToolRiskClientCachesAgentGuardEmptyPolicy(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":null}`))
	}))
	defer server.Close()

	client := NewToolRiskClient(server.URL, "secret")
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-1", ProjectID: "project-1"}
	for i := 0; i < 2; i++ {
		policy, err := client.GetAgentGuardPolicy(context.Background(), envelope)
		if err != nil {
			t.Fatalf("GetAgentGuardPolicy %d: %v", i, err)
		}
		if policy != nil {
			t.Fatalf("expected nil policy, got %#v", policy)
		}
	}
	if calls != 1 {
		t.Fatalf("expected empty policy to be cached, got %d calls", calls)
	}
}

func assertJSONField(t *testing.T, values map[string]any, key string, want string) {
	t.Helper()
	if got := values[key]; got != want {
		t.Fatalf("%s = %#v, want %q", key, got, want)
	}
}

// 2.9.22：旧的 dlp.high_confidence_secret_egress 已由控制面折算进 protections 的
// agent.secret_egress，网关不再解析 dlp；带着旧键的策略照常转换，密钥外发只看 protections。
func TestConvertAgentGuardPolicyMapsBehaviorAndIgnoresLegacyDLP(t *testing.T) {
	var data agentGuardPolicyData
	if err := json.Unmarshal([]byte(`{"id":"agp_x","name":"strict","policy_version":"v1","mode":"strict","default_action":"audit","fail_policy":"fail_closed",`+
		`"behavior":{"file_read_burst_10s":50,"network_egress_burst_10s":50,"command_execute_burst_10s":20},`+
		`"dlp":{"high_confidence_secret_egress":"audit"},"protections":{"agent.secret_egress":{"action":"block","params":{}}}}`), &data); err != nil {
		t.Fatal(err)
	}
	policy := convertAgentGuardPolicy(&data)
	if policy == nil {
		t.Fatalf("convertAgentGuardPolicy returned nil")
	}
	if policy.Behavior == nil {
		t.Fatalf("expected behavior thresholds to be mapped, got nil")
	}
	if policy.Behavior.FileReadBurst != 50 || policy.Behavior.NetworkEgressBurst != 50 || policy.Behavior.CommandExecuteBurst != 20 {
		t.Fatalf("behavior thresholds mismatch: %#v", policy.Behavior)
	}
	if got := policy.Protections.ActionFor("agent.secret_egress"); got != protection.ActionBlock {
		t.Fatalf("secret egress must come from protections only, got %s", got)
	}
}

func TestToolRiskClientMapsAndCachesDestructivePolicyContract(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"data\":{\"id\":\"policy-destructive\",\"policy_version\":\"v7\",\"mode\":\"light\",\"default_action\":\"audit\",\"config_source\":\"application_policy\",\"destructive\":{\"mode\":\"light\",\"action\":\"block\",\"scope_type\":\"application\",\"scope_ref\":\"app-public\"}}}"))
	}))
	defer server.Close()

	client := NewToolRiskClient(server.URL, "secret")
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-1", ProjectID: "app-public"}
	first, err := client.GetAgentGuardPolicy(context.Background(), envelope)
	if err != nil {
		t.Fatalf("GetAgentGuardPolicy: %v", err)
	}
	second, err := client.GetAgentGuardPolicy(context.Background(), envelope)
	if err != nil {
		t.Fatalf("cached GetAgentGuardPolicy: %v", err)
	}
	if calls != 1 {
		t.Fatalf("destructive policy must share scope cache, calls=%d", calls)
	}
	if first.ConfigSource != agentguard.ConfigSourceApplicationPolicy || first.Destructive == nil {
		t.Fatalf("destructive contract not mapped: %#v", first)
	}
	if first.Destructive.Action != agentguard.DestructiveActionBlock || first.Destructive.ScopeRef != "app-public" {
		t.Fatalf("destructive policy fields mismatch: %#v", first.Destructive)
	}
	if second.Destructive == nil || second.Destructive.Action != agentguard.DestructiveActionBlock {
		t.Fatalf("cached destructive policy mismatch: %#v", second)
	}
}
func TestConvertAgentGuardPolicyValidatesDestructiveContract(t *testing.T) {
	tests := []struct {
		name        string
		mode        string
		source      string
		destructive *agentGuardDestructiveData
		wantMapped  bool
		wantAction  agentguard.DestructiveAction
		wantSource  agentguard.ConfigSource
	}{
		{"application light block override", "light", "application_policy", &agentGuardDestructiveData{Mode: "light", Action: "block", ScopeType: "application", ScopeRef: "app-public"}, true, agentguard.DestructiveActionBlock, agentguard.ConfigSourceApplicationPolicy},
		{"tenant strict alert override", "strict", "tenant_policy", &agentGuardDestructiveData{Mode: "strict", Action: "alert_allow", ScopeType: "tenant"}, true, agentguard.DestructiveActionAlertAllow, agentguard.ConfigSourceTenantPolicy},
		{"mode preset matches light", "light", "mode_preset", &agentGuardDestructiveData{Mode: "light", Action: "alert_allow"}, true, agentguard.DestructiveActionAlertAllow, agentguard.ConfigSourceModePreset},
		{"legacy audit record", "audit", "legacy_env_fallback", &agentGuardDestructiveData{Mode: "audit", Action: "record"}, true, agentguard.DestructiveActionRecord, agentguard.ConfigSourceLegacyEnvFallback},
		{"invalid light block mode preset", "light", "mode_preset", &agentGuardDestructiveData{Mode: "light", Action: "block"}, false, agentguard.DestructiveActionAlertAllow, agentguard.ConfigSourceModePreset},
		{"unknown source", "light", "unknown", &agentGuardDestructiveData{Mode: "light", Action: "block", ScopeType: "application", ScopeRef: "app-public"}, false, agentguard.DestructiveActionAlertAllow, agentguard.ConfigSourceModePreset},
		{"unknown action", "strict", "tenant_policy", &agentGuardDestructiveData{Mode: "strict", Action: "erase", ScopeType: "tenant"}, false, agentguard.DestructiveActionBlock, agentguard.ConfigSourceModePreset},
		{"application needs ref", "light", "application_policy", &agentGuardDestructiveData{Mode: "light", Action: "block", ScopeType: "application"}, false, agentguard.DestructiveActionAlertAllow, agentguard.ConfigSourceModePreset},
		{"agent scope must match", "strict", "agent_policy", &agentGuardDestructiveData{Mode: "strict", Action: "alert_allow", ScopeType: "application", ScopeRef: "agent-public"}, false, agentguard.DestructiveActionBlock, agentguard.ConfigSourceModePreset},
		{"tenant ref must be empty", "light", "tenant_policy", &agentGuardDestructiveData{Mode: "light", Action: "block", ScopeType: "tenant", ScopeRef: "foreign"}, false, agentguard.DestructiveActionAlertAllow, agentguard.ConfigSourceModePreset},
		{"legacy cannot block", "audit", "legacy_env_fallback", &agentGuardDestructiveData{Mode: "audit", Action: "block"}, false, agentguard.DestructiveActionRecord, agentguard.ConfigSourceModePreset},
		{"system cannot carry scope", "strict", "system_default", &agentGuardDestructiveData{Mode: "strict", Action: "alert_allow", ScopeType: "agent", ScopeRef: "agent-public"}, false, agentguard.DestructiveActionBlock, agentguard.ConfigSourceModePreset},
		{"old json without destructive fields", "strict", "", nil, false, agentguard.DestructiveActionBlock, agentguard.ConfigSourceModePreset},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := convertAgentGuardPolicy(&agentGuardPolicyData{
				Mode:         tt.mode,
				ConfigSource: tt.source,
				Destructive:  tt.destructive,
			})
			if (policy.Destructive != nil) != tt.wantMapped {
				t.Fatalf("mapped destructive = %#v, want mapped=%t", policy.Destructive, tt.wantMapped)
			}
			decision := agentguard.ApplyEffectivePolicy(
				agentguard.Decision{RawDecision: agentguard.DecisionConfirm},
				agentguard.PolicyEvaluationInput{
					RiskCategory:   agentguard.DestructiveRiskCategory,
					HighConfidence: true,
					Policy:         policy,
					// Protect posture: global audit-only would clamp every action to record.
					CallerMode: agentguard.ModeStrict,
				},
			)
			if decision.FinalAction != tt.wantAction || decision.ConfigSource != tt.wantSource {
				t.Fatalf("decision = %#v, want action=%q source=%q", decision, tt.wantAction, tt.wantSource)
			}
		})
	}
}
func TestAgentGuardPolicyCacheDeepCopiesMutablePolicy(t *testing.T) {
	cache := &agentGuardPolicyCache{
		entries: make(map[string]*agentGuardPolicyCacheEntry),
		ttl:     time.Minute,
	}
	original := &agentguard.EffectivePolicy{
		ID:            "policy-original",
		PolicyVersion: "v1",
		Mode:          agentguard.ModeLight,
		ConfigSource:  agentguard.ConfigSourceTenantPolicy,
		Destructive:   &agentguard.DestructivePolicy{Mode: agentguard.ModeLight, Action: agentguard.DestructiveActionBlock, ScopeType: "tenant"},
		Behavior:      &agentguard.BehaviorThresholds{FileReadBurst: 11, NetworkEgressBurst: 12, CommandExecuteBurst: 13},
		Protections:   protection.Settings{"agent.secret_egress": {Action: protection.ActionBlock}},
		Rules:         []agentguard.PolicyRule{{ID: "rule-original", Action: agentguard.DecisionBlock, Enabled: true}},
		Exceptions:    []agentguard.PolicyException{{ID: "exception-original", RuleID: "rule-original", Decision: agentguard.DecisionAudit}},
	}
	assertOriginal := func(label string, policy *agentguard.EffectivePolicy) {
		t.Helper()
		if policy == nil || policy.ID != "policy-original" || policy.PolicyVersion != "v1" || policy.Mode != agentguard.ModeLight {
			t.Fatalf("%s scalar policy mutated: %#v", label, policy)
		}
		if policy.Destructive == nil || policy.Destructive.Action != agentguard.DestructiveActionBlock {
			t.Fatalf("%s destructive mutated: %#v", label, policy.Destructive)
		}
		if policy.Behavior == nil || policy.Behavior.FileReadBurst != 11 || policy.Protections["agent.secret_egress"].Action != protection.ActionBlock {
			t.Fatalf("%s nested settings mutated: behavior=%#v protections=%#v", label, policy.Behavior, policy.Protections)
		}
		if len(policy.Rules) != 1 || policy.Rules[0].ID != "rule-original" || len(policy.Exceptions) != 1 || policy.Exceptions[0].RuleID != "rule-original" {
			t.Fatalf("%s slices mutated: rules=%#v exceptions=%#v", label, policy.Rules, policy.Exceptions)
		}
	}

	cache.set("tenant", original)
	original.ID = "caller-mutated"
	original.Destructive.Action = agentguard.DestructiveActionRecord
	original.Behavior.FileReadBurst = 99
	original.Protections["agent.secret_egress"] = protection.Setting{Action: protection.ActionRecord}
	original.Rules[0].ID = "caller-rule"
	original.Exceptions[0].RuleID = "caller-rule"

	first, ok := cache.get("tenant")
	if !ok {
		t.Fatal("expected cache hit")
	}
	assertOriginal("after set", first)
	first.PolicyVersion = "mutated-hit"
	first.Destructive.Action = agentguard.DestructiveActionConfirm
	first.Behavior.FileReadBurst = 88
	first.Protections["agent.secret_egress"] = protection.Setting{Action: protection.ActionAlertAllow}
	first.Rules[0].ID = "hit-rule"
	first.Exceptions[0].RuleID = "hit-rule"

	second, ok := cache.get("tenant")
	if !ok {
		t.Fatal("expected second cache hit")
	}
	assertOriginal("after get", second)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			policy, hit := cache.get("tenant")
			if !hit {
				t.Errorf("concurrent cache miss at %d", index)
				return
			}
			policy.PolicyVersion = "goroutine-mutated"
			policy.Destructive.Action = agentguard.DestructiveActionRecord
			policy.Rules[0].ID = "goroutine-rule"
		}(i)
	}
	wg.Wait()
	final, ok := cache.get("tenant")
	if !ok {
		t.Fatal("expected final cache hit")
	}
	assertOriginal("after concurrent gets", final)
}
func TestConvertAgentGuardPolicyRejectsSystemBlockWhenTopModeInvalid(t *testing.T) {
	policy := convertAgentGuardPolicy(&agentGuardPolicyData{
		Mode:         "garbage",
		ConfigSource: "system_default",
		Destructive:  &agentGuardDestructiveData{Mode: "strict", Action: "block"},
	})
	if policy.Mode != "" || policy.Destructive != nil || policy.ConfigSource != "" {
		t.Fatalf("invalid top mode must discard projected system block, got %#v", policy)
	}
	decision := agentguard.ApplyEffectivePolicy(
		agentguard.Decision{RawDecision: agentguard.DecisionBlock},
		agentguard.PolicyEvaluationInput{
			RiskCategory:   agentguard.DestructiveRiskCategory,
			HighConfidence: true,
			Policy:         policy,
			CallerMode:     agentguard.ModeStrict,
		},
	)
	if decision.Mode != agentguard.ModeAudit || decision.FinalAction != agentguard.DestructiveActionRecord ||
		decision.ConfigSource != agentguard.ConfigSourceSystemDefault || decision.NotificationRequired {
		t.Fatalf("invalid top mode must fall back to system audit/record, got %#v", decision)
	}
}

func TestConvertAgentGuardPolicyNormalizesWhitespaceMode(t *testing.T) {
	policy := convertAgentGuardPolicy(&agentGuardPolicyData{
		Mode:         " light ",
		ConfigSource: "tenant_policy",
		Destructive:  &agentGuardDestructiveData{Mode: " light ", Action: "block", ScopeType: "tenant"},
	})
	if policy.Mode != agentguard.ModeLight || policy.ConfigSource != agentguard.ConfigSourceTenantPolicy || policy.Destructive == nil {
		t.Fatalf("valid whitespace mode must be normalized in cached policy, got %#v", policy)
	}
	decision := agentguard.ApplyEffectivePolicy(
		agentguard.Decision{RawDecision: agentguard.DecisionConfirm},
		agentguard.PolicyEvaluationInput{
			RiskCategory:   agentguard.DestructiveRiskCategory,
			HighConfidence: true,
			Policy:         policy,
			CallerMode:     agentguard.ModeStrict,
		},
	)
	// decision.Mode reports the enforcement actually applied (block => strict).
	if decision.Mode != agentguard.ModeStrict || decision.FinalAction != agentguard.DestructiveActionBlock ||
		decision.ConfigSource != agentguard.ConfigSourceTenantPolicy {
		t.Fatalf("runtime mode/source must match normalized policy, got %#v", decision)
	}
}
