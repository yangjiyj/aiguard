package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type behaviorMCPRepo struct {
	policies  []*repository.MCPPolicy
	created   []*repository.MCPPolicy
	updated   []*repository.MCPPolicy
	listError error
}

func (f *behaviorMCPRepo) ListByTenant(_ context.Context, tenantID, _ string) ([]*repository.MCPPolicy, error) {
	if f.listError != nil {
		return nil, f.listError
	}
	var out []*repository.MCPPolicy
	for _, policy := range f.policies {
		if policy != nil && policy.TenantID == tenantID {
			out = append(out, policy)
		}
	}
	return out, nil
}

func (f *behaviorMCPRepo) Create(_ context.Context, policy *repository.MCPPolicy) error {
	policy.ID = "mcppol-created"
	policy.CreatedAt = time.Now().UTC()
	policy.UpdatedAt = policy.CreatedAt
	f.created = append(f.created, policy)
	f.policies = append(f.policies, policy)
	return nil
}

func (f *behaviorMCPRepo) Update(_ context.Context, policy *repository.MCPPolicy) error {
	for _, current := range f.policies {
		if current != nil && current.ID == policy.ID && current.TenantID == policy.TenantID {
			policy.CreatedAt = current.CreatedAt
			policy.UpdatedAt = time.Now().UTC()
			*current = *policy
			f.updated = append(f.updated, policy)
			return nil
		}
	}
	return errors.New("mcp policy not found")
}

func (f *behaviorMCPRepo) Delete(context.Context, string, string) error { return nil }

type behaviorAuditRepo struct {
	operations []*repository.AuditOperation
	settings   map[string]string
}

func (f *behaviorAuditRepo) Get(_ context.Context, key string) (*repository.SystemSetting, error) {
	if value, ok := f.settings[key]; ok {
		return &repository.SystemSetting{Key: key, Value: value}, nil
	}
	return nil, nil
}
func (f *behaviorAuditRepo) GetAll(context.Context) ([]*repository.SystemSetting, error) {
	return nil, nil
}
func (f *behaviorAuditRepo) Set(context.Context, string, string) error            { return nil }
func (f *behaviorAuditRepo) SetMultiple(context.Context, map[string]string) error { return nil }
func (f *behaviorAuditRepo) CreateAuditOperation(_ context.Context, op *repository.AuditOperation) error {
	f.operations = append(f.operations, op)
	return nil
}
func (f *behaviorAuditRepo) ListAuditOperations(context.Context, int, int, string) ([]*repository.AuditOperation, int, error) {
	return f.operations, len(f.operations), nil
}
func (f *behaviorAuditRepo) GetBool(context.Context, string) (bool, error) { return false, nil }

func withBehaviorUser(method, path, body string, user *repository.User) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
}

func behaviorRouteRequest(req *http.Request, key string) *http.Request {
	route := chi.NewRouteContext()
	route.URLParams.Add("key", key)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
}

func behaviorAgentGuardPolicy(tenantID, key, toolPattern, action string, updatedAt time.Time) *repository.AgentGuardPolicy {
	return &repository.AgentGuardPolicy{
		ID:            "policy-center-" + key,
		TenantID:      tenantID,
		Name:          "策略中心托管规则",
		ScopeType:     "tenant",
		Mode:          repository.AgentGuardModeAudit,
		DefaultAction: repository.AgentGuardActionAudit,
		FailPolicy:    repository.AgentGuardFailClosed,
		Enabled:       true,
		UpdatedAt:     updatedAt,
		RulesJSON: map[string]any{"rules": []any{
			map[string]any{"id": "policy-center-" + key, "tool_pattern": toolPattern, "action": action, "enabled": true},
			map[string]any{"id": "advanced-rule", "tool_pattern": toolPattern[:len(toolPattern)-2] + ".danger", "action": repository.AgentGuardActionAllow, "enabled": true, "secret": "do-not-return"},
		}},
	}
}

func behaviorDeps(tenantID string, destructive *repository.AgentOperationPolicy, agentPolicies []*repository.AgentGuardPolicy, mcpPolicies []*repository.MCPPolicy) (*Dependencies, *fakeAgentOperationRepo, *fakeAgentGuardPolicyRepo, *behaviorMCPRepo, *behaviorAuditRepo) {
	operationRepo := &fakeAgentOperationRepo{policy: destructive}
	agentRepo := newFakeAgentGuardPolicyRepo()
	for _, policy := range agentPolicies {
		agentRepo.policies[policy.ID] = policy
	}
	mcpRepo := &behaviorMCPRepo{policies: mcpPolicies}
	auditRepo := &behaviorAuditRepo{}
	deps := &Dependencies{
		AgentOperationRepo:     operationRepo,
		AgentGuardPolicyRepo:   agentRepo,
		AgentGuardBehaviorRepo: agentRepo,
		MCPPolicyRepo:          mcpRepo,
		SystemRepo:             auditRepo,
	}
	deps.PolicyCenterBehaviorRepo = &behaviorConditionalRepo{deps: deps}
	return deps, operationRepo, agentRepo, mcpRepo, auditRepo
}

type behaviorConditionalRepo struct {
	deps       *Dependencies
	beforeSave func()
	saved      repository.PolicyCenterAgentBehaviorMutation
}

func behaviorExpectedMatches(expected repository.PolicyCenterExpectedState, exists bool, current any) bool {
	if expected.ExpectedAbsent {
		return expected.ExpectedVersion == "" && !exists
	}
	return expected.ExpectedVersion != "" && exists && expected.ExpectedVersion == repository.PolicyCenterSnapshotVersion(current)
}

func (f *behaviorConditionalRepo) Save(ctx context.Context, mutation repository.PolicyCenterAgentBehaviorMutation) error {
	f.saved = mutation
	if f.beforeSave != nil {
		f.beforeSave()
	}
	if change := mutation.AgentGuard; change != nil {
		policies, err := f.deps.AgentGuardBehaviorRepo.ListPolicies(ctx, mutation.TenantID)
		if err != nil {
			return err
		}
		var current *repository.AgentGuardPolicy
		for _, policy := range policies {
			if policy.ID == change.ID {
				current = policy
			}
		}
		if change.ExpectedPoliciesVersion != repository.PolicyCenterAgentGuardPoliciesVersion(policies) || !behaviorExpectedMatches(change.Expected, current != nil, current) {
			return repository.ErrPolicyCenterBehaviorConflict
		}
	}
	if change := mutation.MCP; change != nil {
		policies, err := f.deps.MCPPolicyRepo.ListByTenant(ctx, mutation.TenantID, "")
		if err != nil {
			return err
		}
		var current *repository.MCPPolicy
		for _, policy := range policies {
			if policy.ID == change.ID {
				current = policy
			}
		}
		if change.ExpectedPoliciesVersion != repository.PolicyCenterMCPPoliciesVersion(policies) || !behaviorExpectedMatches(change.Expected, current != nil, current) {
			return repository.ErrPolicyCenterBehaviorConflict
		}
	}
	if change := mutation.Operation; change != nil {
		current, err := f.deps.AgentOperationRepo.GetPolicy(ctx, mutation.TenantID, change.ScopeType, change.ScopeRef)
		if err != nil && !errors.Is(err, repository.ErrAgentOperationNotFound) {
			return err
		}
		if !behaviorExpectedMatches(change.Expected, current != nil, current) || (current != nil && current.Version != change.ExpectedStorageVersion) {
			return repository.ErrPolicyCenterBehaviorConflict
		}
	}
	if change := mutation.AgentGuard; change != nil && change.Policy != nil {
		if change.Expected.ExpectedAbsent {
			_, _, err := f.deps.AgentGuardBehaviorRepo.CreatePolicyWithVersion(ctx, change.Policy, mutation.ActorID)
			if err != nil {
				return err
			}
		} else if _, _, _, err := f.deps.AgentGuardBehaviorRepo.UpdatePolicyWithVersion(ctx, change.Policy, mutation.ActorID); err != nil {
			return err
		}
	}
	if change := mutation.MCP; change != nil && change.Policy != nil {
		if change.Expected.ExpectedAbsent {
			if err := f.deps.MCPPolicyRepo.Create(ctx, change.Policy); err != nil {
				return err
			}
		} else if err := f.deps.MCPPolicyRepo.Update(ctx, change.Policy); err != nil {
			return err
		}
	}
	if change := mutation.Operation; change != nil && change.Mutation != nil {
		_, err := f.deps.AgentOperationRepo.SavePolicy(ctx, *change.Mutation)
		return err
	}
	return nil
}

func TestPolicyCenterAgentBehaviorsGetReturnsSixSafeProjections(t *testing.T) {
	now := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	agentPolicies := []*repository.AgentGuardPolicy{
		behaviorAgentGuardPolicy("tenant-a", "system_command", "system.*", repository.AgentGuardActionBlock, now),
		behaviorAgentGuardPolicy("tenant-a", "sensitive_resource", "file.*", repository.AgentGuardActionAudit, now),
		behaviorAgentGuardPolicy("tenant-a", "network_egress", "network.*", repository.AgentGuardActionAllow, now),
		behaviorAgentGuardPolicy("tenant-a", "database_change", "database.*", repository.AgentGuardActionBlock, now),
	}
	deps, _, _, _, _ := behaviorDeps("tenant-a", &repository.AgentOperationPolicy{
		ScopeType: "tenant", Mode: "audit", Action: "alert_allow", CurrentAction: "alert_allow", Version: 3, UpdatedAt: now,
	}, agentPolicies, []*repository.MCPPolicy{
		{ID: "mcp-wildcard", TenantID: "tenant-a", ScopeType: "tenant", ServerID: "", ToolPattern: "*", DefaultAction: repository.AgentGuardActionBlock, Enabled: true, UpdatedAt: now},
		{ID: "mcp-specific", TenantID: "tenant-a", ScopeType: "tenant", ServerID: "server-a", ToolPattern: "danger.*", DefaultAction: repository.AgentGuardActionAllow, Enabled: true, UpdatedAt: now},
	})

	rec := httptest.NewRecorder()
	GetPolicyCenterAgentBehaviors(deps).ServeHTTP(rec, withBehaviorUser(http.MethodGet, "/admin/v1/policy-center/agent-behaviors", "", &repository.User{ID: "u1", TenantID: "tenant-a", Role: "auditor"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Items) != 6 {
		t.Fatalf("items=%d want 6", len(response.Items))
	}
	keys := make(map[string]bool)
	for _, item := range response.Items {
		key, _ := item["key"].(string)
		keys[key] = true
		if _, ok := item["tenant_id"]; ok {
			t.Fatalf("tenant id leaked: %#v", item)
		}
	}
	for _, forbidden := range []string{"policy_id", "rules_json", "tool_pattern", "secret", "mcp-wildcard"} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Fatalf("internal field %q leaked: %s", forbidden, rec.Body.String())
		}
	}
	for _, key := range []string{"destructive_operation", "system_command", "sensitive_resource", "network_egress", "database_change", "external_tool"} {
		if !keys[key] {
			t.Fatalf("missing behavior %q", key)
		}
	}
}

func TestPolicyCenterAgentBehaviorsPutPreservesDestructivePolicyDetails(t *testing.T) {
	now := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
	policy := &repository.AgentOperationPolicy{
		ScopeType:        "tenant",
		Mode:             "light",
		Action:           "record",
		DiscardablePaths: []string{"dist", "tmp"},
		NotifyChannelIDs: []string{"channel-a"},
		Version:          2,
		UpdatedAt:        now,
	}
	deps, operationRepo, _, _, _ := behaviorDeps("tenant-a", policy, nil, nil)
	user := &repository.User{ID: "admin-1", TenantID: "tenant-a", Role: "platform_admin"}

	getRec := httptest.NewRecorder()
	GetPolicyCenterAgentBehaviors(deps).ServeHTTP(getRec, withBehaviorUser(http.MethodGet, "/admin/v1/policy-center/agent-behaviors", "", user))
	var snapshot struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	var version string
	for _, item := range snapshot.Items {
		if item["key"] == "destructive_operation" {
			version, _ = item["version"].(string)
		}
	}
	if version == "" {
		t.Fatal("missing opaque version")
	}

	req := behaviorRouteRequest(withBehaviorUser(
		http.MethodPut,
		"/admin/v1/policy-center/agent-behaviors/destructive_operation",
		`{"action":"block","version":"`+version+`"}`,
		user,
	), "destructive_operation")
	rec := httptest.NewRecorder()
	PutPolicyCenterAgentBehavior(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Join(operationRepo.saved.DiscardablePaths, ",") != "dist,tmp" {
		t.Fatalf("discardable paths=%v", operationRepo.saved.DiscardablePaths)
	}
	if strings.Join(operationRepo.saved.NotifyChannelIDs, ",") != "channel-a" {
		t.Fatalf("notify channel ids=%v", operationRepo.saved.NotifyChannelIDs)
	}
}

func TestPolicyCenterAgentBehaviorsPutUpdatesOnlyManagedRuleAndKeepsAdvancedRule(t *testing.T) {
	now := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	managed := behaviorAgentGuardPolicy("tenant-a", "system_command", "system.*", repository.AgentGuardActionAllow, now)
	deps, _, agentRepo, _, auditRepo := behaviorDeps("tenant-a", &repository.AgentOperationPolicy{ScopeType: "tenant", Mode: "audit", Action: "record", Version: 1, UpdatedAt: now}, []*repository.AgentGuardPolicy{managed}, nil)
	user := &repository.User{ID: "admin-1", TenantID: "tenant-a", Role: "platform_admin"}

	getRec := httptest.NewRecorder()
	GetPolicyCenterAgentBehaviors(deps).ServeHTTP(getRec, withBehaviorUser(http.MethodGet, "/admin/v1/policy-center/agent-behaviors", "", user))
	var snapshot struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	var version string
	for _, item := range snapshot.Items {
		if item["key"] == "system_command" {
			version, _ = item["version"].(string)
		}
	}
	if version == "" {
		t.Fatal("missing opaque version")
	}

	body := `{"action":"alert_allow","version":"` + version + `"}`
	req := behaviorRouteRequest(withBehaviorUser(http.MethodPut, "/admin/v1/policy-center/agent-behaviors/system_command", body, user), "system_command")
	rec := httptest.NewRecorder()
	PutPolicyCenterAgentBehavior(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	updated := agentRepo.policies[managed.ID]
	rules := policyCenterAgentGuardRules(updated)
	if len(rules) != 2 {
		t.Fatalf("rules=%#v", updated.RulesJSON)
	}
	if rules[0]["action"] != repository.AgentGuardActionAudit {
		t.Fatalf("managed action=%v", rules[0]["action"])
	}
	if rules[1]["secret"] != "do-not-return" {
		t.Fatalf("advanced rule was not preserved: %#v", rules[1])
	}
	if len(auditRepo.operations) != 1 || strings.Contains(string(mustJSON(t, auditRepo.operations[0].ActionDetail)), "rules_json") {
		t.Fatalf("unsafe audit detail: %#v", auditRepo.operations)
	}
}

func TestPolicyCenterAgentBehaviorsRejectsStaleVersionAndInvalidInput(t *testing.T) {
	now := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	managed := behaviorAgentGuardPolicy("tenant-a", "network_egress", "network.*", repository.AgentGuardActionAllow, now)
	deps, _, _, _, _ := behaviorDeps("tenant-a", nil, []*repository.AgentGuardPolicy{managed}, nil)
	user := &repository.User{ID: "admin-1", TenantID: "tenant-a", Role: "platform_admin"}
	getRec := httptest.NewRecorder()
	GetPolicyCenterAgentBehaviors(deps).ServeHTTP(getRec, withBehaviorUser(http.MethodGet, "/admin/v1/policy-center/agent-behaviors", "", user))
	var snapshot struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	var version string
	for _, item := range snapshot.Items {
		if item["key"] == "network_egress" {
			version, _ = item["version"].(string)
		}
	}
	managed.UpdatedAt = now.Add(time.Minute)
	stale := behaviorRouteRequest(withBehaviorUser(http.MethodPut, "/admin/v1/policy-center/agent-behaviors/network_egress", `{"action":"block","version":"`+version+`"}`, user), "network_egress")
	staleRec := httptest.NewRecorder()
	PutPolicyCenterAgentBehavior(deps).ServeHTTP(staleRec, stale)
	if staleRec.Code != http.StatusConflict {
		t.Fatalf("stale status=%d body=%s", staleRec.Code, staleRec.Body.String())
	}

	for _, testCase := range []struct {
		name string
		key  string
		body string
		want int
	}{
		{"unknown key", "unknown", `{"action":"block","version":"x"}`, http.StatusNotFound},
		{"unknown action", "network_egress", `{"action":"confirm","version":"x"}`, http.StatusBadRequest},
		{"unknown field", "network_egress", `{"action":"block","version":"x","tenant_id":"tenant-b"}`, http.StatusBadRequest},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			req := behaviorRouteRequest(withBehaviorUser(http.MethodPut, "/admin/v1/policy-center/agent-behaviors/"+testCase.key, testCase.body, user), testCase.key)
			rec := httptest.NewRecorder()
			PutPolicyCenterAgentBehavior(deps).ServeHTTP(rec, req)
			if rec.Code != testCase.want {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPolicyCenterAgentBehaviorStringValueReturnsEmptyForNonString(t *testing.T) {
	if got := stringValue(123); got != "" {
		t.Fatalf("stringValue(non-string)=%q, want empty", got)
	}
}

func TestPolicyCenterAgentBehaviorsRejectsOversizedJSONBody(t *testing.T) {
	deps, _, _, _, _ := behaviorDeps("tenant-a", nil, nil, nil)
	user := &repository.User{ID: "admin-1", TenantID: "tenant-a", Role: "platform_admin"}
	body := "{\"action\":\"block\",\"version\":\"" + strings.Repeat("v", 17<<10) + "\"}"
	req := behaviorRouteRequest(withBehaviorUser(
		http.MethodPut,
		"/admin/v1/policy-center/agent-behaviors/system_command",
		body,
		user,
	), "system_command")
	rec := httptest.NewRecorder()

	PutPolicyCenterAgentBehavior(deps).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPolicyCenterAgentBehaviorsKeepsMCPHealthyWhenAgentGuardReadFails(t *testing.T) {
	deps, _, _, _, _ := behaviorDeps("tenant-a", nil, nil, []*repository.MCPPolicy{{
		ID: "mcp-wildcard", TenantID: "tenant-a", ScopeType: "tenant", ToolPattern: "*", DefaultAction: repository.AgentGuardActionAudit, Enabled: true,
	}})
	deps.AgentGuardBehaviorRepo = &errorAgentGuardBehaviorRepo{}
	rec := httptest.NewRecorder()
	GetPolicyCenterAgentBehaviors(deps).ServeHTTP(rec, withBehaviorUser(http.MethodGet, "/admin/v1/policy-center/agent-behaviors", "", &repository.User{ID: "u1", TenantID: "tenant-a", Role: "auditor"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	for _, item := range response.Items {
		health, _ := item["health"].(string)
		key, _ := item["key"].(string)
		if strings.HasPrefix(key, "system") || strings.HasPrefix(key, "sensitive") || strings.HasPrefix(key, "network") || strings.HasPrefix(key, "database") {
			if health != "error" {
				t.Fatalf("%s health=%q want error", key, health)
			}
		}
		if key == "external_tool" && health == "error" {
			t.Fatalf("MCP health should be independent: %#v", item)
		}
	}
}

type errorAgentGuardBehaviorRepo struct{}

func (*errorAgentGuardBehaviorRepo) ListPolicies(context.Context, string) ([]*repository.AgentGuardPolicy, error) {
	return nil, errors.New("agentguard unavailable")
}

func (*errorAgentGuardBehaviorRepo) CreatePolicyWithVersion(context.Context, *repository.AgentGuardPolicy, string) (*repository.AgentGuardPolicy, *repository.AgentGuardPolicyVersion, error) {
	return nil, nil, errors.New("agentguard unavailable")
}

func (*errorAgentGuardBehaviorRepo) UpdatePolicyWithVersion(context.Context, *repository.AgentGuardPolicy, string) (*repository.AgentGuardPolicy, *repository.AgentGuardPolicyVersion, bool, error) {
	return nil, nil, false, errors.New("agentguard unavailable")
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The MCP policy's own mode caps its action at runtime; the policy center must
// report that, and saving "阻断" must use strict mode so the gateway enforces it.
func TestPolicyCenterMCPBehaviorReportsModeCapAndSavesStrictForBlock(t *testing.T) {
	deps, _, _, mcpRepo, auditRepo := behaviorDeps("tenant-a", nil, nil, []*repository.MCPPolicy{{
		ID: "mcp-wildcard", TenantID: "tenant-a", ScopeType: "tenant", ToolPattern: "*",
		Mode: repository.AgentGuardModeAudit, DefaultAction: repository.AgentGuardActionBlock, Enabled: true,
		Note: "policy-center:external_tool",
	}})
	// Global protect mode, so only the per-policy audit mode caps block to alert.
	// Without a stored mode the control plane fails safe to record.
	auditRepo.settings = map[string]string{"security_execution_mode": "protect"}
	admin := &repository.User{ID: "admin", TenantID: "tenant-a", Role: "platform_admin"}
	read := func() map[string]any {
		rec := httptest.NewRecorder()
		GetPolicyCenterAgentBehaviors(deps).ServeHTTP(rec, withBehaviorUser(http.MethodGet, "/admin/v1/policy-center/agent-behaviors", "", admin))
		var response struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		for _, item := range response.Items {
			if item["key"] == "external_tool" {
				return item
			}
		}
		t.Fatalf("external_tool missing: %s", rec.Body.String())
		return nil
	}
	item := read()
	if item["configured_action"] != "block" || item["current_action"] != "alert_allow" {
		t.Fatalf("audit-mode block must be reported as alert: %#v", item)
	}
	body := `{"action":"block","version":"` + item["version"].(string) + `"}`
	rec := httptest.NewRecorder()
	PutPolicyCenterAgentBehavior(deps).ServeHTTP(rec, behaviorRouteRequest(withBehaviorUser(http.MethodPut, "/admin/v1/policy-center/agent-behaviors/external_tool", body, admin), "external_tool"))
	if rec.Code != http.StatusOK {
		t.Fatalf("save status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(mcpRepo.updated) != 1 || mcpRepo.updated[0].Mode != repository.AgentGuardModeStrict {
		t.Fatalf("block must be saved in strict mode: %#v", mcpRepo.updated)
	}
	if item := read(); item["current_action"] != "block" {
		t.Fatalf("after saving, block must be enforced: %#v", item)
	}
}

func TestNormalizeBlockNoticeSettings(t *testing.T) {
	settings := map[string]string{
		"security_block_response_mode":   " Message ",
		"security_block_notice_template": "编号 {block_id}\r\n规则 {rule}",
	}
	if err := normalizeBlockNoticeSettings(settings); err != nil {
		t.Fatal(err)
	}
	if settings["security_block_response_mode"] != "message" || settings["security_block_notice_template"] != "编号 {block_id}\n规则 {rule}" {
		t.Fatalf("normalized = %#v", settings)
	}
	for _, bad := range []map[string]string{
		{"security_block_response_mode": "silent"},
		{"security_block_notice_template": "泄露 {password}"},
		{"security_block_notice_template": strings.Repeat("长", maxBlockNoticeTemplateRunes+1)},
	} {
		if err := normalizeBlockNoticeSettings(bad); err == nil {
			t.Fatalf("invalid settings accepted: %#v", bad)
		}
	}
}

func (f *behaviorAuditRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, f.Get, keys)
}
