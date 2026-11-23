package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// sensitiveResourcePut  helper：先 GET 拿 version，再 PUT sensitive_resource。
func sensitiveResourcePut(t *testing.T, deps *Dependencies, user *repository.User, body string) *httptest.ResponseRecorder {
	t.Helper()
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
		if item["key"] == "sensitive_resource" {
			version, _ = item["version"].(string)
		}
	}
	if version == "" {
		t.Fatal("missing sensitive_resource version")
	}
	full := strings.Replace(body, `"__VERSION__"`, `"`+version+`"`, 1)
	req := behaviorRouteRequest(withBehaviorUser(http.MethodPut, "/admin/v1/policy-center/agent-behaviors/sensitive_resource", full, user), "sensitive_resource")
	rec := httptest.NewRecorder()
	PutPolicyCenterAgentBehavior(deps).ServeHTTP(rec, req)
	return rec
}

// 写入→读回：受限文件模式与动作落库并经 customerProjection 返回。
func TestPolicyCenterSensitiveResourceRestrictedFilesRoundTrip(t *testing.T) {
	now := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	agentPolicy := behaviorAgentGuardPolicy("tenant-a", "sensitive_resource", "file.*", repository.AgentGuardActionAllow, now)
	destructive := &repository.AgentOperationPolicy{
		ScopeType: "tenant", Mode: "audit", Action: "record", Version: 1,
		DiscardablePaths: []string{"dist", "tmp"}, NotifyChannelIDs: []string{"channel-a"}, UpdatedAt: now,
	}
	deps, _, _, _, _ := behaviorDeps("tenant-a", destructive, []*repository.AgentGuardPolicy{agentPolicy}, nil)
	operationRepo := &consistencyOperationRepo{fakeAgentOperationRepo: fakeAgentOperationRepo{policy: destructive}}
	deps.AgentOperationRepo = operationRepo
	user := &repository.User{ID: "admin-1", TenantID: "tenant-a", Role: "platform_admin"}

	rec := sensitiveResourcePut(t, deps, user, `{"action":"record","version":"__VERSION__","restricted_file_patterns":["*.pdf","*.docx"],"restricted_file_action":"block"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Join(operationRepo.saved.RestrictedFilePatterns, ",") != "*.pdf,*.docx" {
		t.Fatalf("restricted patterns=%v", operationRepo.saved.RestrictedFilePatterns)
	}
	if operationRepo.saved.RestrictedFileAction != "block" {
		t.Fatalf("restricted action=%q", operationRepo.saved.RestrictedFileAction)
	}
	// 回归：受限文件保存回填 discardable_paths 与破坏性动作，不得清空
	if strings.Join(operationRepo.saved.DiscardablePaths, ",") != "dist,tmp" {
		t.Fatalf("discardable paths cleared: %v", operationRepo.saved.DiscardablePaths)
	}
	if strings.Join(operationRepo.saved.NotifyChannelIDs, ",") != "channel-a" {
		t.Fatalf("notify channels cleared: %v", operationRepo.saved.NotifyChannelIDs)
	}
	if operationRepo.saved.Action != "record" || operationRepo.saved.Mode != "audit" {
		t.Fatalf("destructive action/mode changed: %+v", operationRepo.saved)
	}

	var proj map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &proj); err != nil {
		t.Fatal(err)
	}
	patterns, ok := proj["restricted_file_patterns"].([]any)
	if !ok || len(patterns) != 2 || patterns[0] != "*.pdf" || patterns[1] != "*.docx" {
		t.Fatalf("projection restricted_file_patterns=%v", proj)
	}
	if proj["restricted_file_action"] != "block" {
		t.Fatalf("projection restricted_file_action=%v", proj)
	}
	// 2.9.22 批次 2B：不再有“内置，不可关闭”的敏感文件（它们是可配置的防护项），删掉
	// builtin_patterns_summary；原断言要求这个字段存在。作用范围默认三项全选。
	if _, present := proj["builtin_patterns_summary"]; present {
		t.Fatalf("builtin summary must be gone: %v", proj)
	}
	scopes, _ := proj["restricted_file_scopes"].([]any)
	if len(scopes) != 3 || scopes[0] != "tool_call" || scopes[1] != "user_mention" || scopes[2] != "proxy_output" {
		t.Fatalf("default restricted_file_scopes=%v", proj["restricted_file_scopes"])
	}
}

// 受限文件作用范围：多选、可清空、只认三个取值；单改作用范围不动动作和模式。
func TestPolicyCenterRestrictedFileScopes(t *testing.T) {
	now := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, scopes string
		wantStatus   int
		want         []string
	}{
		{"tool call only", `["tool_call"]`, http.StatusOK, []string{"tool_call"}},
		{"none", `[]`, http.StatusOK, []string{}},
		{"unknown value", `["model_input"]`, http.StatusBadRequest, nil},
		{"repeated value", `["tool_call","tool_call"]`, http.StatusBadRequest, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agentPolicy := behaviorAgentGuardPolicy("tenant-a", "sensitive_resource", "file.*", repository.AgentGuardActionAllow, now)
			destructive := &repository.AgentOperationPolicy{
				ScopeType: "tenant", Mode: "audit", Action: "alert_allow", Version: 2,
				RestrictedFilePatterns: []string{"*.pdf"}, RestrictedFileAction: "block",
				RestrictedFileScopes: repository.DefaultRestrictedFileScopes(), UpdatedAt: now,
			}
			deps, _, _, _, _ := behaviorDeps("tenant-a", destructive, []*repository.AgentGuardPolicy{agentPolicy}, nil)
			operationRepo := &consistencyOperationRepo{fakeAgentOperationRepo: fakeAgentOperationRepo{policy: destructive}}
			deps.AgentOperationRepo = operationRepo
			user := &repository.User{ID: "admin-1", TenantID: "tenant-a", Role: "security_officer"}
			rec := sensitiveResourcePut(t, deps, user, `{"action":"record","version":"__VERSION__","restricted_file_scopes":`+tc.scopes+`}`)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if tc.wantStatus != http.StatusOK {
				return
			}
			if strings.Join(operationRepo.saved.RestrictedFileScopes, ",") != strings.Join(tc.want, ",") || operationRepo.saved.RestrictedFileScopes == nil {
				t.Fatalf("saved scopes=%#v", operationRepo.saved.RestrictedFileScopes)
			}
			if operationRepo.saved.Action != "alert_allow" || operationRepo.saved.RestrictedFileAction != "block" ||
				strings.Join(operationRepo.saved.RestrictedFilePatterns, ",") != "*.pdf" {
				t.Fatalf("scope-only change must keep the other fields: %+v", operationRepo.saved)
			}
		})
	}
}

// 带字段打非 sensitive_resource 键 → 400 restricted_file_fields_not_supported。
func TestPolicyCenterRestrictedFieldsRejectedOnOtherKeys(t *testing.T) {
	now := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	managed := behaviorAgentGuardPolicy("tenant-a", "system_command", "system.*", repository.AgentGuardActionAllow, now)
	deps, _, _, _, _ := behaviorDeps("tenant-a", &repository.AgentOperationPolicy{ScopeType: "tenant", Mode: "audit", Action: "record", Version: 1, UpdatedAt: now}, []*repository.AgentGuardPolicy{managed}, nil)
	user := &repository.User{ID: "admin-1", TenantID: "tenant-a", Role: "platform_admin"}

	getRec := httptest.NewRecorder()
	GetPolicyCenterAgentBehaviors(deps).ServeHTTP(getRec, withBehaviorUser(http.MethodGet, "/admin/v1/policy-center/agent-behaviors", "", user))
	var snapshot struct {
		Items []map[string]any `json:"items"`
	}
	_ = json.Unmarshal(getRec.Body.Bytes(), &snapshot)
	var version string
	for _, item := range snapshot.Items {
		if item["key"] == "system_command" {
			version, _ = item["version"].(string)
		}
	}
	body := `{"action":"block","version":"` + version + `","restricted_file_patterns":["*.pdf"]}`
	req := behaviorRouteRequest(withBehaviorUser(http.MethodPut, "/admin/v1/policy-center/agent-behaviors/system_command", body, user), "system_command")
	rec := httptest.NewRecorder()
	PutPolicyCenterAgentBehavior(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "restricted_file_fields_not_supported") {
		t.Fatalf("expected restricted_file_fields_not_supported, got %s", rec.Body.String())
	}
}

// 只改 patterns 不改 action：AgentGuard 规则动作与破坏性动作都不变。
func TestPolicyCenterRestrictedPatternsOnlyKeepsActions(t *testing.T) {
	now := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	agentPolicy := behaviorAgentGuardPolicy("tenant-a", "sensitive_resource", "file.*", repository.AgentGuardActionAllow, now)
	destructive := &repository.AgentOperationPolicy{
		ScopeType: "tenant", Mode: "audit", Action: "alert_allow", Version: 3,
		RestrictedFilePatterns: []string{"*.pdf"}, RestrictedFileAction: "record",
		DiscardablePaths: []string{"dist"}, UpdatedAt: now,
	}
	deps, operationRepo, agentRepo, _, _ := behaviorDeps("tenant-a", destructive, []*repository.AgentGuardPolicy{agentPolicy}, nil)
	user := &repository.User{ID: "admin-1", TenantID: "tenant-a", Role: "platform_admin"}

	rec := sensitiveResourcePut(t, deps, user, `{"action":"record","version":"__VERSION__","restricted_file_patterns":["*.pdf","*.xlsx"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	// 受限文件保存回填破坏性动作，保持现值 alert_allow 不变
	if operationRepo.saved.Action != "alert_allow" {
		t.Fatalf("destructive action changed: %q", operationRepo.saved.Action)
	}
	// restricted_file_action 未携带 → 保留现值 record
	if operationRepo.saved.RestrictedFileAction != "record" {
		t.Fatalf("restricted action should keep current value, got %q", operationRepo.saved.RestrictedFileAction)
	}
	updated := agentRepo.policies[agentPolicy.ID]
	rules := policyCenterAgentGuardRules(updated)
	if agentRepo.atomicUpdateCalls != 0 || agentRepo.atomicCreateCalls != 0 {
		t.Fatalf("restricted-only wrote AgentGuard: updates=%d creates=%d", agentRepo.atomicUpdateCalls, agentRepo.atomicCreateCalls)
	}
	if len(rules) == 0 || rules[0]["action"] != repository.AgentGuardActionAllow {
		t.Fatalf("agentguard rule action unexpected: %#v", rules)
	}
}

// 非法模式 → 400，错误信息来自 filerestrict.Validate。
func TestPolicyCenterRestrictedInvalidPattern(t *testing.T) {
	now := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	agentPolicy := behaviorAgentGuardPolicy("tenant-a", "sensitive_resource", "file.*", repository.AgentGuardActionAllow, now)
	deps, _, _, _, _ := behaviorDeps("tenant-a", &repository.AgentOperationPolicy{ScopeType: "tenant", Mode: "audit", Action: "record", Version: 1, UpdatedAt: now}, []*repository.AgentGuardPolicy{agentPolicy}, nil)
	user := &repository.User{ID: "admin-1", TenantID: "tenant-a", Role: "platform_admin"}

	rec := sensitiveResourcePut(t, deps, user, `{"action":"block","version":"__VERSION__","restricted_file_patterns":["http://x.com/a.pdf"],"restricted_file_action":"block"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "URL") {
		t.Fatalf("expected filerestrict validate message, got %s", rec.Body.String())
	}
}
