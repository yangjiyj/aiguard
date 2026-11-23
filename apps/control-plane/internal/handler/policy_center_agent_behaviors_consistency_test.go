package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type consistencyOperationRepo struct {
	fakeAgentOperationRepo
	getError   error
	saveError  error
	getCalls   int
	saveCalls  int
	beforeSave func()
	afterSave  func()
}

func (f *consistencyOperationRepo) GetPolicy(ctx context.Context, tenantID, scopeType, scopeRef string) (*repository.AgentOperationPolicy, error) {
	f.getCalls++
	if f.getError != nil {
		return nil, f.getError
	}
	current, err := f.fakeAgentOperationRepo.GetPolicy(ctx, tenantID, scopeType, scopeRef)
	if current == nil || err != nil {
		return current, err
	}
	clone := *current
	clone.DiscardablePaths = append([]string(nil), current.DiscardablePaths...)
	clone.NotifyChannelIDs = append([]string(nil), current.NotifyChannelIDs...)
	clone.RestrictedFilePatterns = append([]string(nil), current.RestrictedFilePatterns...)
	return &clone, nil
}

func (f *consistencyOperationRepo) SavePolicy(_ context.Context, mutation repository.AgentOperationPolicyMutation) (*repository.AgentOperationPolicy, error) {
	f.saveCalls++
	f.saved = mutation
	if f.beforeSave != nil {
		f.beforeSave()
	}
	if f.saveError != nil {
		return nil, f.saveError
	}
	if f.policy != nil && f.policy.Version != mutation.ExpectedVersion {
		return nil, repository.ErrAgentOperationConflict
	}
	if f.policy == nil && mutation.ExpectedVersion != 1 {
		return nil, repository.ErrAgentOperationConflict
	}
	nextVersion := int64(1)
	if f.policy != nil {
		nextVersion = f.policy.Version + 1
	}
	f.policy = &repository.AgentOperationPolicy{
		ScopeType: mutation.ScopeType, ScopeRef: mutation.ScopeRef,
		Mode: mutation.Mode, Action: mutation.Action, Protocol: mutation.Protocol,
		DiscardablePaths:       append([]string(nil), mutation.DiscardablePaths...),
		NotifyChannelIDs:       append([]string(nil), mutation.NotifyChannelIDs...),
		RestrictedFilePatterns: append([]string(nil), mutation.RestrictedFilePatterns...),
		RestrictedFileAction:   mutation.RestrictedFileAction,
		Version:                nextVersion, UpdatedBy: mutation.ActorID, UpdatedAt: time.Now().UTC(),
	}
	if f.policy.RestrictedFileAction == "" {
		f.policy.RestrictedFileAction = "block"
	}
	if f.afterSave != nil {
		f.afterSave()
	}
	return f.policy, nil
}

func consistencyBehaviorItem(t *testing.T, deps *Dependencies, user *repository.User, key string) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	GetPolicyCenterAgentBehaviors(deps)(rec, withBehaviorUser(http.MethodGet, "/x", "", user))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	for _, item := range response.Items {
		if item["key"] == key {
			return item
		}
	}
	t.Fatalf("missing behavior %q: %s", key, rec.Body.String())
	return nil
}

func consistencyPut(t *testing.T, deps *Dependencies, user *repository.User, key string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	PutPolicyCenterAgentBehavior(deps)(rec, behaviorRouteRequest(withBehaviorUser(http.MethodPut, "/x", string(mustJSON(t, body)), user), key))
	return rec
}

func consistencySensitiveFixture() (*Dependencies, *consistencyOperationRepo, *fakeAgentGuardPolicyRepo, *repository.User) {
	now := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	guard := behaviorAgentGuardPolicy("tenant-a", policyCenterAgentBehaviorFile, "file.*", repository.AgentGuardActionAudit, now)
	policyCenterAgentGuardRules(guard)[0][policyCenterRuleActionKey] = "record"
	operation := &repository.AgentOperationPolicy{
		ScopeType: "tenant", Mode: "light", Action: "alert_allow", Protocol: "mcp", Version: 7,
		DiscardablePaths: []string{"dist", "tmp"}, NotifyChannelIDs: []string{"channel-a"},
		RestrictedFilePatterns: []string{"contracts/**", "*.pdf"}, RestrictedFileAction: "alert_allow", UpdatedAt: now,
	}
	deps, _, agentRepo, _, auditRepo := behaviorDeps("tenant-a", operation, []*repository.AgentGuardPolicy{guard}, nil)
	operationRepo := &consistencyOperationRepo{fakeAgentOperationRepo: fakeAgentOperationRepo{policy: operation}}
	deps.AgentOperationRepo = operationRepo
	auditRepo.settings = map[string]string{"security_execution_mode": "protect"}
	return deps, operationRepo, agentRepo, &repository.User{ID: "admin-1", TenantID: "tenant-a", Role: "platform_admin"}
}

func TestPolicyCenterSensitiveResourceGetReturnsStoredRestrictedFiles(t *testing.T) {
	for _, variant := range []string{"configured", "missing_guard", "merged_missing_category"} {
		t.Run(variant, func(t *testing.T) {
			deps, operationRepo, agentRepo, user := consistencySensitiveFixture()
			if variant != "configured" {
				agentRepo.policies = map[string]*repository.AgentGuardPolicy{}
			}
			if variant == "merged_missing_category" {
				guard := behaviorAgentGuardPolicy(user.TenantID, policyCenterAgentBehaviorSystem, "system.*", repository.AgentGuardActionBlock, time.Now().UTC())
				guard.ID = policyCenterAgentGuardPolicyIDFor(user.TenantID)
				agentRepo.policies[guard.ID] = guard
			}
			item := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
			if !reflect.DeepEqual(item["restricted_file_patterns"], []any{"contracts/**", "*.pdf"}) || item["restricted_file_action"] != "alert_allow" {
				t.Fatalf("stored restricted files not projected: %#v", item)
			}
			if item["health"] != "ok" || operationRepo.getCalls != 1 {
				t.Fatalf("health/read count: item=%#v reads=%d", item, operationRepo.getCalls)
			}
		})
	}
}

func TestPolicyCenterSensitiveResourceRestrictedOnlyRoundTripsWithoutGuardWrite(t *testing.T) {
	deps, operationRepo, agentRepo, user := consistencySensitiveFixture()
	item := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
	guardBefore := mustJSON(t, agentRepo.policies)
	agentRepo.atomicUpdateErr = errors.New("guard must not be written")
	rec := consistencyPut(t, deps, user, policyCenterAgentBehaviorFile, map[string]any{
		"action": item["configured_action"], "version": item["version"],
		"restricted_file_patterns": []string{"*.docx"}, "restricted_file_action": "record",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", rec.Code, rec.Body.String())
	}
	if operationRepo.saveCalls != 1 || agentRepo.atomicCreateCalls != 0 || agentRepo.atomicUpdateCalls != 0 || string(guardBefore) != string(mustJSON(t, agentRepo.policies)) {
		t.Fatalf("restricted-only changed guard: saves=%d creates=%d updates=%d", operationRepo.saveCalls, agentRepo.atomicCreateCalls, agentRepo.atomicUpdateCalls)
	}
	if operationRepo.saved.ExpectedVersion != 7 || operationRepo.saved.Action != "alert_allow" || operationRepo.saved.Mode != "light" || operationRepo.saved.Protocol != "mcp" || !reflect.DeepEqual(operationRepo.saved.DiscardablePaths, []string{"dist", "tmp"}) || !reflect.DeepEqual(operationRepo.saved.NotifyChannelIDs, []string{"channel-a"}) {
		t.Fatalf("mutation did not preserve edited snapshot: %+v", operationRepo.saved)
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	fresh := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
	for _, projection := range []map[string]any{response, fresh} {
		if !reflect.DeepEqual(projection["restricted_file_patterns"], []any{"*.docx"}) || projection["restricted_file_action"] != "record" || projection["version"] == item["version"] {
			t.Fatalf("save did not read back new state: %#v", projection)
		}
	}
}

func TestPolicyCenterSensitiveResourceVersionTracksBothStores(t *testing.T) {
	for _, variant := range []string{"operation_version", "operation_content", "guard", "missing_guard", "merged_missing_category"} {
		t.Run(variant, func(t *testing.T) {
			deps, operationRepo, agentRepo, user := consistencySensitiveFixture()
			if variant == "missing_guard" {
				agentRepo.policies = map[string]*repository.AgentGuardPolicy{}
			}
			if variant == "merged_missing_category" {
				guard := agentRepo.policies["policy-center-"+policyCenterAgentBehaviorFile]
				agentRepo.policies = map[string]*repository.AgentGuardPolicy{}
				guard.ID = policyCenterAgentGuardPolicyIDFor(user.TenantID)
				guard.RulesJSON = map[string]any{}
				agentRepo.policies[guard.ID] = guard
			}
			item := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
			if variant == "guard" || variant == "merged_missing_category" {
				for _, guard := range agentRepo.policies {
					guard.UpdatedAt = guard.UpdatedAt.Add(time.Minute)
				}
			} else if variant == "operation_content" {
				operationRepo.policy.RestrictedFilePatterns = []string{"*.xlsx"}
			} else {
				operationRepo.policy.Version++
			}
			fresh := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
			if item["version"] == fresh["version"] {
				t.Fatalf("%s did not change composite version", variant)
			}
			rec := consistencyPut(t, deps, user, policyCenterAgentBehaviorFile, map[string]any{
				"action": item["configured_action"], "version": item["version"], "restricted_file_patterns": []string{"*.docx"},
			})
			if rec.Code != http.StatusConflict || operationRepo.saveCalls != 0 || agentRepo.atomicUpdateCalls != 0 || agentRepo.atomicCreateCalls != 0 {
				t.Fatalf("stale request not rejected before writes: status=%d operation=%d guard=%d/%d body=%s", rec.Code, operationRepo.saveCalls, agentRepo.atomicUpdateCalls, agentRepo.atomicCreateCalls, rec.Body.String())
			}
		})
	}
}

type consistencyOrderedAgentGuardRepo struct {
	AgentGuardBehaviorRepo
	policies []*repository.AgentGuardPolicy
}

func (r *consistencyOrderedAgentGuardRepo) ListPolicies(context.Context, string) ([]*repository.AgentGuardPolicy, error) {
	return r.policies, nil
}

func TestPolicyCenterVersionBindsSelectedPolicyWithinUnchangedCandidateSet(t *testing.T) {
	for _, variant := range []string{"guard", "mcp"} {
		t.Run(variant, func(t *testing.T) {
			deps, operationRepo, guardRepo, user := consistencySensitiveFixture()
			key := policyCenterAgentBehaviorSystem
			var reorder func()
			if variant == "guard" {
				first := behaviorAgentGuardPolicy(user.TenantID, key, "system.*", repository.AgentGuardActionAudit, time.Now().UTC())
				second := behaviorAgentGuardPolicy(user.TenantID, key, "system.*", repository.AgentGuardActionAudit, first.UpdatedAt)
				first.ID, second.ID = "advanced-a", "advanced-b"
				ordered := &consistencyOrderedAgentGuardRepo{AgentGuardBehaviorRepo: guardRepo, policies: []*repository.AgentGuardPolicy{first, second}}
				deps.AgentGuardBehaviorRepo = ordered
				reorder = func() { ordered.policies[0], ordered.policies[1] = ordered.policies[1], ordered.policies[0] }
			} else {
				key = policyCenterAgentBehaviorMCP
				mcpRepo := deps.MCPPolicyRepo.(*behaviorMCPRepo)
				mcpRepo.policies = []*repository.MCPPolicy{
					{ID: "mcp-a", TenantID: user.TenantID, ScopeType: "tenant", ToolPattern: "*", Mode: "audit", DefaultAction: "audit", Enabled: true},
					{ID: "mcp-b", TenantID: user.TenantID, ScopeType: "tenant", ToolPattern: "*", Mode: "audit", DefaultAction: "audit", Enabled: true},
				}
				reorder = func() { mcpRepo.policies[0], mcpRepo.policies[1] = mcpRepo.policies[1], mcpRepo.policies[0] }
			}
			item := consistencyBehaviorItem(t, deps, user, key)
			reorder()
			fresh := consistencyBehaviorItem(t, deps, user, key)
			if item["version"] == fresh["version"] {
				t.Fatal("unchanged candidate set hid a different selected object")
			}
			rec := consistencyPut(t, deps, user, key, map[string]any{"action": "block", "version": item["version"]})
			mcpRepo := deps.MCPPolicyRepo.(*behaviorMCPRepo)
			if rec.Code != http.StatusConflict || operationRepo.saveCalls != 0 || guardRepo.atomicCreateCalls != 0 || guardRepo.atomicUpdateCalls != 0 || len(mcpRepo.updated) != 0 {
				t.Fatalf("stale selection was saved: status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPolicyCenterCandidateDoesNotMutateEditedSnapshot(t *testing.T) {
	deps, _, guardRepo, user := consistencySensitiveFixture()
	guard := guardRepo.policies["policy-center-"+policyCenterAgentBehaviorFile]
	guard.BehaviorJSON = map[string]any{"nested": map[string]any{"value": "original"}}
	guard.DLPJSON = map[string]any{"nested": map[string]any{"value": "original"}}
	states, err := loadPolicyCenterAgentBehaviors(withBehaviorUser(http.MethodGet, "/x", "", user), deps, user.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	state := policyCenterAgentBehaviorStateByKey(states, policyCenterAgentBehaviorFile)
	before := mustJSON(t, guardRepo.policies)
	mutation, err := preparePolicyCenterAgentBehaviorMutation(user, state, policyCenterAgentBehaviorUpdateRequest{Action: "block"})
	if err != nil {
		t.Fatal(err)
	}
	mutation.AgentGuard.Policy.BehaviorJSON["nested"].(map[string]any)["value"] = "candidate"
	mutation.AgentGuard.Policy.DLPJSON["nested"].(map[string]any)["value"] = "candidate"
	if string(before) != string(mustJSON(t, guardRepo.policies)) || mutation.AgentGuard.Expected.ExpectedVersion != repository.PolicyCenterSnapshotVersion(state.agentGuardPolicy) {
		t.Fatal("candidate construction mutated the edited snapshot")
	}
}

func TestPolicyCenterSensitiveMutationChecksBothStoresForEachWriteShape(t *testing.T) {
	for _, variant := range []string{"restricted_only", "baseline_only", "combined"} {
		t.Run(variant, func(t *testing.T) {
			deps, _, _, user := consistencySensitiveFixture()
			states, err := loadPolicyCenterAgentBehaviors(withBehaviorUser(http.MethodGet, "/x", "", user), deps, user.TenantID)
			if err != nil {
				t.Fatal(err)
			}
			state := policyCenterAgentBehaviorStateByKey(states, policyCenterAgentBehaviorFile)
			request := policyCenterAgentBehaviorUpdateRequest{Action: "block"}
			if variant != "baseline_only" {
				patterns := []string{"candidate/**"}
				request.RestrictedFilePatterns = &patterns
			}
			if variant == "restricted_only" {
				request.Action = state.ConfiguredAction
			}
			mutation, err := preparePolicyCenterAgentBehaviorMutation(user, state, request)
			if err != nil {
				t.Fatal(err)
			}
			if mutation.AgentGuard == nil || mutation.Operation == nil || mutation.AgentGuard.Expected.ExpectedVersion != repository.PolicyCenterSnapshotVersion(state.agentGuardPolicy) || mutation.Operation.Expected.ExpectedVersion != repository.PolicyCenterSnapshotVersion(state.destructivePolicy) || mutation.Operation.ExpectedStorageVersion != state.destructivePolicy.Version {
				t.Fatalf("incomplete shared-store preconditions: %+v", mutation)
			}
			if (mutation.AgentGuard.Policy != nil) != (variant != "restricted_only") || (mutation.Operation.Mutation != nil) != (variant != "baseline_only") {
				t.Fatalf("unexpected write shape %s: %+v", variant, mutation)
			}
		})
	}
}

func TestPolicyCenterMissingConditionalStorageNeverFallsBackToUnconditionalWrite(t *testing.T) {
	deps, operationRepo, guardRepo, user := consistencySensitiveFixture()
	item := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
	before := mustJSON(t, guardRepo.policies)
	deps.PolicyCenterBehaviorRepo = nil
	rec := consistencyPut(t, deps, user, policyCenterAgentBehaviorFile, map[string]any{
		"action": item["configured_action"], "version": item["version"], "restricted_file_patterns": []string{"*.docx"},
	})
	if rec.Code != http.StatusServiceUnavailable || operationRepo.saveCalls != 0 || guardRepo.atomicCreateCalls != 0 || guardRepo.atomicUpdateCalls != 0 || string(before) != string(mustJSON(t, guardRepo.policies)) {
		t.Fatalf("conditional storage absence fell back to a write: status=%d operation=%d guard=%d/%d body=%s", rec.Code, operationRepo.saveCalls, guardRepo.atomicCreateCalls, guardRepo.atomicUpdateCalls, rec.Body.String())
	}
}

func TestPolicyCenterBehaviorSaveErrorsRemainVisible(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
	}{
		{"cas", repository.ErrPolicyCenterBehaviorConflict, http.StatusConflict},
		{"operation", repository.ErrAgentOperationConflict, http.StatusConflict},
		{"storage", errors.New("storage unavailable"), http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writePolicyCenterAgentBehaviorSaveError(rec, fmt.Errorf("save: %w", test.err))
			if rec.Code != test.status {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, test.status, rec.Body.String())
			}
		})
	}
}

func TestPolicyCenterSensitiveResourceUnchangedRestrictedFieldsAllowBaselineUpdate(t *testing.T) {
	for _, variant := range []string{"patterns", "restricted_action", "both", "empty_patterns", "nil_patterns", "missing_policy_defaults", "empty_stored_action"} {
		t.Run(variant, func(t *testing.T) {
			deps, operationRepo, agentRepo, user := consistencySensitiveFixture()
			switch variant {
			case "empty_patterns":
				operationRepo.policy.RestrictedFilePatterns = []string{}
			case "nil_patterns":
				operationRepo.policy.RestrictedFilePatterns = nil
			case "missing_policy_defaults":
				operationRepo.policy = nil
			case "empty_stored_action":
				operationRepo.policy.RestrictedFileAction = ""
			}
			item := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
			operationBefore := mustJSON(t, operationRepo.policy)
			loadedOperation, err := operationRepo.GetPolicy(context.Background(), user.TenantID, "tenant", "")
			if err != nil {
				t.Fatal(err)
			}
			guardBefore := repository.PolicyCenterSnapshotVersion(agentRepo.policies["policy-center-"+policyCenterAgentBehaviorFile])
			body := map[string]any{"action": "block", "version": item["version"]}
			if variant != "restricted_action" {
				body["restricted_file_patterns"] = item["restricted_file_patterns"]
			}
			if variant != "patterns" {
				body["restricted_file_action"] = item["restricted_file_action"]
			}
			rec := consistencyPut(t, deps, user, policyCenterAgentBehaviorFile, body)
			if rec.Code != http.StatusOK {
				t.Fatalf("unchanged restricted fields rejected baseline update: status=%d body=%s", rec.Code, rec.Body.String())
			}
			shared := deps.PolicyCenterBehaviorRepo.(*behaviorConditionalRepo)
			if shared.saved.AgentGuard == nil || shared.saved.AgentGuard.Policy == nil || shared.saved.AgentGuard.Expected.ExpectedVersion != guardBefore || shared.saved.Operation == nil || shared.saved.Operation.Mutation != nil {
				t.Fatalf("baseline update did not preserve conditional read-only operation: %+v", shared.saved)
			}
			if loadedOperation == nil {
				if !shared.saved.Operation.Expected.ExpectedAbsent || shared.saved.Operation.ExpectedStorageVersion != 0 {
					t.Fatalf("missing operation precondition lost: %+v", shared.saved.Operation)
				}
			} else if shared.saved.Operation.Expected.ExpectedVersion != repository.PolicyCenterSnapshotVersion(loadedOperation) || shared.saved.Operation.ExpectedStorageVersion != loadedOperation.Version {
				t.Fatalf("operation snapshot precondition lost: %+v", shared.saved.Operation)
			}
			if operationRepo.saveCalls != 0 || string(operationBefore) != string(mustJSON(t, operationRepo.policy)) || agentRepo.atomicUpdateCalls != 1 || agentRepo.atomicCreateCalls != 0 {
				t.Fatalf("baseline update wrote unchanged restricted configuration: operation=%d guard=%d/%d", operationRepo.saveCalls, agentRepo.atomicUpdateCalls, agentRepo.atomicCreateCalls)
			}
			var response map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			fresh := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
			for _, projection := range []map[string]any{response, fresh} {
				if projection["configured_action"] != "block" || projection["version"] == item["version"] || !reflect.DeepEqual(projection["restricted_file_patterns"], item["restricted_file_patterns"]) || projection["restricted_file_action"] != item["restricted_file_action"] {
					t.Fatalf("baseline update did not roundtrip unchanged restricted fields: %#v", projection)
				}
			}
		})
	}
}

func TestPolicyCenterSensitiveResourceCombinedUpdateRejectedBeforeWrites(t *testing.T) {
	for _, variant := range []string{"patterns", "restricted_action", "both", "same_patterns_changed_action", "changed_patterns_same_action", "clear_patterns", "reordered_patterns"} {
		t.Run(variant, func(t *testing.T) {
			deps, operationRepo, agentRepo, user := consistencySensitiveFixture()
			item := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
			guardBefore, operationBefore := mustJSON(t, agentRepo.policies), mustJSON(t, operationRepo.policy)
			shared := deps.PolicyCenterBehaviorRepo.(*behaviorConditionalRepo)
			body := map[string]any{"action": "block", "version": item["version"]}
			if variant != "restricted_action" {
				body["restricted_file_patterns"] = []string{"*.docx"}
			}
			if variant != "patterns" {
				body["restricted_file_action"] = "block"
			}
			switch variant {
			case "same_patterns_changed_action":
				body["restricted_file_patterns"] = item["restricted_file_patterns"]
			case "changed_patterns_same_action":
				body["restricted_file_action"] = item["restricted_file_action"]
			case "clear_patterns":
				body["restricted_file_patterns"] = []string{}
				delete(body, "restricted_file_action")
			case "reordered_patterns":
				body["restricted_file_patterns"] = []string{"*.pdf", "contracts/**"}
				delete(body, "restricted_file_action")
			}
			rec := consistencyPut(t, deps, user, policyCenterAgentBehaviorFile, body)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "combined_update_not_supported") {
				t.Fatalf("combined status=%d body=%s", rec.Code, rec.Body.String())
			}
			if shared.saved.TenantID != "" || operationRepo.saveCalls != 0 || agentRepo.atomicCreateCalls != 0 || agentRepo.atomicUpdateCalls != 0 || string(guardBefore) != string(mustJSON(t, agentRepo.policies)) || string(operationBefore) != string(mustJSON(t, operationRepo.policy)) {
				t.Fatalf("combined request reached a writer: %+v", shared.saved)
			}
		})
	}
}

func TestPolicyCenterSensitiveResourceOperationReadFailureIsVisibleAndBlocksSave(t *testing.T) {
	deps, operationRepo, agentRepo, user := consistencySensitiveFixture()
	operationRepo.getError = errors.New("operation read failed")
	item := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
	if item["health"] != "error" || item["health_message"] == "" || item["current_action"] != "unknown" {
		t.Fatalf("read failure reported as healthy action: %#v", item)
	}
	if _, present := item["restricted_file_patterns"]; present {
		t.Fatalf("read failure substituted empty patterns: %#v", item)
	}
	if _, present := item["restricted_file_action"]; present {
		t.Fatalf("read failure substituted default action: %#v", item)
	}
	rec := consistencyPut(t, deps, user, policyCenterAgentBehaviorFile, map[string]any{
		"action": "record", "version": item["version"], "restricted_file_patterns": []string{"*.docx"},
	})
	if rec.Code != http.StatusServiceUnavailable || operationRepo.saveCalls != 0 || agentRepo.atomicUpdateCalls != 0 {
		t.Fatalf("read failure was swallowed: status=%d operation=%d guard=%d body=%s", rec.Code, operationRepo.saveCalls, agentRepo.atomicUpdateCalls, rec.Body.String())
	}
}

func TestPolicyCenterSensitiveResourceReadAfterSaveFailureDoesNotReturnSuccess(t *testing.T) {
	deps, operationRepo, _, user := consistencySensitiveFixture()
	item := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
	operationRepo.afterSave = func() { operationRepo.getError = errors.New("fresh read failed") }
	rec := consistencyPut(t, deps, user, policyCenterAgentBehaviorFile, map[string]any{
		"action": item["configured_action"], "version": item["version"], "restricted_file_patterns": []string{"*.docx"},
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("fresh read failure returned success: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPolicyCenterSensitiveResourceRestrictedOnlyUsesStorageCASAfterRead(t *testing.T) {
	deps, operationRepo, agentRepo, user := consistencySensitiveFixture()
	item := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
	operationRepo.beforeSave = func() {
		operationRepo.policy.Version++
		operationRepo.policy.RestrictedFilePatterns = []string{"concurrent/**"}
	}
	rec := consistencyPut(t, deps, user, policyCenterAgentBehaviorFile, map[string]any{
		"action": item["configured_action"], "version": item["version"], "restricted_file_patterns": []string{"*.docx"},
	})
	if rec.Code != http.StatusConflict || operationRepo.saved.ExpectedVersion != 7 || agentRepo.atomicUpdateCalls != 0 || agentRepo.atomicCreateCalls != 0 || !reflect.DeepEqual(operationRepo.policy.RestrictedFilePatterns, []string{"concurrent/**"}) {
		t.Fatalf("storage CAS lost update: status=%d mutation=%+v policy=%+v guard=%d/%d body=%s", rec.Code, operationRepo.saved, operationRepo.policy, agentRepo.atomicUpdateCalls, agentRepo.atomicCreateCalls, rec.Body.String())
	}
}

func TestPolicyCenterDestructiveOnlyPreservesRestrictedConfiguration(t *testing.T) {
	deps, operationRepo, _, user := consistencySensitiveFixture()
	item := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorDestructive)
	rec := consistencyPut(t, deps, user, policyCenterAgentBehaviorDestructive, map[string]any{"action": "block", "version": item["version"]})
	if rec.Code != http.StatusOK {
		t.Fatalf("destructive save: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !reflect.DeepEqual(operationRepo.policy.RestrictedFilePatterns, []string{"contracts/**", "*.pdf"}) || operationRepo.policy.RestrictedFileAction != "alert_allow" {
		t.Fatalf("destructive save erased restricted configuration: %+v", operationRepo.policy)
	}
}

// 2.9.22 批次 2B：“删除与破坏”卡片能直接选确认，原 variant 表里的 "destructive" 去掉（它不再是
// 高级动作，见 TestPolicyCenterDestructiveCard2922AcceptsConfirm）；其余卡片的确认仍是高级动作。
func TestPolicyCenterAdvancedConfirmIsNotProjectedAsHealthyRecord(t *testing.T) {
	for _, variant := range []string{"managed", "managed_marker", "matching_rule", "guard_default", "merged_missing_category", "merged_default_override", "mcp"} {
		t.Run(variant, func(t *testing.T) {
			deps, operationRepo, agentRepo, user := consistencySensitiveFixture()
			key := policyCenterAgentBehaviorFile
			switch variant {
			case "destructive":
				key = policyCenterAgentBehaviorDestructive
				operationRepo.policy.Action = "confirm"
			case "mcp":
				key = policyCenterAgentBehaviorMCP
				deps.MCPPolicyRepo = &behaviorMCPRepo{policies: []*repository.MCPPolicy{{ID: "mcp-a", TenantID: user.TenantID, ScopeType: "tenant", ToolPattern: "*", Mode: "strict", DefaultAction: "confirm", Enabled: true}}}
			default:
				guard := agentRepo.policies["policy-center-"+key]
				rules := policyCenterAgentGuardRules(guard)
				rules[0]["action"] = "confirm"
				if variant != "managed_marker" {
					delete(rules[0], policyCenterRuleActionKey)
				}
				if variant == "matching_rule" || variant == "guard_default" {
					guard.ID = "advanced-policy"
					agentRepo.policies = map[string]*repository.AgentGuardPolicy{guard.ID: guard}
					rules[0]["id"] = "advanced-file-rule"
				}
				if variant == "guard_default" {
					guard.ID = "policy-center-" + key
					guard.DefaultAction = "confirm"
					guard.RulesJSON = map[string]any{}
					agentRepo.policies = map[string]*repository.AgentGuardPolicy{guard.ID: guard}
				}
				if variant == "merged_missing_category" || variant == "merged_default_override" {
					guard.ID = policyCenterAgentGuardPolicyIDFor(user.TenantID)
					guard.DefaultAction = "confirm"
					guard.RulesJSON = map[string]any{}
					if variant == "merged_default_override" {
						guard.RulesJSON["rules"] = []map[string]any{{"id": "policy-center-" + key, "tool_pattern": "file.*", "action": "audit", policyCenterRuleActionKey: "record", "enabled": true}}
					}
					agentRepo.policies = map[string]*repository.AgentGuardPolicy{guard.ID: guard}
				}
			}
			item := consistencyBehaviorItem(t, deps, user, key)
			wantConfiguredAction := "confirm"
			if strings.HasPrefix(variant, "merged_") {
				wantConfiguredAction = "record"
			}
			if item["health"] != "error" || item["configured_action"] != wantConfiguredAction || item["raw_configured_action"] != "confirm" || item["current_action"] != "unknown" || item["has_advanced_overrides"] != true {
				t.Fatalf("confirm projected as ordinary healthy action: %#v", item)
			}
			if !reflect.DeepEqual(item["allowed_actions"], []any{"record", "alert_allow", "block"}) {
				t.Fatalf("advanced action expanded basic API: %#v", item)
			}
			rec := consistencyPut(t, deps, user, key, map[string]any{"action": "record", "version": item["version"]})
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("advanced action overwritten through basic API: status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPolicyCenterAdvancedOverrideMarksCurrentActionUnknown(t *testing.T) {
	deps, _, agentRepo, user := consistencySensitiveFixture()
	guard := agentRepo.policies["policy-center-"+policyCenterAgentBehaviorFile]
	policyCenterAgentGuardRules(guard)[1]["action"] = "confirm"
	item := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
	if item["configured_action"] != "record" || item["has_advanced_overrides"] != true || item["current_action"] != "unknown" {
		t.Fatalf("advanced override represented as baseline execution: %#v", item)
	}
}

func consistencyPostgresFixture(t *testing.T) (*Dependencies, *repository.AgentOperationRepository, *repository.AgentGuardPolicyRepository, *pgxpool.Pool, *repository.User) {
	t.Helper()
	dsn := os.Getenv("AGENT_OPERATION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AGENT_OPERATION_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := pgx.Identifier{fmt.Sprintf("policy_center_consistency_%d", time.Now().UnixNano())}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	_, err = db.Exec(ctx, `
		CREATE TABLE notify_channels (id text PRIMARY KEY, tenant_id text NOT NULL, enabled boolean NOT NULL);
		INSERT INTO notify_channels VALUES ('channel-a', 'tenant-a', true);
		CREATE TABLE agent_destructive_policies (
			id text PRIMARY KEY, tenant_id text, scope_type text NOT NULL, scope_ref text NOT NULL,
			mode text NOT NULL, action text NOT NULL, protocol text NOT NULL DEFAULT '',
			discardable_paths_json jsonb NOT NULL, notify_channel_ids_json jsonb NOT NULL,
			restricted_file_patterns_json jsonb NOT NULL DEFAULT '[]'::jsonb,
			restricted_file_action text NOT NULL DEFAULT 'block',
			restricted_file_scopes_json jsonb NOT NULL DEFAULT '["tool_call","user_mention","proxy_output"]'::jsonb,
			version bigint NOT NULL, enabled boolean NOT NULL, created_by text NOT NULL, updated_by text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
			UNIQUE (tenant_id, scope_type, scope_ref)
		);
		CREATE TABLE agent_destructive_policy_audits (
			id text PRIMARY KEY, tenant_id text, actor_id text NOT NULL, source text NOT NULL,
			scope_type text NOT NULL, scope_ref text NOT NULL, before_json jsonb NOT NULL,
			after_json jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
		);
		CREATE TABLE agentguard_policies (
			id varchar(64) PRIMARY KEY, tenant_id varchar(64) NOT NULL, name varchar(128) NOT NULL,
			scope_type varchar(32) NOT NULL, scope_ref varchar(128) NOT NULL DEFAULT '',
			mode varchar(16) NOT NULL DEFAULT 'audit', default_action varchar(16) NOT NULL DEFAULT 'audit',
			fail_policy varchar(16) NOT NULL DEFAULT 'fail_closed', priority integer NOT NULL DEFAULT 0,
			enabled boolean NOT NULL DEFAULT true, template_id varchar(64),
			rules_json jsonb NOT NULL DEFAULT '{}'::jsonb, behavior_json jsonb NOT NULL DEFAULT '{}'::jsonb,
			dlp_json jsonb NOT NULL DEFAULT '{}'::jsonb, created_by varchar(64), updated_by varchar(64),
			created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
		);
		CREATE TABLE agentguard_policy_versions (
			id varchar(64) PRIMARY KEY, tenant_id varchar(64) NOT NULL,
			policy_id varchar(64) NOT NULL REFERENCES agentguard_policies(id) ON DELETE CASCADE,
			policy_version varchar(64) NOT NULL, snapshot_json jsonb NOT NULL, config_hash varchar(128) NOT NULL,
			active boolean NOT NULL DEFAULT false, created_by varchar(64), created_at timestamptz NOT NULL DEFAULT now(),
			UNIQUE (policy_id, policy_version)
		);
		CREATE UNIQUE INDEX consistency_agentguard_one_active ON agentguard_policy_versions(policy_id) WHERE active;
		CREATE TABLE mcp_policies (
			id text PRIMARY KEY, tenant_id text NOT NULL, scope_type text NOT NULL, scope_ref text NOT NULL DEFAULT '',
			server_id text NOT NULL DEFAULT '', tool_pattern text NOT NULL DEFAULT '', target_kind text NOT NULL DEFAULT 'tool',
			arg_conditions jsonb NOT NULL DEFAULT '[]'::jsonb, mode text NOT NULL DEFAULT 'audit',
			default_action text NOT NULL DEFAULT 'audit', priority integer NOT NULL DEFAULT 0, enabled boolean NOT NULL DEFAULT true,
			note text NOT NULL DEFAULT '', created_by text NOT NULL DEFAULT '',
			created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
		);
	`)
	if err != nil {
		t.Fatal(err)
	}
	user := &repository.User{ID: "admin-1", TenantID: "tenant-a", Role: "platform_admin"}
	operationRepo := repository.NewAgentOperationRepository(db)
	if _, err := operationRepo.SavePolicy(ctx, repository.AgentOperationPolicyMutation{
		TenantID: user.TenantID, ActorID: user.ID, Source: "test",
		ScopeType: "tenant", Mode: "light", Action: "alert_allow", Protocol: "mcp", ExpectedVersion: 1,
		DiscardablePaths: []string{"dist", "tmp"}, NotifyChannelIDs: []string{"channel-a"},
		RestrictedFilePatterns: []string{"contracts/**", "*.pdf"}, RestrictedFileAction: "alert_allow",
	}); err != nil {
		t.Fatal(err)
	}
	guardRepo := repository.NewAgentGuardPolicyRepository(db)
	guard := behaviorAgentGuardPolicy(user.TenantID, policyCenterAgentBehaviorFile, "file.*", repository.AgentGuardActionAudit, time.Now().UTC())
	guard.ID = policyCenterAgentGuardPolicyIDFor(user.TenantID)
	guard.RulesJSON["rules"] = policyCenterAgentGuardRules(guard)[:1]
	policyCenterAgentGuardRules(guard)[0][policyCenterRuleActionKey] = "record"
	if _, _, err := guardRepo.CreatePolicyWithVersion(ctx, guard, user.ID); err != nil {
		t.Fatal(err)
	}
	deps, _, _, _, auditRepo := behaviorDeps(user.TenantID, nil, nil, nil)
	deps.AgentOperationRepo = operationRepo
	deps.AgentGuardPolicyRepo = guardRepo
	deps.AgentGuardBehaviorRepo = guardRepo
	deps.PolicyCenterBehaviorRepo = repository.NewPolicyCenterAgentBehaviorRepository(db)
	deps.MCPPolicyRepo = repository.NewMCPPoliciesRepository(db)
	auditRepo.settings = map[string]string{"security_execution_mode": "protect"}
	return deps, operationRepo, guardRepo, db, user
}

type consistencyPostgresBehaviorRepo struct {
	PolicyCenterAgentBehaviorRepo
	beforeSave func() error
	saved      repository.PolicyCenterAgentBehaviorMutation
}

func (r *consistencyPostgresBehaviorRepo) Save(ctx context.Context, mutation repository.PolicyCenterAgentBehaviorMutation) error {
	r.saved = mutation
	if err := r.beforeSave(); err != nil {
		return err
	}
	return r.PolicyCenterAgentBehaviorRepo.Save(ctx, mutation)
}

func TestPolicyCenterBehaviorStorageCASPostgreSQL(t *testing.T) {
	for _, variant := range []string{"guard_stale", "guard_phantom", "guard_selected", "mcp_stale", "mcp_phantom", "mcp_selected", "restricted_guard_race", "baseline_operation_race", "operation_absent_race", "guard_absent_race", "combined_rollback", "tenant_boundary"} {
		t.Run(variant, func(t *testing.T) {
			deps, operationRepo, guardRepo, db, user := consistencyPostgresFixture(t)
			ctx := context.Background()
			key := policyCenterAgentBehaviorFile
			guardID := policyCenterAgentGuardPolicyIDFor(user.TenantID)
			guardOtherID := ""
			if variant == "guard_selected" {
				if _, err := db.Exec(ctx, `DELETE FROM agentguard_policy_versions; DELETE FROM agentguard_policies`); err != nil {
					t.Fatal(err)
				}
				for index := 0; index < 2; index++ {
					policy := behaviorAgentGuardPolicy(user.TenantID, key, "file.*", "audit", time.Now().UTC())
					policy.Priority = 10 - index
					stored, _, err := guardRepo.CreatePolicyWithVersion(ctx, policy, user.ID)
					if err != nil {
						t.Fatal(err)
					}
					if index == 0 {
						guardID = stored.ID
					} else {
						guardOtherID = stored.ID
					}
				}
			}
			if strings.HasPrefix(variant, "mcp_") {
				key = policyCenterAgentBehaviorMCP
				if err := deps.MCPPolicyRepo.Create(ctx, &repository.MCPPolicy{ID: "mcp-base", TenantID: user.TenantID, ScopeType: "tenant", ToolPattern: "*", DefaultAction: "audit", Mode: "audit", Enabled: true, Priority: 10}); err != nil {
					t.Fatal(err)
				}
				if variant == "mcp_selected" {
					if err := deps.MCPPolicyRepo.Create(ctx, &repository.MCPPolicy{ID: "mcp-other", TenantID: user.TenantID, ScopeType: "tenant", ToolPattern: "*", DefaultAction: "audit", Mode: "audit", Enabled: true, Priority: 1}); err != nil {
						t.Fatal(err)
					}
				}
			}
			if variant == "operation_absent_race" {
				if _, err := db.Exec(ctx, `DELETE FROM agent_destructive_policies; DELETE FROM agent_destructive_policy_audits`); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "guard_absent_race" {
				if _, err := db.Exec(ctx, `DELETE FROM agentguard_policy_versions; DELETE FROM agentguard_policies`); err != nil {
					t.Fatal(err)
				}
			}
			item := consistencyBehaviorItem(t, deps, user, key)
			body := map[string]any{"action": "block", "version": item["version"]}
			if variant == "restricted_guard_race" || variant == "operation_absent_race" || variant == "combined_rollback" {
				body["restricted_file_patterns"] = []string{"*.docx"}
			}
			if variant == "restricted_guard_race" || variant == "operation_absent_race" {
				body["action"] = item["configured_action"]
			}
			expectedOperation, err := operationRepo.GetPolicy(ctx, user.TenantID, "tenant", "")
			if err != nil && !errors.Is(err, repository.ErrAgentOperationNotFound) {
				t.Fatal(err)
			}
			expectedGuard, err := guardRepo.GetPolicy(ctx, user.TenantID, guardID)
			if err != nil {
				t.Fatal(err)
			}
			expectedMCP, err := deps.MCPPolicyRepo.ListByTenant(ctx, user.TenantID, "")
			if err != nil {
				t.Fatal(err)
			}
			operationJSON, guardJSON := mustJSON(t, expectedOperation), mustJSON(t, expectedGuard)
			mcpVersion := repository.PolicyCenterMCPPoliciesVersion(expectedMCP)
			guardPolicies, err := guardRepo.ListPolicies(ctx, user.TenantID)
			if err != nil {
				t.Fatal(err)
			}
			guardSetVersion := repository.PolicyCenterAgentGuardPoliciesVersion(guardPolicies)
			if variant == "guard_selected" {
				definition, _ := policyCenterAgentBehaviorDefinitionByKey(key)
				selected, _ := findPolicyCenterAgentGuardPolicy(guardPolicies, definition)
				if selected == nil || selected.ID != guardID {
					t.Fatalf("initial guard selection=%+v", selected)
				}
			}
			if variant == "mcp_selected" {
				if selected := findPolicyCenterMCPPolicy(expectedMCP); selected == nil || selected.ID != "mcp-base" {
					t.Fatalf("initial mcp selection=%+v", selected)
				}
			}
			before := func() error {
				switch variant {
				case "guard_stale", "restricted_guard_race":
					expectedGuard.Name += "-concurrent"
					if _, _, _, err := guardRepo.UpdatePolicyWithVersion(ctx, expectedGuard, user.ID); err != nil {
						return err
					}
					guardJSON = mustJSON(t, expectedGuard)
				case "guard_phantom":
					policy := behaviorAgentGuardPolicy(user.TenantID, key, "file.*", "audit", time.Now().UTC())
					policy.ID = "advanced-concurrent"
					if _, _, err := guardRepo.CreatePolicyWithVersion(ctx, policy, user.ID); err != nil {
						return err
					}
				case "guard_selected":
					if _, err := db.Exec(ctx, `UPDATE agentguard_policies SET priority=20, updated_at=now() WHERE id=$1`, guardOtherID); err != nil {
						return err
					}
					policies, err := guardRepo.ListPolicies(ctx, user.TenantID)
					if err != nil {
						return err
					}
					definition, _ := policyCenterAgentBehaviorDefinitionByKey(key)
					selected, _ := findPolicyCenterAgentGuardPolicy(policies, definition)
					if selected == nil || selected.ID != guardOtherID {
						return fmt.Errorf("guard selected object did not switch: %+v", selected)
					}
				case "mcp_selected":
					if _, err := db.Exec(ctx, `UPDATE mcp_policies SET priority=20, updated_at=now() WHERE id='mcp-other'`); err != nil {
						return err
					}
					policies, err := deps.MCPPolicyRepo.ListByTenant(ctx, user.TenantID, "")
					if err != nil {
						return err
					}
					selected := findPolicyCenterMCPPolicy(policies)
					if selected == nil || selected.ID != "mcp-other" {
						return fmt.Errorf("mcp selected object did not switch: %+v", selected)
					}
					mcpVersion = repository.PolicyCenterMCPPoliciesVersion(policies)
				case "mcp_stale":
					expectedMCP[0].Note = "concurrent"
					if err := deps.MCPPolicyRepo.Update(ctx, expectedMCP[0]); err != nil {
						return err
					}
					mcpVersion = repository.PolicyCenterMCPPoliciesVersion(expectedMCP)
				case "mcp_phantom":
					if err := deps.MCPPolicyRepo.Create(ctx, &repository.MCPPolicy{ID: "mcp-concurrent", TenantID: user.TenantID, ScopeType: "tenant", ToolPattern: "danger.*", DefaultAction: "confirm", Mode: "strict", Enabled: true}); err != nil {
						return err
					}
					policies, err := deps.MCPPolicyRepo.ListByTenant(ctx, user.TenantID, "")
					if err != nil {
						return err
					}
					mcpVersion = repository.PolicyCenterMCPPoliciesVersion(policies)
				case "baseline_operation_race", "operation_absent_race":
					mutation := repository.AgentOperationPolicyMutation{TenantID: user.TenantID, ActorID: user.ID, Source: "concurrent", ScopeType: "tenant", Mode: "audit", Action: "record", ExpectedVersion: 1, RestrictedFilePatterns: []string{"concurrent/**"}}
					if expectedOperation != nil {
						mutation.ExpectedVersion = expectedOperation.Version
					}
					if _, err := operationRepo.SavePolicy(ctx, mutation); err != nil {
						return err
					}
					fresh, err := operationRepo.GetPolicy(ctx, user.TenantID, "tenant", "")
					if err != nil {
						return err
					}
					operationJSON = mustJSON(t, fresh)
				case "guard_absent_race":
					policy := behaviorAgentGuardPolicy(user.TenantID, key, "file.*", "audit", time.Now().UTC())
					policy.ID = policyCenterAgentGuardPolicyIDFor(user.TenantID)
					if _, _, err := guardRepo.CreatePolicyWithVersion(ctx, policy, user.ID); err != nil {
						return err
					}
					guardJSON = mustJSON(t, policy)
				case "combined_rollback":
					_, err := db.Exec(ctx, `CREATE FUNCTION reject_behavior_audit() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''injected audit failure''; END'; CREATE TRIGGER reject_behavior_audit BEFORE INSERT ON agent_destructive_policy_audits FOR EACH ROW EXECUTE FUNCTION reject_behavior_audit()`)
					return err
				}
				policies, err := guardRepo.ListPolicies(ctx, user.TenantID)
				if err != nil {
					return err
				}
				guardSetVersion = repository.PolicyCenterAgentGuardPoliciesVersion(policies)
				return nil
			}
			shared := &consistencyPostgresBehaviorRepo{PolicyCenterAgentBehaviorRepo: deps.PolicyCenterBehaviorRepo, beforeSave: before}
			deps.PolicyCenterBehaviorRepo = shared
			wantStatus := http.StatusConflict
			if variant == "combined_rollback" {
				wantStatus = http.StatusInternalServerError
			}
			if variant == "tenant_boundary" || variant == "combined_rollback" {
				states, err := loadPolicyCenterAgentBehaviors(withBehaviorUser(http.MethodGet, "/x", "", user), deps, user.TenantID)
				if err != nil {
					t.Fatal(err)
				}
				request := policyCenterAgentBehaviorUpdateRequest{Action: "block"}
				if variant == "combined_rollback" {
					patterns := []string{"*.docx"}
					request.RestrictedFilePatterns = &patterns
				}
				mutation, err := preparePolicyCenterAgentBehaviorMutation(user, policyCenterAgentBehaviorStateByKey(states, key), request)
				if err != nil {
					t.Fatal(err)
				}
				if variant == "tenant_boundary" {
					mutation.TenantID = "tenant-other"
					if err := shared.Save(ctx, mutation); !errors.Is(err, repository.ErrPolicyCenterBehaviorConflict) {
						t.Fatalf("cross-tenant expected conflict: %v", err)
					}
				} else {
					mutation.MCP = &repository.PolicyCenterMCPChange{
						ID: "mcp-rollback", Expected: repository.PolicyCenterExpectedState{ExpectedAbsent: true}, ExpectedPoliciesVersion: mcpVersion,
						Policy: &repository.MCPPolicy{ID: "mcp-rollback", TenantID: user.TenantID, ScopeType: "tenant", ToolPattern: "*", Mode: "strict", DefaultAction: "block", Enabled: true},
					}
					err := shared.Save(ctx, mutation)
					if err == nil || errors.Is(err, repository.ErrPolicyCenterBehaviorConflict) || !strings.Contains(err.Error(), "injected audit failure") {
						t.Fatalf("audit failure did not remain a save error: %v", err)
					}
					rec := httptest.NewRecorder()
					writePolicyCenterAgentBehaviorSaveError(rec, err)
					if rec.Code != wantStatus {
						t.Fatalf("audit failure status=%d want=%d body=%s", rec.Code, wantStatus, rec.Body.String())
					}
				}
			} else {
				rec := consistencyPut(t, deps, user, key, body)
				if rec.Code != wantStatus {
					t.Fatalf("status=%d want=%d body=%s", rec.Code, wantStatus, rec.Body.String())
				}
			}
			freshOperation, err := operationRepo.GetPolicy(ctx, user.TenantID, "tenant", "")
			if err != nil && !errors.Is(err, repository.ErrAgentOperationNotFound) {
				t.Fatal(err)
			}
			freshGuard, err := guardRepo.GetPolicy(ctx, user.TenantID, guardID)
			if err != nil {
				t.Fatal(err)
			}
			freshMCP, err := deps.MCPPolicyRepo.ListByTenant(ctx, user.TenantID, "")
			if err != nil {
				t.Fatal(err)
			}
			freshGuardPolicies, err := guardRepo.ListPolicies(ctx, user.TenantID)
			if err != nil {
				t.Fatal(err)
			}
			if string(operationJSON) != string(mustJSON(t, freshOperation)) || string(guardJSON) != string(mustJSON(t, freshGuard)) || guardSetVersion != repository.PolicyCenterAgentGuardPoliciesVersion(freshGuardPolicies) || mcpVersion != repository.PolicyCenterMCPPoliciesVersion(freshMCP) {
				t.Fatalf("rejected save changed stored objects: operation=%s guard=%s", mustJSON(t, freshOperation), mustJSON(t, freshGuard))
			}
			if variant == "operation_absent_race" && (!shared.saved.Operation.Expected.ExpectedAbsent || shared.saved.Operation.ExpectedStorageVersion != 0) {
				t.Fatalf("absence was conflated with v1: %+v", shared.saved.Operation)
			}
			if variant == "combined_rollback" {
				var audits, versions int
				if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM agent_destructive_policy_audits), (SELECT count(*) FROM agentguard_policy_versions)`).Scan(&audits, &versions); err != nil {
					t.Fatal(err)
				}
				if audits != 1 || versions != 1 {
					t.Fatalf("failed transaction left partial audit/version: %d/%d", audits, versions)
				}
			}
		})
	}
}

func TestPolicyCenterBehaviorCreateCollisionPostgreSQL(t *testing.T) {
	deps, _, _, db, user := consistencyPostgresFixture(t)
	ctx := context.Background()
	states, err := loadPolicyCenterAgentBehaviors(withBehaviorUser(http.MethodGet, "/x", "", user), deps, user.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	mutation, err := preparePolicyCenterAgentBehaviorMutation(user, policyCenterAgentBehaviorStateByKey(states, policyCenterAgentBehaviorMCP), policyCenterAgentBehaviorUpdateRequest{Action: "block"})
	if err != nil {
		t.Fatal(err)
	}
	foreign := &repository.MCPPolicy{ID: mutation.MCP.ID, TenantID: "tenant-other", ScopeType: "tenant", ToolPattern: "*", Mode: "audit", DefaultAction: "audit", Enabled: true}
	if err := deps.MCPPolicyRepo.Create(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	before := mustJSON(t, foreign)
	err = deps.PolicyCenterBehaviorRepo.Save(ctx, mutation)
	if !errors.Is(err, repository.ErrPolicyCenterBehaviorConflict) || !strings.Contains(err.Error(), "23505") {
		t.Fatalf("pure insert collision was not a CAS conflict: %v", err)
	}
	rec := httptest.NewRecorder()
	writePolicyCenterAgentBehaviorSaveError(rec, err)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate insert status=%d body=%s", rec.Code, rec.Body.String())
	}
	policies, err := deps.MCPPolicyRepo.ListByTenant(ctx, foreign.TenantID, "")
	if err != nil {
		t.Fatal(err)
	}
	var own int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM mcp_policies WHERE tenant_id=$1`, user.TenantID).Scan(&own); err != nil {
		t.Fatal(err)
	}
	if own != 0 || len(policies) != 1 || string(before) != string(mustJSON(t, policies[0])) {
		t.Fatalf("insert collision overwrote existing object: own=%d policies=%+v", own, policies)
	}
}

func TestPolicyCenterBehaviorAllPreconditionsBeforeAnyWritePostgreSQL(t *testing.T) {
	for _, stale := range []string{"guard", "mcp", "operation"} {
		t.Run(stale, func(t *testing.T) {
			deps, operationRepo, guardRepo, db, user := consistencyPostgresFixture(t)
			ctx := context.Background()
			if err := deps.MCPPolicyRepo.Create(ctx, &repository.MCPPolicy{ID: "mcp-base", TenantID: user.TenantID, ScopeType: "tenant", ToolPattern: "*", Mode: "audit", DefaultAction: "audit", Enabled: true}); err != nil {
				t.Fatal(err)
			}
			states, err := loadPolicyCenterAgentBehaviors(withBehaviorUser(http.MethodGet, "/x", "", user), deps, user.TenantID)
			if err != nil {
				t.Fatal(err)
			}
			patterns := []string{"candidate/**"}
			mutation, err := preparePolicyCenterAgentBehaviorMutation(user, policyCenterAgentBehaviorStateByKey(states, policyCenterAgentBehaviorFile), policyCenterAgentBehaviorUpdateRequest{Action: "block", RestrictedFilePatterns: &patterns})
			if err != nil {
				t.Fatal(err)
			}
			mcpMutation, err := preparePolicyCenterAgentBehaviorMutation(user, policyCenterAgentBehaviorStateByKey(states, policyCenterAgentBehaviorMCP), policyCenterAgentBehaviorUpdateRequest{Action: "block"})
			if err != nil {
				t.Fatal(err)
			}
			mutation.MCP = mcpMutation.MCP
			switch stale {
			case "guard":
				mutation.AgentGuard.Expected.ExpectedVersion = "stale"
			case "mcp":
				mutation.MCP.Expected.ExpectedVersion = "stale"
			case "operation":
				mutation.Operation.Expected.ExpectedVersion = "stale"
			}
			snapshot := func() []byte {
				guards, err := guardRepo.ListPolicies(ctx, user.TenantID)
				if err != nil {
					t.Fatal(err)
				}
				mcps, err := deps.MCPPolicyRepo.ListByTenant(ctx, user.TenantID, "")
				if err != nil {
					t.Fatal(err)
				}
				operation, err := operationRepo.GetPolicy(ctx, user.TenantID, "tenant", "")
				if err != nil {
					t.Fatal(err)
				}
				return mustJSON(t, []any{guards, mcps, operation})
			}
			before := snapshot()
			if _, err := db.Exec(ctx, `
				CREATE FUNCTION reject_behavior_write() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''write before complete preconditions''; END';
				CREATE TRIGGER reject_guard_write BEFORE INSERT OR UPDATE ON agentguard_policies FOR EACH ROW EXECUTE FUNCTION reject_behavior_write();
				CREATE TRIGGER reject_mcp_write BEFORE INSERT OR UPDATE ON mcp_policies FOR EACH ROW EXECUTE FUNCTION reject_behavior_write();
				CREATE TRIGGER reject_operation_write BEFORE INSERT OR UPDATE ON agent_destructive_policies FOR EACH ROW EXECUTE FUNCTION reject_behavior_write()
			`); err != nil {
				t.Fatal(err)
			}
			if err := deps.PolicyCenterBehaviorRepo.Save(ctx, mutation); !errors.Is(err, repository.ErrPolicyCenterBehaviorConflict) {
				t.Fatalf("stale %s expected conflict: %v", stale, err)
			}
			var audits, versions int
			if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM agent_destructive_policy_audits), (SELECT count(*) FROM agentguard_policy_versions)`).Scan(&audits, &versions); err != nil {
				t.Fatal(err)
			}
			if string(before) != string(snapshot()) || audits != 1 || versions != 1 {
				t.Fatalf("stale %s left partial writes: audits=%d versions=%d", stale, audits, versions)
			}
		})
	}
}

func TestPolicyCenterBehaviorConcurrentUpdatePostgreSQL(t *testing.T) {
	for _, key := range []string{policyCenterAgentBehaviorDestructive, policyCenterAgentBehaviorFile, policyCenterAgentBehaviorMCP} {
		t.Run(key, func(t *testing.T) {
			deps, _, _, db, user := consistencyPostgresFixture(t)
			ctx := context.Background()
			if key == policyCenterAgentBehaviorMCP {
				if err := deps.MCPPolicyRepo.Create(ctx, &repository.MCPPolicy{ID: "mcp-base", TenantID: user.TenantID, ScopeType: "tenant", ToolPattern: "*", Mode: "audit", DefaultAction: "audit", Enabled: true}); err != nil {
					t.Fatal(err)
				}
			}
			states, err := loadPolicyCenterAgentBehaviors(withBehaviorUser(http.MethodGet, "/x", "", user), deps, user.TenantID)
			if err != nil {
				t.Fatal(err)
			}
			state := policyCenterAgentBehaviorStateByKey(states, key)
			var mutations []repository.PolicyCenterAgentBehaviorMutation
			for index, action := range []string{"block", "alert_allow"} {
				request := policyCenterAgentBehaviorUpdateRequest{Action: action}
				if key == policyCenterAgentBehaviorFile {
					patterns := []string{fmt.Sprintf("candidate%d/**", index)}
					request.RestrictedFilePatterns = &patterns
				}
				mutation, err := preparePolicyCenterAgentBehaviorMutation(user, state, request)
				if err != nil {
					t.Fatal(err)
				}
				mutations = append(mutations, mutation)
			}
			start := make(chan struct{})
			results := make(chan struct {
				index int
				err   error
			}, 2)
			var wait sync.WaitGroup
			for index, mutation := range mutations {
				wait.Add(1)
				go func(index int, mutation repository.PolicyCenterAgentBehaviorMutation) {
					defer wait.Done()
					<-start
					err := deps.PolicyCenterBehaviorRepo.Save(ctx, mutation)
					results <- struct {
						index int
						err   error
					}{index, err}
				}(index, mutation)
			}
			close(start)
			wait.Wait()
			close(results)
			winner, successes, conflicts := -1, 0, 0
			for result := range results {
				if result.err == nil {
					winner = result.index
					successes++
				} else if errors.Is(result.err, repository.ErrPolicyCenterBehaviorConflict) {
					conflicts++
				} else {
					t.Fatalf("unexpected update error: %v", result.err)
				}
			}
			if successes != 1 || conflicts != 1 {
				t.Fatalf("stale concurrent update accepted: success=%d conflicts=%d", successes, conflicts)
			}
			fresh := consistencyBehaviorItem(t, deps, user, key)
			wantAction := []string{"block", "alert_allow"}[winner]
			if fresh["configured_action"] != wantAction {
				t.Fatalf("winner not stored: winner=%d fresh=%#v", winner, fresh)
			}
			if key == policyCenterAgentBehaviorFile && !reflect.DeepEqual(fresh["restricted_file_patterns"], []any{fmt.Sprintf("candidate%d/**", winner)}) {
				t.Fatalf("mixed combined write: winner=%d fresh=%#v", winner, fresh)
			}
			var audits, versions int
			if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM agent_destructive_policy_audits), (SELECT count(*) FROM agentguard_policy_versions)`).Scan(&audits, &versions); err != nil {
				t.Fatal(err)
			}
			wantAudits, wantVersions := 1, 1
			if key != policyCenterAgentBehaviorMCP {
				wantAudits = 2
			}
			if key == policyCenterAgentBehaviorFile {
				wantVersions = 2
			}
			if audits != wantAudits || versions != wantVersions {
				t.Fatalf("loser left partial writes: audits=%d versions=%d", audits, versions)
			}
		})
	}
}

func TestPolicyCenterBehaviorConcurrentCreatePostgreSQL(t *testing.T) {
	for _, key := range []string{policyCenterAgentBehaviorDestructive, policyCenterAgentBehaviorSystem, policyCenterAgentBehaviorMCP} {
		t.Run(key, func(t *testing.T) {
			deps, _, _, db, user := consistencyPostgresFixture(t)
			ctx := context.Background()
			if _, err := db.Exec(ctx, `DELETE FROM agent_destructive_policy_audits; DELETE FROM agent_destructive_policies; DELETE FROM agentguard_policy_versions; DELETE FROM agentguard_policies`); err != nil {
				t.Fatal(err)
			}
			states, err := loadPolicyCenterAgentBehaviors(withBehaviorUser(http.MethodGet, "/x", "", user), deps, user.TenantID)
			if err != nil {
				t.Fatal(err)
			}
			state := policyCenterAgentBehaviorStateByKey(states, key)
			first, err := preparePolicyCenterAgentBehaviorMutation(user, state, policyCenterAgentBehaviorUpdateRequest{Action: "block"})
			if err != nil {
				t.Fatal(err)
			}
			second, err := preparePolicyCenterAgentBehaviorMutation(user, state, policyCenterAgentBehaviorUpdateRequest{Action: "alert_allow"})
			if err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			results := make(chan error, 2)
			var wait sync.WaitGroup
			for _, mutation := range []repository.PolicyCenterAgentBehaviorMutation{first, second} {
				wait.Add(1)
				go func(mutation repository.PolicyCenterAgentBehaviorMutation) {
					defer wait.Done()
					<-start
					results <- deps.PolicyCenterBehaviorRepo.Save(ctx, mutation)
				}(mutation)
			}
			close(start)
			wait.Wait()
			close(results)
			passed, conflicted := 0, 0
			for err := range results {
				if err == nil {
					passed++
				} else if errors.Is(err, repository.ErrPolicyCenterBehaviorConflict) {
					conflicted++
				} else {
					t.Fatalf("unexpected create result: %v", err)
				}
			}
			if passed != 1 || conflicted != 1 {
				t.Fatalf("create-only allowed overwrite: passed=%d conflicts=%d", passed, conflicted)
			}
			var operations, guards, mcps, audits, versions int
			if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM agent_destructive_policies), (SELECT count(*) FROM agentguard_policies), (SELECT count(*) FROM mcp_policies), (SELECT count(*) FROM agent_destructive_policy_audits), (SELECT count(*) FROM agentguard_policy_versions)`).Scan(&operations, &guards, &mcps, &audits, &versions); err != nil {
				t.Fatal(err)
			}
			wantOperation, wantGuard, wantMCP := 0, 0, 0
			switch key {
			case policyCenterAgentBehaviorDestructive:
				wantOperation = 1
			case policyCenterAgentBehaviorSystem:
				wantGuard = 1
			case policyCenterAgentBehaviorMCP:
				wantMCP = 1
			}
			if operations != wantOperation || guards != wantGuard || mcps != wantMCP || audits != wantOperation || versions != wantGuard {
				t.Fatalf("concurrent create partial writes: %d/%d/%d audits/versions=%d/%d", operations, guards, mcps, audits, versions)
			}
		})
	}
}

func TestPolicyCenterSensitiveResourceUnchangedRestrictedFieldsPostgreSQL(t *testing.T) {
	for _, variant := range []string{"patterns", "restricted_action", "both", "empty_patterns", "nil_patterns", "missing_policy_defaults", "empty_stored_action", "operation_race", "operation_absent_race", "guard_race", "audit_failure"} {
		t.Run(variant, func(t *testing.T) {
			deps, operationRepo, guardRepo, db, user := consistencyPostgresFixture(t)
			ctx := context.Background()
			switch variant {
			case "empty_patterns":
				if _, err := db.Exec(ctx, `UPDATE agent_destructive_policies SET restricted_file_patterns_json='[]'::jsonb`); err != nil {
					t.Fatal(err)
				}
			case "nil_patterns":
				if _, err := db.Exec(ctx, `UPDATE agent_destructive_policies SET restricted_file_patterns_json='null'::jsonb`); err != nil {
					t.Fatal(err)
				}
			case "missing_policy_defaults", "operation_absent_race":
				if _, err := db.Exec(ctx, `DELETE FROM agent_destructive_policy_audits; DELETE FROM agent_destructive_policies`); err != nil {
					t.Fatal(err)
				}
			case "empty_stored_action":
				if _, err := db.Exec(ctx, `UPDATE agent_destructive_policies SET restricted_file_action=''`); err != nil {
					t.Fatal(err)
				}
			}
			item := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
			operation, err := operationRepo.GetPolicy(ctx, user.TenantID, "tenant", "")
			if err != nil && !errors.Is(err, repository.ErrAgentOperationNotFound) {
				t.Fatal(err)
			}
			guardID := policyCenterAgentGuardPolicyIDFor(user.TenantID)
			guard, err := guardRepo.GetPolicy(ctx, user.TenantID, guardID)
			if err != nil {
				t.Fatal(err)
			}
			expectedOperation, expectedGuard := mustJSON(t, operation), mustJSON(t, guard)
			var auditsBefore, versionsBefore int
			if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM agent_destructive_policy_audits), (SELECT count(*) FROM agentguard_policy_versions)`).Scan(&auditsBefore, &versionsBefore); err != nil {
				t.Fatal(err)
			}
			body := map[string]any{"action": "block", "version": item["version"]}
			if variant != "restricted_action" {
				body["restricted_file_patterns"] = item["restricted_file_patterns"]
			}
			if variant != "patterns" {
				body["restricted_file_action"] = item["restricted_file_action"]
			}
			wantStatus := http.StatusOK
			if strings.HasSuffix(variant, "race") {
				wantStatus = http.StatusConflict
			}
			if variant == "audit_failure" {
				wantStatus = http.StatusInternalServerError
				if _, err := db.Exec(ctx, `
					CREATE FUNCTION consistency_reject_guard_version() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN RAISE EXCEPTION 'forced guard version failure'; END $$;
					CREATE TRIGGER consistency_reject_guard_version BEFORE INSERT ON agentguard_policy_versions
					FOR EACH ROW EXECUTE FUNCTION consistency_reject_guard_version();
				`); err != nil {
					t.Fatal(err)
				}
			}
			shared := &consistencyPostgresBehaviorRepo{PolicyCenterAgentBehaviorRepo: deps.PolicyCenterBehaviorRepo, beforeSave: func() error {
				switch variant {
				case "operation_race":
					if _, err := db.Exec(ctx, `UPDATE agent_destructive_policies SET restricted_file_patterns_json='["concurrent/**"]'::jsonb, version=version+1`); err != nil {
						return err
					}
				case "operation_absent_race":
					if _, err := operationRepo.SavePolicy(ctx, repository.AgentOperationPolicyMutation{
						TenantID: user.TenantID, ActorID: user.ID, Source: "concurrent_test", ScopeType: "tenant",
						Mode: "audit", Action: "record", RestrictedFileAction: "block", ExpectedVersion: 1,
					}); err != nil {
						return err
					}
					auditsBefore++
				case "guard_race":
					if _, err := db.Exec(ctx, `UPDATE agentguard_policies SET name=name || '-concurrent' WHERE id=$1`, guardID); err != nil {
						return err
					}
					fresh, err := guardRepo.GetPolicy(ctx, user.TenantID, guardID)
					if err != nil {
						return err
					}
					expectedGuard = mustJSON(t, fresh)
				}
				if variant == "operation_race" || variant == "operation_absent_race" {
					fresh, err := operationRepo.GetPolicy(ctx, user.TenantID, "tenant", "")
					if err != nil {
						return err
					}
					expectedOperation = mustJSON(t, fresh)
				}
				return nil
			}}
			deps.PolicyCenterBehaviorRepo = shared
			rec := consistencyPut(t, deps, user, policyCenterAgentBehaviorFile, body)
			if rec.Code != wantStatus {
				t.Fatalf("unchanged restricted fields status=%d want=%d body=%s", rec.Code, wantStatus, rec.Body.String())
			}
			if shared.saved.AgentGuard == nil || shared.saved.AgentGuard.Policy == nil || shared.saved.AgentGuard.Expected.ExpectedVersion != repository.PolicyCenterSnapshotVersion(guard) || shared.saved.Operation == nil || shared.saved.Operation.Mutation != nil {
				t.Fatalf("baseline-only conditional mutation lost: %+v", shared.saved)
			}
			if operation == nil {
				if !shared.saved.Operation.Expected.ExpectedAbsent || shared.saved.Operation.ExpectedStorageVersion != 0 {
					t.Fatalf("missing operation precondition lost: %+v", shared.saved.Operation)
				}
			} else if shared.saved.Operation.Expected.ExpectedVersion != repository.PolicyCenterSnapshotVersion(operation) || shared.saved.Operation.ExpectedStorageVersion != operation.Version {
				t.Fatalf("read-only operation precondition lost: %+v", shared.saved.Operation)
			}
			stored, err := operationRepo.GetPolicy(ctx, user.TenantID, "tenant", "")
			if err != nil && !errors.Is(err, repository.ErrAgentOperationNotFound) {
				t.Fatal(err)
			}
			if string(expectedOperation) != string(mustJSON(t, stored)) {
				t.Fatalf("baseline-only request wrote operation: expected=%s actual=%s", expectedOperation, mustJSON(t, stored))
			}
			freshGuard, err := guardRepo.GetPolicy(ctx, user.TenantID, guardID)
			if err != nil {
				t.Fatal(err)
			}
			var auditsAfter, versionsAfter int
			if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM agent_destructive_policy_audits), (SELECT count(*) FROM agentguard_policy_versions)`).Scan(&auditsAfter, &versionsAfter); err != nil {
				t.Fatal(err)
			}
			wantVersions := versionsBefore
			if wantStatus == http.StatusOK {
				wantVersions++
				var response map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				fresh := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
				for _, projection := range []map[string]any{response, fresh} {
					if projection["configured_action"] != "block" || projection["version"] == item["version"] || !reflect.DeepEqual(projection["restricted_file_patterns"], item["restricted_file_patterns"]) || projection["restricted_file_action"] != item["restricted_file_action"] {
						t.Fatalf("baseline update did not roundtrip: %#v", projection)
					}
				}
			} else if string(expectedGuard) != string(mustJSON(t, freshGuard)) {
				t.Fatalf("rejected baseline update wrote guard: expected=%s actual=%s", expectedGuard, mustJSON(t, freshGuard))
			}
			if auditsAfter != auditsBefore || versionsAfter != wantVersions {
				t.Fatalf("unexpected audits/versions: %d/%d want=%d/%d", auditsAfter, versionsAfter, auditsBefore, wantVersions)
			}
		})
	}
}

func TestPolicyCenterSensitiveResourcePostgreSQLConsistency(t *testing.T) {
	for _, variant := range []string{"roundtrip", "operation_conflict", "guard_conflict", "combined", "combined_patterns", "combined_restricted_action", "combined_same_patterns_changed_action", "combined_changed_patterns_same_action", "combined_clear_patterns", "combined_reordered_patterns", "storage_cas"} {
		t.Run(variant, func(t *testing.T) {
			deps, operationRepo, guardRepo, db, user := consistencyPostgresFixture(t)
			ctx := context.Background()
			item := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
			if item["health"] != "ok" || !reflect.DeepEqual(item["restricted_file_patterns"], []any{"contracts/**", "*.pdf"}) || item["restricted_file_action"] != "alert_allow" {
				t.Fatalf("GET did not project stored configuration: %#v", item)
			}
			operation, err := operationRepo.GetPolicy(ctx, user.TenantID, "tenant", "")
			if err != nil {
				t.Fatal(err)
			}
			guardID := policyCenterAgentGuardPolicyIDFor(user.TenantID)
			guard, err := guardRepo.GetPolicy(ctx, user.TenantID, guardID)
			if err != nil {
				t.Fatal(err)
			}
			expectedOperation := mustJSON(t, operation)
			expectedGuard := mustJSON(t, guard)
			concurrent := repository.AgentOperationPolicyMutation{
				TenantID: user.TenantID, ActorID: user.ID, Source: "concurrent_test",
				ScopeType: "tenant", Mode: operation.Mode, Action: operation.Action, Protocol: operation.Protocol,
				DiscardablePaths: operation.DiscardablePaths, NotifyChannelIDs: operation.NotifyChannelIDs,
				RestrictedFilePatterns: []string{"concurrent/**"}, RestrictedFileAction: operation.RestrictedFileAction,
				ExpectedVersion: operation.Version,
			}
			concurrentWrite := func() error {
				if _, err := operationRepo.SavePolicy(ctx, concurrent); err != nil {
					return err
				}
				fresh, err := operationRepo.GetPolicy(ctx, user.TenantID, "tenant", "")
				if err == nil {
					expectedOperation = mustJSON(t, fresh)
				}
				return err
			}
			body := map[string]any{
				"action": item["configured_action"], "version": item["version"],
				"restricted_file_patterns": []string{"*.docx"}, "restricted_file_action": "record",
			}
			wantStatus := http.StatusConflict
			shared := &consistencyPostgresBehaviorRepo{PolicyCenterAgentBehaviorRepo: deps.PolicyCenterBehaviorRepo, beforeSave: func() error { return nil }}
			deps.PolicyCenterBehaviorRepo = shared
			var racingRepo *consistencyPostgresBehaviorRepo
			switch variant {
			case "roundtrip":
				wantStatus = http.StatusOK
			case "operation_conflict":
				if err := concurrentWrite(); err != nil {
					t.Fatal(err)
				}
			case "guard_conflict":
				guard.Name += "-concurrent"
				if _, _, _, err := guardRepo.UpdatePolicyWithVersion(ctx, guard, user.ID); err != nil {
					t.Fatal(err)
				}
				fresh, err := guardRepo.GetPolicy(ctx, user.TenantID, guardID)
				if err != nil {
					t.Fatal(err)
				}
				expectedGuard = mustJSON(t, fresh)
			case "combined", "combined_patterns", "combined_restricted_action", "combined_same_patterns_changed_action", "combined_changed_patterns_same_action", "combined_clear_patterns", "combined_reordered_patterns":
				body["action"] = "block"
				wantStatus = http.StatusBadRequest
				switch variant {
				case "combined_patterns":
					delete(body, "restricted_file_action")
				case "combined_restricted_action":
					delete(body, "restricted_file_patterns")
				case "combined_same_patterns_changed_action":
					body["restricted_file_patterns"] = item["restricted_file_patterns"]
				case "combined_changed_patterns_same_action":
					body["restricted_file_action"] = item["restricted_file_action"]
				case "combined_clear_patterns":
					body["restricted_file_patterns"] = []string{}
					delete(body, "restricted_file_action")
				case "combined_reordered_patterns":
					body["restricted_file_patterns"] = []string{"*.pdf", "contracts/**"}
					delete(body, "restricted_file_action")
				}
			case "storage_cas":
				racingRepo = &consistencyPostgresBehaviorRepo{PolicyCenterAgentBehaviorRepo: deps.PolicyCenterBehaviorRepo, beforeSave: concurrentWrite}
				deps.PolicyCenterBehaviorRepo = racingRepo
			}
			rec := consistencyPut(t, deps, user, policyCenterAgentBehaviorFile, body)
			if rec.Code != wantStatus {
				t.Fatalf("PUT status=%d want=%d body=%s", rec.Code, wantStatus, rec.Body.String())
			}
			if strings.HasPrefix(variant, "combined") && (shared.saved.TenantID != "" || !strings.Contains(rec.Body.String(), "combined_update_not_supported")) {
				t.Fatalf("combined request reached conditional writer: %+v body=%s", shared.saved, rec.Body.String())
			}
			stored, err := operationRepo.GetPolicy(ctx, user.TenantID, "tenant", "")
			if err != nil {
				t.Fatal(err)
			}
			if variant == "roundtrip" {
				if stored.Version != operation.Version+1 || stored.Mode != operation.Mode || stored.Action != operation.Action || stored.Protocol != operation.Protocol || !reflect.DeepEqual(stored.DiscardablePaths, operation.DiscardablePaths) || !reflect.DeepEqual(stored.NotifyChannelIDs, operation.NotifyChannelIDs) || !reflect.DeepEqual(stored.RestrictedFilePatterns, []string{"*.docx"}) || stored.RestrictedFileAction != "record" {
					t.Fatalf("stored mutation lost configuration: before=%+v after=%+v", operation, stored)
				}
				var response map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				fresh := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorFile)
				for _, projection := range []map[string]any{response, fresh} {
					if !reflect.DeepEqual(projection["restricted_file_patterns"], []any{"*.docx"}) || projection["restricted_file_action"] != "record" || projection["version"] == item["version"] {
						t.Fatalf("save did not roundtrip: %#v", projection)
					}
				}
			} else if string(expectedOperation) != string(mustJSON(t, stored)) {
				t.Fatalf("rejected save modified operation: expected=%s actual=%s", expectedOperation, mustJSON(t, stored))
			}
			if racingRepo != nil && racingRepo.saved.Operation.ExpectedStorageVersion != operation.Version {
				t.Fatalf("write did not use loaded storage version: %+v", racingRepo.saved)
			}
			freshGuard, err := guardRepo.GetPolicy(ctx, user.TenantID, guardID)
			if err != nil {
				t.Fatal(err)
			}
			if string(expectedGuard) != string(mustJSON(t, freshGuard)) {
				t.Fatalf("restricted save changed guard: expected=%s actual=%s", expectedGuard, mustJSON(t, freshGuard))
			}
			var operationAudits, guardVersions int
			if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM agent_destructive_policy_audits), (SELECT count(*) FROM agentguard_policy_versions)`).Scan(&operationAudits, &guardVersions); err != nil {
				t.Fatal(err)
			}
			wantOperationAudits, wantGuardVersions := 1, 1
			if variant == "roundtrip" || variant == "operation_conflict" || variant == "storage_cas" {
				wantOperationAudits = 2
			}
			if variant == "guard_conflict" {
				wantGuardVersions = 2
			}
			if operationAudits != wantOperationAudits || guardVersions != wantGuardVersions {
				t.Fatalf("unexpected partial writes: operation audits=%d guard versions=%d want=%d/%d", operationAudits, guardVersions, wantOperationAudits, wantGuardVersions)
			}
		})
	}
}
