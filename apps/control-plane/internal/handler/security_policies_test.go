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

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
	"github.com/go-chi/chi/v5"
)

type fakeSecurityPolicyStore struct {
	policies     []repository.SecurityPolicy
	capabilities []repository.SecurityPolicyCapability
	created      repository.CreateSecurityPolicyInput
	updatedID    string
	updated      repository.SecurityPolicyUpdate
	batch        []repository.SecurityPolicyBatchUpdate
	createErr    error
	updateErr    error
	batchErr     error
	deletedID    string
	deleteErr    error
	updateResult *repository.SecurityPolicy
}

func (f *fakeSecurityPolicyStore) ListSecurityPolicies(context.Context, string) ([]repository.SecurityPolicy, error) {
	return append([]repository.SecurityPolicy(nil), f.policies...), nil
}

func (f *fakeSecurityPolicyStore) GetSecurityPolicy(_ context.Context, _ string, id string) (*repository.SecurityPolicy, error) {
	for i := range f.policies {
		if f.policies[i].ID == id {
			copy := f.policies[i]
			return &copy, nil
		}
	}
	return nil, repository.ErrSecurityPolicyNotFound
}

func (f *fakeSecurityPolicyStore) ListSecurityCapabilities(context.Context) ([]repository.SecurityPolicyCapability, error) {
	return append([]repository.SecurityPolicyCapability(nil), f.capabilities...), nil
}

func (f *fakeSecurityPolicyStore) CreateSecurityPolicy(_ context.Context, _ string, input repository.CreateSecurityPolicyInput) (*repository.SecurityPolicy, error) {
	f.created = input
	if f.createErr != nil {
		return nil, f.createErr
	}
	return &repository.SecurityPolicy{ID: "policy-new", Name: input.Name, Scene: input.Scene, Severity: input.Severity, Action: input.Action, Enabled: input.Enabled, Source: "tenant"}, nil
}

func (f *fakeSecurityPolicyStore) UpdateSecurityPolicy(_ context.Context, _ string, id string, update repository.SecurityPolicyUpdate) (*repository.SecurityPolicy, error) {
	f.updatedID = id
	f.updated = update
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	if f.updateResult != nil {
		result := *f.updateResult
		return &result, nil
	}
	return &repository.SecurityPolicy{ID: id, Name: "updated", Scene: "data_security", Severity: "high", Action: "block", Enabled: true, Source: "tenant"}, nil
}

func (f *fakeSecurityPolicyStore) BatchUpdateSecurityPolicies(_ context.Context, _ string, updates []repository.SecurityPolicyBatchUpdate) error {
	f.batch = append([]repository.SecurityPolicyBatchUpdate(nil), updates...)
	return f.batchErr
}

func (f *fakeSecurityPolicyStore) DeleteSecurityPolicy(_ context.Context, _ string, id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deletedID = id
	return nil
}

type fakeRegexValidator struct {
	valid     bool
	errorCode string
	err       error
	patterns  []string
}

func (f *fakeRegexValidator) ValidateRegex(_ context.Context, pattern string) (bool, string, error) {
	f.patterns = append(f.patterns, pattern)
	return f.valid, f.errorCode, f.err
}

func policyHandlerRequest(method, target, body, role string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	user := &repository.User{ID: "user-a", TenantID: "tenant-a", Role: role, Status: "active"}
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
}

func withPolicyID(req *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestSecurityPoliciesListReturnsAllAndHidesInternalFields(t *testing.T) {
	store := &fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{
		{ID: "system-1", PolicyCode: "builtin.secret", RuleType: "regex", Name: "密钥检测", Scene: "data_security", Severity: "critical", Action: "block", Enabled: true, Source: "system", DetectionConfigured: true, DetectionReady: true, Capabilities: []repository.SecurityPolicyCapability{{Category: "semantic_roleplay", Name: "语义角色扮演绕过", Kind: "dynamic", Component: "security-engine.semantic", Enabled: true, BindingMode: "any"}}},
		{ID: "system-2", PolicyCode: "builtin.pending", RuleType: "prompt_injection", Name: "越权指令", Scene: "prompt_security", Severity: "high", Action: "audit", Enabled: true, Source: "system", DetectionConfigured: true, DetectionReady: false, DetectionIssue: "runtime_binding_pending"},
		{ID: "system-3", PolicyCode: "builtin.empty", RuleType: "fraud_detect", Name: "欺诈引导", Scene: "fraud_risk", Severity: "high", Action: "audit", Enabled: false, Source: "system", DetectionConfigured: false, DetectionReady: false},
		{ID: "system-4", PolicyCode: "builtin.paused", RuleType: "regex", Name: "已停用检测", Scene: "data_security", Severity: "medium", Action: "audit", Enabled: false, Source: "system", DetectionConfigured: true, DetectionReady: true},
	}}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, &fakeRegexValidator{valid: true})
	rec := httptest.NewRecorder()
	h.list(rec, policyHandlerRequest(http.MethodGet, "/admin/v1/security/policies", "", "auditor"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["total"] != float64(4) || response["configured_count"] != float64(3) || response["ready_count"] != float64(2) || response["active_count"] != float64(0) {
		t.Fatalf("unexpected summary: %#v", response)
	}
	if response["runtime_verified"] != false || response["runtime_status"] != "unavailable" {
		t.Fatalf("missing runtime proof must be explicit: %#v", response)
	}
	items, ok := response["data"].([]any)
	if !ok || len(items) != 4 {
		t.Fatalf("unexpected data: %#v", response["data"])
	}
	readyWithoutReceipt := items[0].(map[string]any)
	if readyWithoutReceipt["detection_ready"] != true || readyWithoutReceipt["runtime_active"] != false {
		t.Fatalf("ready policy without runtime receipt was misrepresented: %#v", readyWithoutReceipt)
	}
	capabilities, ok := readyWithoutReceipt["capabilities"].([]any)
	if !ok || len(capabilities) != 1 || capabilities[0].(map[string]any)["semantic_judge"] != true {
		t.Fatalf("policy capability must expose that it is evaluated by the semantic judge: %#v", readyWithoutReceipt["capabilities"])
	}
	if _, stale := capabilities[0].(map[string]any)["semantic_audit_only"]; stale {
		t.Fatalf("semantic capabilities are no longer audit-only; stale flag leaked: %#v", capabilities[0])
	}
	if readyWithoutReceipt["semantic_action"] != "audit" {
		t.Fatalf("unset semantic action must be reported as audit: %#v", readyWithoutReceipt["semantic_action"])
	}
	paused := items[3].(map[string]any)
	if paused["detection_ready"] != true || paused["runtime_active"] != false {
		t.Fatalf("disabled ready policy was misrepresented: %#v", paused)
	}
	body := rec.Body.String()
	for _, forbidden := range []string{"policy_code", "rule_type", "builtin.secret"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response leaks internal field %q: %s", forbidden, body)
		}
	}
}

func TestSecurityPoliciesListUsesOnlyCompleteVerifiedRuntimeProof(t *testing.T) {
	store := &fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{
		{ID: "policy-active", Enabled: true, DetectionConfigured: true, DetectionReady: true},
		{ID: "policy-disabled", Enabled: false, DetectionConfigured: true, DetectionReady: true},
		{ID: "policy-not-in-pack", Enabled: true, DetectionConfigured: true, DetectionReady: true},
	}}
	actualSkipped := 0
	proof := func(_ context.Context, tenantID string) (securityPolicyRuntimeProof, error) {
		if tenantID != "tenant-a" {
			t.Fatalf("runtime proof tenant=%q want tenant-a", tenantID)
		}
		return securityPolicyRuntimeProof{
			RuntimeVerified:    true,
			RuntimeStatus:      runtimeStatusApplied,
			ActualSkippedCount: &actualSkipped,
			ActivePolicyIDs: map[string]struct{}{
				"policy-active":   {},
				"policy-disabled": {},
			},
		}, nil
	}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, &fakeRegexValidator{valid: true}, proof)
	rec := httptest.NewRecorder()
	h.list(rec, policyHandlerRequest(http.MethodGet, "/admin/v1/security/policies", "", "auditor"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response securityPoliciesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.RuntimeVerified || response.RuntimeStatus != runtimeStatusApplied || response.ActiveCount != 1 {
		t.Fatalf("runtime summary=%+v", response)
	}
	if !response.Data[0].RuntimeActive {
		t.Fatalf("verified enabled policy was not active: %+v", response.Data[0])
	}
	if response.Data[1].RuntimeActive {
		t.Fatalf("disabled policy was active despite proof membership: %+v", response.Data[1])
	}
	if response.Data[2].RuntimeActive {
		t.Fatalf("policy absent from proof was active: %+v", response.Data[2])
	}
}

func TestActiveSecurityPolicyIDsUnionsPoliciesAndLegacyRules(t *testing.T) {
	pack := &rules.RulePack{
		Policies: []rules.CompiledPolicy{
			{PolicyID: "policy-capability"},
			{PolicyID: "policy-shared"},
			{PolicyID: "  "},
		},
		Rules: []rules.CompiledRule{
			{RuleID: "policy-legacy-matcher"},
			{RuleID: "policy-shared"},
			{RuleID: ""},
		},
	}
	got := activeSecurityPolicyIDs(pack)
	if len(got) != 3 {
		t.Fatalf("active ids=%v want three unique ids", got)
	}
	for _, id := range []string{"policy-capability", "policy-legacy-matcher", "policy-shared"} {
		if _, ok := got[id]; !ok {
			t.Fatalf("active ids missing %q: %v", id, got)
		}
	}
}

func TestSecurityPoliciesListTreatsCompleteReceiptAsRuntimeReadinessProof(t *testing.T) {
	store := &fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{{
		ID: "system-regex", Enabled: true, DetectionConfigured: true,
		DetectionReady: false, DetectionIssue: "runtime_validation_required",
	}}}
	zero := 0
	proof := func(context.Context, string) (securityPolicyRuntimeProof, error) {
		return securityPolicyRuntimeProof{
			RuntimeVerified: true, RuntimeStatus: runtimeStatusApplied,
			ActualSkippedCount: &zero,
			ActivePolicyIDs:    map[string]struct{}{"system-regex": {}},
		}, nil
	}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, &fakeRegexValidator{valid: true}, proof)
	rec := httptest.NewRecorder()
	h.list(rec, policyHandlerRequest(http.MethodGet, "/admin/v1/security/policies", "", "auditor"))
	var response securityPoliciesResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &response) != nil {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if response.ReadyCount != 1 || response.ActiveCount != 1 || response.PendingCount != 0 {
		t.Fatalf("receipt-backed summary=%+v want ready=1 active=1 pending=0", response)
	}
	if !response.Data[0].DetectionReady || !response.Data[0].RuntimeActive || response.Data[0].DetectionIssue != "" {
		t.Fatalf("receipt-backed policy=%+v", response.Data[0])
	}
}

func TestSecurityPoliciesListNeverGuessesActivePoliciesFromDegradedProof(t *testing.T) {
	store := &fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{{
		ID: "policy-ready", Enabled: true, DetectionConfigured: true, DetectionReady: true,
	}}}
	zero := 0
	one := 1
	tests := []struct {
		name  string
		proof securityPolicyRuntimeProof
	}{
		{
			name: "degraded",
			proof: securityPolicyRuntimeProof{
				RuntimeVerified: true, RuntimeStatus: runtimeStatusAppliedDegraded,
				Degraded: true, ActualSkippedCount: &zero,
				ActivePolicyIDs: map[string]struct{}{"policy-ready": {}},
			},
		},
		{
			name: "stale nodes",
			proof: securityPolicyRuntimeProof{
				RuntimeVerified: true, RuntimeStatus: runtimeStatusAppliedWithStaleNodes,
				ActualSkippedCount: &zero,
				ActivePolicyIDs:    map[string]struct{}{"policy-ready": {}},
			},
		},
		{
			name: "actual skipped without per-policy ids",
			proof: securityPolicyRuntimeProof{
				RuntimeVerified: true, RuntimeStatus: runtimeStatusAppliedDegraded,
				ActualSkippedCount: &one,
				ActivePolicyIDs:    map[string]struct{}{"policy-ready": {}},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newSecurityPoliciesHandler(
				&Dependencies{}, store, &fakeRegexValidator{valid: true},
				func(context.Context, string) (securityPolicyRuntimeProof, error) { return tc.proof, nil },
			)
			rec := httptest.NewRecorder()
			h.list(rec, policyHandlerRequest(http.MethodGet, "/admin/v1/security/policies", "", "auditor"))
			var response securityPoliciesResponse
			if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &response) != nil {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if response.RuntimeVerified || response.ActiveCount != 0 || response.Data[0].RuntimeActive {
				t.Fatalf("degraded proof guessed active policy: %+v", response)
			}
		})
	}
}

func TestSecurityPoliciesListKeepsCatalogAvailableWhenRuntimeProofFails(t *testing.T) {
	const errorCanary = "database-password-canary"
	store := &fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{{ID: "policy-1", Enabled: true, DetectionReady: true}}}
	h := newSecurityPoliciesHandler(
		&Dependencies{}, store, &fakeRegexValidator{valid: true},
		func(context.Context, string) (securityPolicyRuntimeProof, error) {
			return securityPolicyRuntimeProof{}, errors.New(errorCanary)
		},
	)
	rec := httptest.NewRecorder()
	h.list(rec, policyHandlerRequest(http.MethodGet, "/admin/v1/security/policies", "", "auditor"))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), errorCanary) {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response securityPoliciesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Total != 1 || response.RuntimeVerified || response.RuntimeStatus != runtimeStatusUnavailable || response.ActiveCount != 0 {
		t.Fatalf("runtime proof failure hid catalog or claimed activity: %+v", response)
	}
}

func TestSecurityPoliciesCreateValidatesRegexInExactRuntime(t *testing.T) {
	store := &fakeSecurityPolicyStore{}
	validator := &fakeRegexValidator{valid: true}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, validator)
	rec := httptest.NewRecorder()
	body := `{"name":"API 密钥格式","description":"检测自定义密钥","scene":"data_security","severity":"high","action":"block","enabled":true,"matcher":{"type":"regex","config":{"regex":"sk-(?=live)[A-Za-z0-9]+"}}}`
	h.create(rec, policyHandlerRequest(http.MethodPost, "/admin/v1/security/policies", body, "platform_admin"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(validator.patterns) != 1 || validator.patterns[0] != "sk-(?=live)[A-Za-z0-9]+" {
		t.Fatalf("runtime validator patterns=%q", validator.patterns)
	}
	if store.created.Matcher == nil || !store.created.Matcher.RuntimeValidated {
		t.Fatal("repository input was not attested by exact runtime")
	}
}

func TestSecurityPoliciesCreateRejectsConflictingDetectionBasesBeforePersistence(t *testing.T) {
	store := &fakeSecurityPolicyStore{}
	validator := &fakeRegexValidator{valid: true}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, validator)
	rec := httptest.NewRecorder()
	body := `{"name":"冲突策略","scene":"data_security","severity":"high","action":"block","enabled":false,"matcher":{"type":"keyword","config":{"keywords":["secret"]}},"capability_categories":["phone_cn"],"binding_mode":"any"}`
	h.create(rec, policyHandlerRequest(http.MethodPost, "/admin/v1/security/policies", body, "platform_admin"))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "conflicting_detection_basis") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if store.created.Name != "" || len(validator.patterns) != 0 {
		t.Fatalf("conflicting policy reached validator or repository: created=%#v patterns=%#v", store.created, validator.patterns)
	}
}

func TestSecurityPoliciesCanonicalizesRegexBeforeRuntimeValidation(t *testing.T) {
	store := &fakeSecurityPolicyStore{}
	validator := &fakeRegexValidator{valid: true}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, validator)
	payload, err := json.Marshal(map[string]any{
		"name": "canonical regex", "scene": "data_security", "severity": "high",
		"action": "block", "enabled": true,
		"matcher": map[string]any{"type": "regex", "config": map[string]any{"regex": "\\ "}},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	rec := httptest.NewRecorder()
	h.create(rec, policyHandlerRequest(http.MethodPost, "/admin/v1/security/policies", string(payload), "platform_admin"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(validator.patterns) != 1 || validator.patterns[0] != "\\" {
		t.Fatalf("validator received non-canonical pattern %#v", validator.patterns)
	}
	var persisted struct {
		Regex string `json:"regex"`
	}
	if err := json.Unmarshal(store.created.Matcher.ConfigJSON, &persisted); err != nil || persisted.Regex != validator.patterns[0] {
		t.Fatalf("validated=%q persisted=%q err=%v", validator.patterns[0], persisted.Regex, err)
	}
}

func TestSecurityPoliciesCreateRejectsInvalidAndUnavailableRegexWithoutLeakingPattern(t *testing.T) {
	const secretPattern = "(?P<customer_secret>"
	tests := []struct {
		name      string
		validator *fakeRegexValidator
		status    int
		code      string
	}{
		{"invalid", &fakeRegexValidator{valid: false, errorCode: "invalid_syntax"}, http.StatusUnprocessableEntity, "regex_invalid_syntax"},
		{"unsafe", &fakeRegexValidator{valid: false, errorCode: "unsafe_pattern"}, http.StatusUnprocessableEntity, "regex_unsafe"},
		{"unavailable", &fakeRegexValidator{err: errors.New("validator unavailable")}, http.StatusServiceUnavailable, "regex_validator_unavailable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeSecurityPolicyStore{}
			h := newSecurityPoliciesHandler(&Dependencies{}, store, tc.validator)
			rec := httptest.NewRecorder()
			body := `{"name":"bad","scene":"data_security","severity":"high","action":"block","enabled":true,"matcher":{"type":"regex","config":{"regex":"` + secretPattern + `"}}}`
			h.create(rec, policyHandlerRequest(http.MethodPost, "/admin/v1/security/policies", body, "platform_admin"))
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.code) {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.status, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), secretPattern) {
				t.Fatalf("response leaked regex: %s", rec.Body.String())
			}
		})
	}
}

func TestSecurityPoliciesWriteRequiresPlatformAdminAndStrictJSON(t *testing.T) {
	store := &fakeSecurityPolicyStore{}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, &fakeRegexValidator{valid: true})

	rec := httptest.NewRecorder()
	h.create(rec, policyHandlerRequest(http.MethodPost, "/admin/v1/security/policies", `{}`, "auditor"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("auditor status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.create(rec, policyHandlerRequest(http.MethodPost, "/admin/v1/security/policies", `{"name":"x","scene":"data_security","severity":"high","action":"audit","enabled":false,"tenant_id":"foreign"}`, "platform_admin"))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Fatalf("unknown field status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSecurityPoliciesPatchAndBatchUseTenantScopedRepository(t *testing.T) {
	store := &fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{{ID: "policy-1", Source: "tenant", RuleType: "keyword", Enabled: true}}}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, &fakeRegexValidator{valid: true})

	rec := httptest.NewRecorder()
	req := withPolicyID(policyHandlerRequest(http.MethodPatch, "/admin/v1/security/policies/policy-1", `{"action":"block","enabled":true}`, "platform_admin"), "policy-1")
	h.update(rec, req)
	if rec.Code != http.StatusOK || store.updatedID != "policy-1" || store.updated.Action == nil || *store.updated.Action != "block" {
		t.Fatalf("patch status=%d id=%q update=%#v body=%s", rec.Code, store.updatedID, store.updated, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.batchUpdate(rec, policyHandlerRequest(http.MethodPost, "/admin/v1/security/policies/batch", `{"updates":[{"id":"policy-1","enabled":false},{"id":"policy-2","action":"audit"}]}`, "platform_admin"))
	if rec.Code != http.StatusOK || len(store.batch) != 2 {
		t.Fatalf("batch status=%d updates=%#v body=%s", rec.Code, store.batch, rec.Body.String())
	}
}

func TestSecurityPoliciesPatchPreservesCapabilityFieldPresence(t *testing.T) {
	store := &fakeSecurityPolicyStore{}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, &fakeRegexValidator{valid: true})

	rec := httptest.NewRecorder()
	req := withPolicyID(
		policyHandlerRequest(
			http.MethodPatch,
			"/admin/v1/security/policies/system-policy",
			`{"capability_categories":["phone_cn"],"binding_mode":"all"}`,
			"platform_admin",
		),
		"system-policy",
	)
	h.update(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("binding patch status=%d body=%s", rec.Code, rec.Body.String())
	}
	if store.updated.CapabilityCategories == nil || len(*store.updated.CapabilityCategories) != 1 || (*store.updated.CapabilityCategories)[0] != "phone_cn" {
		t.Fatalf("binding patch categories=%#v", store.updated.CapabilityCategories)
	}
	if store.updated.BindingMode == nil || *store.updated.BindingMode != "all" {
		t.Fatalf("binding patch mode=%#v", store.updated.BindingMode)
	}
	if store.updated.Action != nil || store.updated.Enabled != nil {
		t.Fatalf("omitted action/enabled became overrides: %#v", store.updated)
	}

	rec = httptest.NewRecorder()
	req = withPolicyID(
		policyHandlerRequest(
			http.MethodPatch,
			"/admin/v1/security/policies/system-policy",
			`{"capability_categories":[],"binding_mode":"any"}`,
			"platform_admin",
		),
		"system-policy",
	)
	h.update(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("explicit clear patch status=%d body=%s", rec.Code, rec.Body.String())
	}
	if store.updated.CapabilityCategories == nil || len(*store.updated.CapabilityCategories) != 0 {
		t.Fatalf("explicit empty capability list lost field presence: %#v", store.updated.CapabilityCategories)
	}

	const internalRuleID = "internal-system-rule-42"
	rec = httptest.NewRecorder()
	req = withPolicyID(
		policyHandlerRequest(
			http.MethodPatch,
			"/admin/v1/security/policies/system-policy",
			`{"capability_categories":[],"binding_mode":"any","rule_id":"`+internalRuleID+`"}`,
			"platform_admin",
		),
		"system-policy",
	)
	h.update(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Fatalf("unknown internal field status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), internalRuleID) || strings.Contains(rec.Body.String(), "rule_id") {
		t.Fatalf("strict JSON error leaked internal field or value: %s", rec.Body.String())
	}
}

func TestSecurityPoliciesRevalidatesStoredTenantRegexWhenEnabling(t *testing.T) {
	store := &fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{{
		ID: "policy-regex", Source: "tenant", RuleType: "regex", Enabled: false,
		MatchConfigJSON: json.RawMessage(`{"regex":"(?=secret)secret"}`),
	}}}
	validator := &fakeRegexValidator{valid: true}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, validator)
	rec := httptest.NewRecorder()
	req := withPolicyID(
		policyHandlerRequest(http.MethodPatch, "/admin/v1/security/policies/policy-regex", `{"enabled":true}`, "platform_admin"),
		"policy-regex",
	)
	h.update(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(validator.patterns) != 1 || validator.patterns[0] != "(?=secret)secret" {
		t.Fatalf("stored regex was not revalidated: %#v", validator.patterns)
	}
	if store.updated.Matcher == nil || !store.updated.Matcher.RuntimeValidated {
		t.Fatalf("revalidated matcher was not passed to repository: %#v", store.updated.Matcher)
	}
}

func TestSecurityPoliciesRevalidatesHiddenSystemRegexWhenEnabling(t *testing.T) {
	store := &fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{{
		ID: "policy-system-regex", Source: "system", RuleType: "regex", Enabled: false,
		InternalMatchConfigJSON: json.RawMessage(`{"regex":"(?=secret)secret"}`),
	}}}
	validator := &fakeRegexValidator{valid: true}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, validator)
	rec := httptest.NewRecorder()
	req := withPolicyID(
		policyHandlerRequest(http.MethodPatch, "/admin/v1/security/policies/policy-system-regex", `{"enabled":true}`, "platform_admin"),
		"policy-system-regex",
	)
	h.update(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(validator.patterns) != 1 || validator.patterns[0] != "(?=secret)secret" {
		t.Fatalf("hidden system matcher was not revalidated: %#v", validator.patterns)
	}
	if !store.updated.RuntimeValidated || store.updated.Matcher != nil {
		t.Fatalf("system re-attestation crossed the read-only boundary: %#v", store.updated)
	}
}

func TestSecurityPoliciesRevalidatesEnabledSystemRegexBeforeActionOnlyUpdate(t *testing.T) {
	store := &fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{{
		ID: "policy-system-regex", Source: "system", RuleType: "regex", Enabled: true,
		InternalMatchConfigJSON: json.RawMessage(`{"regex":"stored-system-pattern"}`),
	}}}
	validator := &fakeRegexValidator{valid: true}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, validator)
	rec := httptest.NewRecorder()
	req := withPolicyID(
		policyHandlerRequest(http.MethodPatch, "/admin/v1/security/policies/policy-system-regex", `{"action":"block"}`, "platform_admin"),
		"policy-system-regex",
	)
	h.update(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(validator.patterns) != 1 || validator.patterns[0] != "stored-system-pattern" {
		t.Fatalf("action-only patch did not revalidate stored matcher: %#v", validator.patterns)
	}
	if !store.updated.RuntimeValidated || store.updated.Matcher != nil || store.updated.Action == nil || *store.updated.Action != "block" {
		t.Fatalf("action-only re-attestation update=%#v", store.updated)
	}
}

func TestSecurityPoliciesRejectsClientMatcherForSystemPolicyWithoutAttestingStoredMatcher(t *testing.T) {
	store := &fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{{
		ID: "policy-system-regex", Source: "system", RuleType: "regex", Enabled: false,
		InternalMatchConfigJSON: json.RawMessage(`{"regex":"stored-system-pattern"}`),
	}}}
	validator := &fakeRegexValidator{valid: true}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, validator)
	rec := httptest.NewRecorder()
	req := withPolicyID(
		policyHandlerRequest(http.MethodPatch, "/admin/v1/security/policies/policy-system-regex", `{"matcher":{"type":"regex","config":{"regex":"attacker-controlled-pattern"}}}`, "platform_admin"),
		"policy-system-regex",
	)
	h.update(rec, req)

	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "system_policy_read_only") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(validator.patterns) != 0 || store.updatedID != "" || store.updated.RuntimeValidated {
		t.Fatalf("unrelated client matcher reached attestation path: patterns=%#v update=%#v", validator.patterns, store.updated)
	}
}

func TestSecurityPolicyCapabilitiesSeparatesBuiltinAndExtensionTotals(t *testing.T) {
	store := &fakeSecurityPolicyStore{capabilities: []repository.SecurityPolicyCapability{
		{Category: "phone_cn", Name: "phone_cn", Kind: "static", Enabled: true},
		{Category: "semantic_roleplay", Name: "语义角色扮演绕过", Kind: "dynamic", Component: "security-engine.semantic", Enabled: true},
	}, policies: []repository.SecurityPolicy{
		{ID: "enabled-policy", Enabled: true, Capabilities: []repository.SecurityPolicyCapability{{Category: "phone_cn"}, {Category: "phone_cn"}}},
		{ID: "disabled-policy", Enabled: false, Capabilities: []repository.SecurityPolicyCapability{{Category: "semantic_roleplay"}}},
	}}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, &fakeRegexValidator{valid: true})
	rec := httptest.NewRecorder()
	h.listCapabilities(rec, policyHandlerRequest(http.MethodGet, "/admin/v1/security/policies/capabilities", "", "auditor"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Total          int `json:"total"`
		BuiltinTotal   int `json:"builtin_total"`
		ExtensionTotal int `json:"extension_total"`
		Data           []struct {
			Category         string `json:"category"`
			SemanticJudge    bool   `json:"semantic_judge"`
			BoundPolicyCount int    `json:"bound_policy_count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	if response.Total != 2 || response.BuiltinTotal != 1 || response.ExtensionTotal != 1 {
		t.Fatalf("capability totals=%+v", response)
	}
	if len(response.Data) != 2 || response.Data[0].SemanticJudge || !response.Data[1].SemanticJudge {
		t.Fatalf("semantic judge flags=%+v", response.Data)
	}
	if response.Data[0].BoundPolicyCount != 1 || response.Data[1].BoundPolicyCount != 0 {
		t.Fatalf("tenant enabled-policy usage=%+v", response.Data)
	}
	if strings.Contains(rec.Body.String(), "security-engine.semantic") || strings.Contains(rec.Body.String(), "component") {
		t.Fatalf("capability response leaked internal component: %s", rec.Body.String())
	}
}

func TestSecurityPoliciesRepositoryErrorsMapToCustomerStatus(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{repository.ErrSecurityPolicyNotFound, http.StatusNotFound, "policy_not_found"},
		{repository.ErrSystemPolicyFieldReadOnly, http.StatusConflict, "system_policy_read_only"},
		{repository.ErrPolicyDetectionRequired, http.StatusUnprocessableEntity, "detection_basis_required"},
		{repository.ErrPolicyRuntimeValidation, http.StatusServiceUnavailable, "runtime_validation_required"},
		{repository.ErrInvalidSecurityPolicy, http.StatusUnprocessableEntity, "invalid_policy"},
		{repository.ErrPolicyActionUnsupported, http.StatusUnprocessableEntity, "action_not_supported"},
	}
	for _, tc := range tests {
		t.Run(tc.code, func(t *testing.T) {
			store := &fakeSecurityPolicyStore{
				policies: []repository.SecurityPolicy{{
					ID: "missing", RuleType: "keyword", Enabled: true, Source: "tenant",
				}},
				updateErr: tc.err,
			}
			h := newSecurityPoliciesHandler(&Dependencies{}, store, &fakeRegexValidator{valid: true})
			rec := httptest.NewRecorder()
			h.update(rec, withPolicyID(policyHandlerRequest(http.MethodPatch, "/policy/missing", `{"action":"block"}`, "platform_admin"), "missing"))
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.code) {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
}

func TestSystemPolicyReadOnlyErrorDescribesConfigurableBoundary(t *testing.T) {
	store := &fakeSecurityPolicyStore{updateErr: repository.ErrSystemPolicyFieldReadOnly}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, &fakeRegexValidator{valid: true})
	rec := httptest.NewRecorder()
	h.update(rec, withPolicyID(
		policyHandlerRequest(http.MethodPatch, "/security/policies/system-policy", `{"name":"tenant rename"}`, "platform_admin"),
		"system-policy",
	))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "system_policy_read_only") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	message := rec.Body.String()
	for _, expected := range []string{
		"built-in policy definition and detector bindings are read-only",
		"only action, enabled state and severity can be configured",
	} {
		if !strings.Contains(message, expected) {
			t.Fatalf("read-only boundary omitted %q: %s", expected, message)
		}
	}
	for _, forbidden := range []string{"policy_code", "rule_type", "builtin_rule_overrides"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("read-only error leaked internal field %q: %s", forbidden, message)
		}
	}
}

func TestSecurityPoliciesAuthoringEditorContract(t *testing.T) {
	store := &fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{{ID: "policy-1", Source: "tenant", RuleType: "regex", Enabled: false}}}
	h := newSecurityPoliciesHandler(&Dependencies{SecurityEngineInternalToken: "test-quick-authoring-secret"}, store, &fakeRegexValidator{valid: true})
	create := httptest.NewRecorder()
	first := []quickNumberSegment{{Kind: "fixed", Value: "HT-", Length: 3}, {Kind: "fixed", Value: "2026", Length: 4}, {Kind: "fixed", Value: "-", Length: 1}, {Kind: "digits", Length: 6}}
	firstProof := signQuickAuthoring("test-quick-authoring-secret", quickAuthoringProof{TenantID: "tenant-a", Pattern: `(?<![A-Za-z0-9_])HT-2026-[0-9]{6}(?![A-Za-z0-9_])`, Segments: first, Expires: time.Now().Add(time.Minute).Unix()})
	h.create(create, policyHandlerRequest(http.MethodPost, "/admin/v1/security/policies", `{"name":"number","scene":"data_security","severity":"medium","action":"audit","enabled":false,"matcher":{"type":"regex","config":{"regex":"(?<![A-Za-z0-9_])HT-2026-[0-9]{6}(?![A-Za-z0-9_])"}},"authoring":{"version":1,"kind":"number","matcher_pattern":"(?<![A-Za-z0-9_])HT-2026-[0-9]{6}(?![A-Za-z0-9_])","segments":[{"kind":"fixed","value":"HT-","length":3},{"kind":"fixed","value":"2026","length":4},{"kind":"fixed","value":"-","length":1},{"kind":"digits","length":6}]},"authoring_proof":"`+firstProof+`"}`, "platform_admin"))
	if create.Code != http.StatusCreated || store.created.Authoring == nil || len(store.created.Authoring.Segments) != 4 {
		t.Fatalf("create authoring: %d %+v", create.Code, store.created.Authoring)
	}
	unauthorized := httptest.NewRecorder()
	h.create(unauthorized, policyHandlerRequest(http.MethodPost, "/admin/v1/security/policies", `{"name":"forged","scene":"data_security","severity":"medium","action":"audit","enabled":false,"matcher":{"type":"regex","config":{"regex":"(?<![A-Za-z0-9_])HT-2026-[0-9]{6}(?![A-Za-z0-9_])"}},"authoring":{"version":1,"kind":"number","matcher_pattern":"(?<![A-Za-z0-9_])HT-2026-[0-9]{6}(?![A-Za-z0-9_])","segments":[{"kind":"fixed","value":"HT-"},{"kind":"fixed","value":"2026"},{"kind":"fixed","value":"-"},{"kind":"digits","length":6}]}}`, "platform_admin"))
	if unauthorized.Code != 422 || store.created.Name != "number" {
		t.Fatalf("forged authoring accepted: %d %s", unauthorized.Code, unauthorized.Body.String())
	}
	if verifyQuickAuthoring("test-quick-authoring-secret", firstProof, "other-tenant", "", `(?<![A-Za-z0-9_])HT-2026-[0-9]{6}(?![A-Za-z0-9_])`, first) {
		t.Fatal("cross-tenant proof accepted")
	}
	expired := signQuickAuthoring("test-quick-authoring-secret", quickAuthoringProof{TenantID: "tenant-a", Pattern: `(?<![A-Za-z0-9_])HT-2026-[0-9]{6}(?![A-Za-z0-9_])`, Segments: first, Expires: time.Now().Add(-time.Second).Unix()})
	if verifyQuickAuthoring("test-quick-authoring-secret", expired, "tenant-a", "", `(?<![A-Za-z0-9_])HT-2026-[0-9]{6}(?![A-Za-z0-9_])`, first) {
		t.Fatal("expired proof accepted")
	}
	update := httptest.NewRecorder()
	second := []quickNumberSegment{{Kind: "fixed", Value: "HT-", Length: 3}, {Kind: "digits", Length: 4}, {Kind: "fixed", Value: "-", Length: 1}, {Kind: "digits", Length: 6}}
	secondProof := signQuickAuthoring("test-quick-authoring-secret", quickAuthoringProof{TenantID: "tenant-a", PolicyID: "policy-1", Pattern: `(?<![A-Za-z0-9_])HT-[0-9]{4}-[0-9]{6}(?![A-Za-z0-9_])`, Segments: second, Expires: time.Now().Add(time.Minute).Unix()})
	h.update(update, withPolicyID(policyHandlerRequest(http.MethodPatch, "/admin/v1/security/policies/policy-1", `{"matcher":{"type":"regex","config":{"regex":"(?<![A-Za-z0-9_])HT-[0-9]{4}-[0-9]{6}(?![A-Za-z0-9_])"}},"authoring":{"version":1,"kind":"number","matcher_pattern":"(?<![A-Za-z0-9_])HT-[0-9]{4}-[0-9]{6}(?![A-Za-z0-9_])","segments":[{"kind":"fixed","value":"HT-","length":3},{"kind":"digits","length":4},{"kind":"fixed","value":"-","length":1},{"kind":"digits","length":6}]},"authoring_proof":"`+secondProof+`"}`, "platform_admin"), "policy-1"))
	if update.Code != http.StatusOK || store.updated.Authoring == nil || len(store.updated.Authoring.Segments) != 4 {
		t.Fatalf("patch authoring: %d %+v", update.Code, store.updated.Authoring)
	}
}

func TestSecurityPoliciesActionOnlyRevalidationKeepsAuthoring(t *testing.T) {
	segments := []repository.SecurityPolicyNumberSegment{{Kind: "fixed", Value: "HT-", Length: 3}, {Kind: "digits", Length: 6}}
	pattern := `(?<![A-Za-z0-9_])HT-[0-9]{6}(?![A-Za-z0-9_])`
	authoring := &repository.SecurityPolicyAuthoring{Version: 1, Kind: "number", MatcherPattern: pattern, Segments: segments}
	store := &fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{{ID: "policy-1", Source: "tenant", RuleType: "regex", Enabled: true, Authoring: authoring, MatchConfigJSON: json.RawMessage(`{"regex":"(?<![A-Za-z0-9_])HT-[0-9]{6}(?![A-Za-z0-9_])"}`)}}}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, &fakeRegexValidator{valid: true})
	response := httptest.NewRecorder()
	h.update(response, withPolicyID(policyHandlerRequest(http.MethodPatch, "/admin/v1/security/policies/policy-1", `{"action":"block"}`, "platform_admin"), "policy-1"))
	if response.Code != http.StatusOK || store.updated.Matcher == nil || store.updated.Authoring == nil || len(store.updated.Authoring.Segments) != len(segments) {
		t.Fatalf("action patch lost authoring: %d %+v", response.Code, store.updated)
	}
}

func TestSecurityPolicyDeleteRemovesOrganizationPolicy(t *testing.T) {
	store := &fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{{ID: "custom-1", PolicyCode: "custom.abc", Name: "厂房", Source: "tenant", Origin: "organization_created", RuleType: "keyword", Enabled: true}}}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, &fakeRegexValidator{valid: true})
	rec := httptest.NewRecorder()
	h.deleteOne(rec, withPolicyID(policyHandlerRequest(http.MethodDelete, "/admin/v1/security/policies/custom-1", "", "platform_admin"), "custom-1"))
	if rec.Code != http.StatusNoContent || store.deletedID != "custom-1" {
		t.Fatalf("delete status=%d deleted=%q body=%s", rec.Code, store.deletedID, rec.Body.String())
	}
}

func TestSecurityPolicyDeleteBuiltinIsRefusedWithAClearCode(t *testing.T) {
	store := &fakeSecurityPolicyStore{
		policies:  []repository.SecurityPolicy{{ID: "builtin-1", PolicyCode: "builtin.data_leak.x", Name: "手机号检测", Source: "tenant", Origin: "preloaded", RuleType: "data_leak", Enabled: true}},
		deleteErr: repository.ErrSecurityPolicyNotDeletable,
	}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, &fakeRegexValidator{valid: true})
	rec := httptest.NewRecorder()
	h.deleteOne(rec, withPolicyID(policyHandlerRequest(http.MethodDelete, "/admin/v1/security/policies/builtin-1", "", "platform_admin"), "builtin-1"))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "policy_not_deletable") || store.deletedID != "" {
		t.Fatalf("builtin delete status=%d deleted=%q body=%s", rec.Code, store.deletedID, rec.Body.String())
	}
}

func TestSecurityPolicyDeleteUnknownPolicyIs404AndReadOnlyRolesAreForbidden(t *testing.T) {
	store := &fakeSecurityPolicyStore{}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, &fakeRegexValidator{valid: true})
	rec := httptest.NewRecorder()
	h.deleteOne(rec, withPolicyID(policyHandlerRequest(http.MethodDelete, "/admin/v1/security/policies/nope", "", "platform_admin"), "nope"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown policy status=%d body=%s", rec.Code, rec.Body.String())
	}
	store.policies = []repository.SecurityPolicy{{ID: "custom-1", PolicyCode: "custom.abc", Source: "tenant"}}
	rec = httptest.NewRecorder()
	h.deleteOne(rec, withPolicyID(policyHandlerRequest(http.MethodDelete, "/admin/v1/security/policies/custom-1", "", "auditor"), "custom-1"))
	if rec.Code != http.StatusForbidden || store.deletedID != "" {
		t.Fatalf("auditor delete status=%d deleted=%q body=%s", rec.Code, store.deletedID, rec.Body.String())
	}
}

type auditCaptureSystemRepo struct {
	budgetTestSystemRepo
	ops []*repository.AuditOperation
}

func (r *auditCaptureSystemRepo) CreateAuditOperation(_ context.Context, op *repository.AuditOperation) error {
	r.ops = append(r.ops, op)
	return nil
}

func TestSystemPolicySeverityOnlyPatchAuditsBeforeAndAfter(t *testing.T) {
	store := &fakeSecurityPolicyStore{
		policies: []repository.SecurityPolicy{{ID: "system-policy", PolicyCode: "builtin.secret", Source: "system", Severity: "high"}},
		updateResult: &repository.SecurityPolicy{
			ID: "system-policy", Source: "system", Scene: "data_security", Action: "audit", Enabled: true,
			Severity: "critical", DefaultSeverity: "high", SeverityOverridden: true, PreviousSeverity: "high",
		},
	}
	audit := &auditCaptureSystemRepo{}
	h := newSecurityPoliciesHandler(&Dependencies{SystemRepo: audit}, store, &fakeRegexValidator{valid: true})
	rec := httptest.NewRecorder()
	h.update(rec, withPolicyID(
		policyHandlerRequest(http.MethodPatch, "/security/policies/system-policy", `{"severity":"critical"}`, "platform_admin"),
		"system-policy",
	))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["default_severity"] != "high" || body["severity_overridden"] != true || body["severity"] != "critical" {
		t.Fatalf("response must expose default_severity and severity_overridden: %s", rec.Body.String())
	}
	if len(audit.ops) != 1 || audit.ops[0].ActionType != "security_policy.update" {
		t.Fatalf("audit ops=%+v", audit.ops)
	}
	detail := audit.ops[0].ActionDetail
	change, ok := detail["severity"].(map[string]string)
	if !ok || change["from"] != "high" || change["to"] != "critical" {
		t.Fatalf("audit detail must carry severity from/to, got %#v", detail)
	}
}

func TestPolicyUpdateWithoutSeverityChangeOmitsSeverityAuditDetail(t *testing.T) {
	store := &fakeSecurityPolicyStore{updateResult: &repository.SecurityPolicy{ID: "p", Source: "tenant", Severity: "high", PreviousSeverity: "high"}}
	audit := &auditCaptureSystemRepo{}
	h := newSecurityPoliciesHandler(&Dependencies{SystemRepo: audit}, store, &fakeRegexValidator{valid: true})
	rec := httptest.NewRecorder()
	h.update(rec, withPolicyID(policyHandlerRequest(http.MethodPatch, "/security/policies/p", `{"severity":"high"}`, "platform_admin"), "p"))
	if rec.Code != http.StatusOK || len(audit.ops) != 1 {
		t.Fatalf("status=%d ops=%d", rec.Code, len(audit.ops))
	}
	if _, present := audit.ops[0].ActionDetail["severity"]; present {
		t.Fatalf("unchanged severity must not be audited as a change: %#v", audit.ops[0].ActionDetail)
	}
}

func TestSecurityCapabilityResponseCarriesMatchDocs(t *testing.T) {
	got := securityCapabilityWithDocs(repository.SecurityPolicyCapability{Category: "ssh_private_key", Name: "私钥"})
	if got.Matches == "" || len(got.HitExamples) == 0 || len(got.MissExamples) == 0 {
		t.Fatalf("能力接口应带匹配说明：%+v", got)
	}
	none := securityCapabilityWithDocs(repository.SecurityPolicyCapability{Category: "no_such_capability"})
	if none.Matches != "" || none.HitExamples != nil {
		t.Fatalf("没有说明的能力不应带字段：%+v", none)
	}
	body, err := json.Marshal(none)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"matches", "hit_examples", "miss_examples", "judged_by_ai", "check"} {
		if strings.Contains(string(body), `"`+key+`"`) {
			t.Fatalf("没有说明的能力序列化后不应出现 %s：%s", key, body)
		}
	}
	withDoc, _ := json.Marshal(got)
	if strings.Contains(string(withDoc), `"check"`) {
		t.Fatalf("接口响应不应返回 check：%s", withDoc)
	}
}

func TestPolicyCapabilitiesDoNotRepeatMatchDocs(t *testing.T) {
	response := policyResponse(repository.SecurityPolicy{
		ID: "p1", Capabilities: []repository.SecurityPolicyCapability{{Category: "ssh_private_key", Name: "私钥"}},
	}, false)
	if len(response.Capabilities) != 1 || response.Capabilities[0].Category != "ssh_private_key" {
		t.Fatalf("策略应仍带能力键：%+v", response.Capabilities)
	}
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"matches", "hit_examples", "miss_examples", "judged_by_ai"} {
		if strings.Contains(string(body), `"`+key+`"`) {
			t.Fatalf("策略里的能力不应重复带 %s：%s", key, body)
		}
	}
}

func TestCapabilityListCarriesMatchDocs(t *testing.T) {
	store := &fakeSecurityPolicyStore{capabilities: []repository.SecurityPolicyCapability{
		{Category: "ssh_private_key", Name: "私钥", Kind: "static", Enabled: true},
		{Category: "no_such_capability", Name: "无说明", Kind: "static", Enabled: true},
	}}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, &fakeRegexValidator{valid: true})
	rec := httptest.NewRecorder()
	h.listCapabilities(rec, policyHandlerRequest(http.MethodGet, "/admin/v1/security/policies/capabilities", "", "auditor"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || len(response.Data) != 2 {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	for _, key := range []string{"matches", "hit_examples", "miss_examples"} {
		if _, ok := response.Data[0][key]; !ok {
			t.Fatalf("能力列表应带 %s：%v", key, response.Data[0])
		}
		if _, ok := response.Data[1][key]; ok {
			t.Fatalf("没有说明的能力不应带 %s：%v", key, response.Data[1])
		}
	}
}
