package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type quotaAuditSystemRepo struct {
	auditOps []*repository.AuditOperation
}

func (r *quotaAuditSystemRepo) Get(ctx context.Context, key string) (*repository.SystemSetting, error) {
	return nil, nil
}
func (r *quotaAuditSystemRepo) GetAll(ctx context.Context) ([]*repository.SystemSetting, error) {
	return nil, nil
}
func (r *quotaAuditSystemRepo) Set(ctx context.Context, key, value string) error {
	return nil
}
func (r *quotaAuditSystemRepo) SetMultiple(ctx context.Context, settings map[string]string) error {
	return nil
}
func (r *quotaAuditSystemRepo) CreateAuditOperation(ctx context.Context, op *repository.AuditOperation) error {
	r.auditOps = append(r.auditOps, op)
	return nil
}
func (r *quotaAuditSystemRepo) ListAuditOperations(ctx context.Context, limit, offset int, userID string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, nil
}
func (r *quotaAuditSystemRepo) GetBool(ctx context.Context, key string) (bool, error) {
	return false, nil
}

type fakeProjectRepo struct {
	project *repository.Project
}

func (r *fakeProjectRepo) GetByID(ctx context.Context, tenantID, id string) (*repository.Project, error) {
	return r.project, nil
}
func (r *fakeProjectRepo) List(ctx context.Context, tenantID string) ([]*repository.Project, error) {
	return nil, nil
}
func (r *fakeProjectRepo) CountByTenant(ctx context.Context, tenantID string) (int, error) {
	if r.project == nil || r.project.TenantID != tenantID {
		return 0, nil
	}
	return 1, nil
}
func (r *fakeProjectRepo) Create(ctx context.Context, project *repository.Project) error {
	return nil
}
func (r *fakeProjectRepo) Update(ctx context.Context, project *repository.Project) error {
	return nil
}
func (r *fakeProjectRepo) UpdateModelConfig(ctx context.Context, id string, whitelist, quotaLimits string) error {
	return nil
}
func (r *fakeProjectRepo) Delete(ctx context.Context, tenantID, id string) error {
	return nil
}

type fakeQuotaPolicyRepo struct {
	saved *repository.QuotaPolicy
	// GetByScope 调用捕获 + 可配置返回值
	scopeCalledType    string
	scopeCalledProject string
	scopeCalledTeam    string
	scopeCalledUser    string
	scopeCalledKey     string
	getByScopeResult   *repository.QuotaPolicy
}

type fakeQuotaKeyLookup struct {
	keys     map[string]*repository.InternalKey
	prefixes map[string][]*repository.InternalKey
	err      error
}

func (r *fakeQuotaKeyLookup) GetByID(_ context.Context, tenantID, keyID string) (*repository.InternalKey, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.keys[tenantID+"|"+keyID], nil
}

func (r *fakeQuotaKeyLookup) GetUniqueByPrefix(_ context.Context, tenantID, keyPrefix string) (*repository.InternalKey, error) {
	if r.err != nil {
		return nil, r.err
	}
	matches := r.prefixes[tenantID+"|"+keyPrefix]
	if len(matches) != 1 {
		return nil, nil
	}
	return matches[0], nil
}

func (r *fakeQuotaPolicyRepo) GetByProject(ctx context.Context, tenantID, projectID string) (*repository.QuotaPolicy, error) {
	return nil, nil
}
func (r *fakeQuotaPolicyRepo) GetByScope(ctx context.Context, tenantID, scopeType, projectID, teamID, userID, keyPrefix string) (*repository.QuotaPolicy, error) {
	r.scopeCalledType = scopeType
	r.scopeCalledProject = projectID
	r.scopeCalledTeam = teamID
	r.scopeCalledUser = userID
	r.scopeCalledKey = keyPrefix
	return r.getByScopeResult, nil
}
func (r *fakeQuotaPolicyRepo) List(ctx context.Context, tenantID string) ([]*repository.QuotaPolicy, error) {
	return nil, nil
}
func (r *fakeQuotaPolicyRepo) CreateOrUpdate(ctx context.Context, policy *repository.QuotaPolicy) error {
	policy.ID = "qpol_test"
	r.saved = policy
	return nil
}

// adminCtx 注入 platform_admin 用户上下文
func adminCtx(req *http.Request) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_default",
		Role:     "platform_admin",
		Status:   "active",
	}))
}

func TestSetQuotaPolicyWritesAuditOperation(t *testing.T) {
	systemRepo := &quotaAuditSystemRepo{}
	deps := &Dependencies{
		SystemRepo:      systemRepo,
		ProjectRepo:     &fakeProjectRepo{project: &repository.Project{ID: "proj_001", TenantID: "tenant_default", Name: "测试应用"}},
		QuotaPolicyRepo: &fakeQuotaPolicyRepo{},
	}
	body, _ := json.Marshal(map[string]interface{}{
		"project_id":           "proj_001",
		"daily_token_limit":    1000,
		"monthly_token_limit":  30000,
		"monthly_budget_limit": 100,
		"rpm_limit":            60,
		"concurrency_limit":    5,
		"overage_action":       "rate_limit",
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", bytes.NewReader(body))
	req = adminCtx(req)
	w := httptest.NewRecorder()

	SetQuotaPolicy(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if len(systemRepo.auditOps) != 1 {
		t.Fatalf("audit ops = %d, want 1", len(systemRepo.auditOps))
	}
	if systemRepo.auditOps[0].ActionType != "quota_policy.update" {
		t.Fatalf("action type = %s, want quota_policy.update", systemRepo.auditOps[0].ActionType)
	}
	quotaRepo := deps.QuotaPolicyRepo.(*fakeQuotaPolicyRepo)
	if quotaRepo.saved == nil {
		t.Fatal("quota policy was not saved")
	}
	if quotaRepo.saved.OverageAction != "rate_limit" {
		t.Fatalf("saved overage action = %q, want rate_limit", quotaRepo.saved.OverageAction)
	}
	if systemRepo.auditOps[0].TargetType != "quota_policy" || systemRepo.auditOps[0].TargetID != "qpol_test" {
		t.Fatalf("unexpected audit target: %+v", systemRepo.auditOps[0])
	}
	auditData := systemRepo.auditOps[0].ActionDetail
	if auditData["overage_action"] != "rate_limit" {
		t.Fatalf("audit overage action = %v, want rate_limit", auditData["overage_action"])
	}
}

func TestSetQuotaPolicyRejectsUnimplementedOverageActions(t *testing.T) {
	for _, action := range []string{"pause_key", "downgrade_model"} {
		t.Run(action, func(t *testing.T) {
			quotaRepo := &fakeQuotaPolicyRepo{}
			deps := &Dependencies{
				ProjectRepo: &fakeProjectRepo{project: &repository.Project{
					ID: "proj_001", TenantID: "tenant_default", Name: "测试应用",
				}},
				QuotaPolicyRepo: quotaRepo,
			}
			body, _ := json.Marshal(map[string]interface{}{
				"project_id": "proj_001", "overage_action": action,
				"enforcement_mode": "enforce", "daily_token_limit": 100,
			})
			req := adminCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", bytes.NewReader(body)))
			w := httptest.NewRecorder()
			SetQuotaPolicy(deps).ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest || quotaRepo.saved != nil {
				t.Fatalf("unsupported action accepted: status=%d body=%s saved=%+v", w.Code, w.Body.String(), quotaRepo.saved)
			}
		})
	}
}

func TestSetQuotaPolicyPersistsAndEchoesDailyBudgetAndEnforcementMode(t *testing.T) {
	systemRepo := &quotaAuditSystemRepo{}
	quotaRepo := &fakeQuotaPolicyRepo{}
	deps := &Dependencies{
		SystemRepo:      systemRepo,
		ProjectRepo:     &fakeProjectRepo{project: &repository.Project{ID: "proj_001", TenantID: "tenant_default", Name: "测试应用"}},
		QuotaPolicyRepo: quotaRepo,
	}
	body, _ := json.Marshal(map[string]interface{}{
		"project_id":          "proj_001",
		"daily_budget_limit":  12.5,
		"enforcement_mode":    "enforce",
		"overage_action":      "rate_limit",
		"daily_token_limit":   1000,
		"monthly_token_limit": 30000,
	})
	req := adminCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	SetQuotaPolicy(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if quotaRepo.saved == nil {
		t.Fatal("quota policy was not saved")
	}
	if quotaRepo.saved.DailyBudgetLimit != 12.5 {
		t.Fatalf("saved daily budget = %v, want 12.5", quotaRepo.saved.DailyBudgetLimit)
	}
	if quotaRepo.saved.EnforcementMode != "enforce" {
		t.Fatalf("saved enforcement mode = %q, want enforce", quotaRepo.saved.EnforcementMode)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["daily_budget_limit"] != 12.5 || resp["enforcement_mode"] != "enforce" {
		t.Fatalf("response lost quota fields: %#v", resp)
	}
	if len(systemRepo.auditOps) != 1 || systemRepo.auditOps[0].ActionDetail["daily_budget_limit"] != 12.5 || systemRepo.auditOps[0].ActionDetail["enforcement_mode"] != "enforce" {
		t.Fatalf("audit lost quota fields: %#v", systemRepo.auditOps)
	}
}

func TestSetQuotaPolicyPersistsEchoesAndAuditsTPM(t *testing.T) {
	systemRepo := &quotaAuditSystemRepo{}
	quotaRepo := &fakeQuotaPolicyRepo{}
	deps := &Dependencies{
		SystemRepo:      systemRepo,
		ProjectRepo:     &fakeProjectRepo{project: &repository.Project{ID: "proj_001", TenantID: "tenant_default"}},
		QuotaPolicyRepo: quotaRepo,
	}
	body, _ := json.Marshal(map[string]interface{}{
		"project_id":       "proj_001",
		"tpm_limit":        12000,
		"overage_action":   "rate_limit",
		"enforcement_mode": "enforce",
	})
	w := httptest.NewRecorder()
	SetQuotaPolicy(deps).ServeHTTP(w, adminCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", bytes.NewReader(body))))

	if w.Code != http.StatusOK || quotaRepo.saved == nil || quotaRepo.saved.TPMLimit == nil || *quotaRepo.saved.TPMLimit != 12000 {
		t.Fatalf("TPM save status=%d policy=%+v body=%s", w.Code, quotaRepo.saved, w.Body.String())
	}
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["tpm_limit"] != float64(12000) || len(systemRepo.auditOps) != 1 || systemRepo.auditOps[0].ActionDetail["tpm_limit"] != int64(12000) {
		t.Fatalf("TPM response/audit missing: response=%#v audit=%#v", response, systemRepo.auditOps)
	}
}

func TestSetQuotaPolicyRejectsNegativeTPM(t *testing.T) {
	quotaRepo := &fakeQuotaPolicyRepo{}
	deps := &Dependencies{
		SystemRepo:      &quotaAuditSystemRepo{},
		ProjectRepo:     &fakeProjectRepo{project: &repository.Project{ID: "proj_001", TenantID: "tenant_default"}},
		QuotaPolicyRepo: quotaRepo,
	}
	body := bytes.NewBufferString(`{"project_id":"proj_001","tpm_limit":-1}`)
	w := httptest.NewRecorder()
	SetQuotaPolicy(deps).ServeHTTP(w, adminCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", body)))
	if w.Code != http.StatusBadRequest || quotaRepo.saved != nil {
		t.Fatalf("negative TPM status=%d saved=%+v body=%s", w.Code, quotaRepo.saved, w.Body.String())
	}
}

func TestSetQuotaPolicyRejectsInvalidNumericLimits(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
	}{
		{name: "negative daily tokens", field: "daily_token_limit", value: "-1"},
		{name: "negative monthly tokens", field: "monthly_token_limit", value: "-1"},
		{name: "negative rpm", field: "rpm_limit", value: "-1"},
		{name: "overflow tpm", field: "tpm_limit", value: "9007199254740992"},
		{name: "negative concurrency", field: "concurrency_limit", value: "-1"},
		{name: "negative daily budget", field: "daily_budget_limit", value: "-0.01"},
		{name: "negative monthly budget", field: "monthly_budget_limit", value: "-0.01"},
		{name: "overflow daily budget", field: "daily_budget_limit", value: "1e309"},
		{name: "overflow monthly budget", field: "monthly_budget_limit", value: "1e309"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			quotaRepo := &fakeQuotaPolicyRepo{}
			deps := &Dependencies{SystemRepo: &quotaAuditSystemRepo{}, QuotaPolicyRepo: quotaRepo}
			body := `{"scope_type":"tenant","` + tc.field + `":` + tc.value + `}`
			w := httptest.NewRecorder()
			SetQuotaPolicy(deps).ServeHTTP(w, adminCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", strings.NewReader(body))))
			if w.Code != http.StatusBadRequest || quotaRepo.saved != nil {
				t.Fatalf("status=%d saved=%+v body=%s", w.Code, quotaRepo.saved, w.Body.String())
			}
		})
	}
}

func TestSetQuotaPolicyAcceptsZeroLimits(t *testing.T) {
	quotaRepo := &fakeQuotaPolicyRepo{}
	deps := &Dependencies{SystemRepo: &quotaAuditSystemRepo{}, QuotaPolicyRepo: quotaRepo}
	body := `{"scope_type":"tenant","daily_token_limit":0,"monthly_token_limit":0,"daily_budget_limit":0,"monthly_budget_limit":0,"rpm_limit":0,"tpm_limit":0,"concurrency_limit":0}`
	w := httptest.NewRecorder()
	SetQuotaPolicy(deps).ServeHTTP(w, adminCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", strings.NewReader(body))))
	if w.Code != http.StatusOK || quotaRepo.saved == nil || quotaRepo.saved.TPMLimit == nil || *quotaRepo.saved.TPMLimit != 0 {
		t.Fatalf("zero limits status=%d saved=%+v body=%s", w.Code, quotaRepo.saved, w.Body.String())
	}
}

func TestSetQuotaPolicyRejectsUnknownFieldsOversizedAndMultipleObjects(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "unknown field", body: `{"scope_type":"tenant","unlimited":true}`},
		{name: "oversized", body: `{"scope_type":"tenant","padding":"` + strings.Repeat("x", int(maxQuotaPolicyConfigRequestBytes)) + `"}`},
		{name: "multiple objects", body: `{"scope_type":"tenant"} {"scope_type":"tenant"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			quotaRepo := &fakeQuotaPolicyRepo{}
			deps := &Dependencies{SystemRepo: &quotaAuditSystemRepo{}, QuotaPolicyRepo: quotaRepo}
			w := httptest.NewRecorder()
			SetQuotaPolicy(deps).ServeHTTP(w, adminCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", strings.NewReader(tc.body))))
			if w.Code != http.StatusBadRequest || quotaRepo.saved != nil {
				t.Fatalf("status=%d saved=%+v body=%s", w.Code, quotaRepo.saved, w.Body.String())
			}
		})
	}
}

func TestSetQuotaPolicyRejectsConflictingTPMBlockAndLimit(t *testing.T) {
	quotaRepo := &fakeQuotaPolicyRepo{}
	deps := &Dependencies{
		SystemRepo: &quotaAuditSystemRepo{}, ProjectRepo: &fakeProjectRepo{project: &repository.Project{ID: "proj_001", TenantID: "tenant_default"}},
		QuotaPolicyRepo: quotaRepo,
	}
	body := bytes.NewBufferString(`{"project_id":"proj_001","tpm_limit":0,"tpm_blocked":true}`)
	w := httptest.NewRecorder()
	SetQuotaPolicy(deps).ServeHTTP(w, adminCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", body)))
	if w.Code != http.StatusBadRequest || quotaRepo.saved != nil {
		t.Fatalf("conflicting TPM status=%d saved=%+v body=%s", w.Code, quotaRepo.saved, w.Body.String())
	}
}

func TestSetQuotaPolicyKeepsTPMPresenceAndBlockStatesDistinct(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantNil     bool
		wantLimit   int64
		wantBlocked bool
	}{
		{name: "inherited", body: `{"project_id":"proj_001"}`, wantNil: true},
		{name: "explicit unlimited", body: `{"project_id":"proj_001","tpm_limit":0}`, wantLimit: 0},
		{name: "explicit blocked", body: `{"project_id":"proj_001","tpm_blocked":true}`, wantNil: true, wantBlocked: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			quotaRepo := &fakeQuotaPolicyRepo{}
			deps := &Dependencies{
				SystemRepo: &quotaAuditSystemRepo{}, ProjectRepo: &fakeProjectRepo{project: &repository.Project{ID: "proj_001", TenantID: "tenant_default"}},
				QuotaPolicyRepo: quotaRepo,
			}
			w := httptest.NewRecorder()
			SetQuotaPolicy(deps).ServeHTTP(w, adminCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", bytes.NewBufferString(tc.body))))
			if w.Code != http.StatusOK || quotaRepo.saved == nil {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if (quotaRepo.saved.TPMLimit == nil) != tc.wantNil || quotaRepo.saved.TPMBlocked != tc.wantBlocked {
				t.Fatalf("saved TPM state=%+v", quotaRepo.saved)
			}
			if !tc.wantNil && *quotaRepo.saved.TPMLimit != tc.wantLimit {
				t.Fatalf("saved TPM limit=%v, want %d", quotaRepo.saved.TPMLimit, tc.wantLimit)
			}
		})
	}
}

func TestGetQuotaPolicyEchoesDailyBudgetAndEnforcementMode(t *testing.T) {
	quotaRepo := &fakeQuotaPolicyRepo{getByScopeResult: &repository.QuotaPolicy{
		ID: "qpol_test", TenantID: "tenant_default", ScopeType: "team", ScopeRef: "team_001",
		DailyBudgetLimit: 7.25, EnforcementMode: "enforce", OverageAction: "rate_limit", Status: "active",
	}}
	deps := &Dependencies{
		SystemRepo:      &quotaAuditSystemRepo{},
		QuotaPolicyRepo: quotaRepo,
		DepartmentStore: &quotaTeamLookupStub{team: &repository.Team{ID: "team_001", TenantID: "tenant_default"}},
	}
	req := adminCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/policies/quota?scope_type=team&scope_id=team_001", nil))
	w := httptest.NewRecorder()

	GetQuotaPolicy(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["daily_budget_limit"] != 7.25 || resp["enforcement_mode"] != "enforce" {
		t.Fatalf("response lost quota fields: %#v", resp)
	}
}

func TestSetQuotaPolicyRejectsInvalidEnforcementMode(t *testing.T) {
	quotaRepo := &fakeQuotaPolicyRepo{}
	deps := &Dependencies{
		SystemRepo:      &quotaAuditSystemRepo{},
		ProjectRepo:     &fakeProjectRepo{project: &repository.Project{ID: "proj_001", TenantID: "tenant_default"}},
		QuotaPolicyRepo: quotaRepo,
	}
	body, _ := json.Marshal(map[string]interface{}{
		"project_id":       "proj_001",
		"enforcement_mode": "silently_disable",
	})
	req := adminCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	SetQuotaPolicy(deps).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}
	if quotaRepo.saved != nil {
		t.Fatal("invalid enforcement mode must not be persisted")
	}
}

// TestSetQuotaPolicyTeamScope: team 维度配额写入应映射到 ScopeRef，且不依赖 ProjectRepo。
func TestSetQuotaPolicyTeamScope(t *testing.T) {
	systemRepo := &quotaAuditSystemRepo{}
	deps := &Dependencies{
		SystemRepo:      systemRepo,
		QuotaPolicyRepo: &fakeQuotaPolicyRepo{},
		DepartmentStore: &quotaTeamLookupStub{team: &repository.Team{ID: "team_001", TenantID: "tenant_default"}},
	}
	body, _ := json.Marshal(map[string]interface{}{
		"scope_type":          "team",
		"scope_id":            "team_001",
		"daily_token_limit":   2000,
		"monthly_token_limit": 60000,
		"rpm_limit":           120,
		"concurrency_limit":   10,
		"overage_action":      "rate_limit",
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", bytes.NewReader(body))
	req = adminCtx(req)
	w := httptest.NewRecorder()

	SetQuotaPolicy(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	saved := deps.QuotaPolicyRepo.(*fakeQuotaPolicyRepo).saved
	if saved == nil {
		t.Fatal("quota policy was not saved")
	}
	if saved.ScopeType != "team" {
		t.Fatalf("saved scope type = %q, want team", saved.ScopeType)
	}
	if saved.ScopeRef != "team_001" {
		t.Fatalf("saved scope ref = %q, want team_001", saved.ScopeRef)
	}
	if saved.ProjectID != "" {
		t.Fatalf("saved project id = %q, want empty for team scope", saved.ProjectID)
	}
}

// TestSetQuotaPolicyUserScope: user 维度配额写入应映射到 UserID。
func TestSetQuotaPolicyUserScope(t *testing.T) {
	systemRepo := &quotaAuditSystemRepo{}
	deps := &Dependencies{
		SystemRepo:      systemRepo,
		QuotaPolicyRepo: &fakeQuotaPolicyRepo{},
		QuotaUserLookup: &quotaUserLookupStub{user: &repository.User{ID: "user_042", TenantID: "tenant_default"}},
	}
	body, _ := json.Marshal(map[string]interface{}{
		"scope_type":          "user",
		"scope_id":            "user_042",
		"daily_token_limit":   500,
		"monthly_token_limit": 15000,
		"overage_action":      "notify",
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", bytes.NewReader(body))
	req = adminCtx(req)
	w := httptest.NewRecorder()

	SetQuotaPolicy(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	saved := deps.QuotaPolicyRepo.(*fakeQuotaPolicyRepo).saved
	if saved == nil {
		t.Fatal("quota policy was not saved")
	}
	if saved.ScopeType != "user" {
		t.Fatalf("saved scope type = %q, want user", saved.ScopeType)
	}
	if saved.UserID != "user_042" {
		t.Fatalf("saved user id = %q, want user_042", saved.UserID)
	}
}

// TestSetQuotaPolicyKeyScope: key 维度 scope_id 是稳定 internal_keys.id；prefix 仅兼容持久化。
func TestSetQuotaPolicyKeyScope(t *testing.T) {
	systemRepo := &quotaAuditSystemRepo{}
	deps := &Dependencies{
		SystemRepo:      systemRepo,
		QuotaPolicyRepo: &fakeQuotaPolicyRepo{},
		QuotaKeyLookup: &fakeQuotaKeyLookup{keys: map[string]*repository.InternalKey{
			"tenant_default|key_001": {ID: "key_001", TenantID: "tenant_default", KeyPrefix: "sk-abc"},
		}},
	}
	body, _ := json.Marshal(map[string]interface{}{
		"scope_type":          "key",
		"scope_id":            "key_001",
		"daily_token_limit":   100,
		"monthly_token_limit": 3000,
		"overage_action":      "rate_limit",
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", bytes.NewReader(body))
	req = adminCtx(req)
	w := httptest.NewRecorder()

	SetQuotaPolicy(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	saved := deps.QuotaPolicyRepo.(*fakeQuotaPolicyRepo).saved
	if saved == nil {
		t.Fatal("quota policy was not saved")
	}
	if saved.ScopeType != "key" {
		t.Fatalf("saved scope type = %q, want key", saved.ScopeType)
	}
	if saved.KeyID != "key_001" {
		t.Fatalf("saved key id = %q, want key_001", saved.KeyID)
	}
	if saved.KeyPrefix != "sk-abc" {
		t.Fatalf("saved key prefix = %q, want sk-abc", saved.KeyPrefix)
	}
}

func TestQuotaPolicyKeyScopeRejectsMissingAndCrossTenantWithoutDisclosure(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			quotaRepo := &fakeQuotaPolicyRepo{}
			deps := &Dependencies{
				SystemRepo:      &quotaAuditSystemRepo{},
				QuotaPolicyRepo: quotaRepo,
				QuotaKeyLookup: &fakeQuotaKeyLookup{keys: map[string]*repository.InternalKey{
					"tenant_other|key_secret": {ID: "key_secret", TenantID: "tenant_other", KeyPrefix: "sk-secret"},
				}},
			}
			var req *http.Request
			if method == http.MethodGet {
				req = httptest.NewRequest(method, "/admin/v1/policies/quota?scope_type=key&scope_id=key_secret", nil)
			} else {
				body, _ := json.Marshal(map[string]interface{}{
					"scope_type": "key", "scope_id": "key_secret", "overage_action": "notify",
				})
				req = httptest.NewRequest(method, "/admin/v1/policies/quota", bytes.NewReader(body))
			}
			w := httptest.NewRecorder()
			if method == http.MethodGet {
				GetQuotaPolicy(deps).ServeHTTP(w, adminCtx(req))
			} else {
				SetQuotaPolicy(deps).ServeHTTP(w, adminCtx(req))
			}
			if w.Code != http.StatusNotFound {
				t.Fatalf("status=%d body=%s, want uniform 404", w.Code, w.Body.String())
			}
			if quotaRepo.saved != nil || quotaRepo.scopeCalledType != "" {
				t.Fatalf("missing/cross-tenant key must not reach quota repository: %+v", quotaRepo)
			}
		})
	}
}

func TestGetQuotaPolicyKeyScopeUsesStableID(t *testing.T) {
	quotaRepo := &fakeQuotaPolicyRepo{getByScopeResult: &repository.QuotaPolicy{
		ID: "qpol_key", TenantID: "tenant_default", ScopeType: "key", KeyID: "key_001", KeyPrefix: "sk-abc",
	}}
	deps := &Dependencies{
		SystemRepo:      &quotaAuditSystemRepo{},
		QuotaPolicyRepo: quotaRepo,
		QuotaKeyLookup: &fakeQuotaKeyLookup{keys: map[string]*repository.InternalKey{
			"tenant_default|key_001": {ID: "key_001", TenantID: "tenant_default", KeyPrefix: "sk-abc"},
		}},
	}
	w := httptest.NewRecorder()
	req := adminCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/policies/quota?scope_type=key&scope_id=key_001", nil))
	GetQuotaPolicy(deps).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if quotaRepo.scopeCalledKey != "key_001" {
		t.Fatalf("repository key id=%q, want key_001", quotaRepo.scopeCalledKey)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["scope_id"] != "key_001" {
		t.Fatalf("scope_id=%v, want stable key id", resp["scope_id"])
	}
}

func TestQuotaPolicyKeyScopeResolvesUniqueLegacyPrefixToStableID(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			quotaRepo := &fakeQuotaPolicyRepo{}
			lookup := &fakeQuotaKeyLookup{prefixes: map[string][]*repository.InternalKey{
				"tenant_default|sk-legacy": {{ID: "key_legacy", TenantID: "tenant_default", KeyPrefix: "sk-legacy"}},
			}}
			deps := &Dependencies{SystemRepo: &quotaAuditSystemRepo{}, QuotaPolicyRepo: quotaRepo, QuotaKeyLookup: lookup}

			var req *http.Request
			if method == http.MethodGet {
				req = httptest.NewRequest(method, "/admin/v1/policies/quota?scope_type=key&scope_id=sk-legacy", nil)
			} else {
				body, _ := json.Marshal(map[string]any{
					"scope_type": "key", "scope_id": "sk-legacy", "overage_action": "notify",
				})
				req = httptest.NewRequest(method, "/admin/v1/policies/quota", bytes.NewReader(body))
			}
			w := httptest.NewRecorder()
			if method == http.MethodGet {
				GetQuotaPolicy(deps).ServeHTTP(w, adminCtx(req))
			} else {
				SetQuotaPolicy(deps).ServeHTTP(w, adminCtx(req))
			}
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if quotaRepo.scopeCalledKey != "key_legacy" && (quotaRepo.saved == nil || quotaRepo.saved.KeyID != "key_legacy") {
				t.Fatalf("legacy prefix was not resolved to stable id: repo=%+v", quotaRepo)
			}
			var resp map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if resp["scope_id"] != "key_legacy" {
				t.Fatalf("scope_id=%v, want stable key id", resp["scope_id"])
			}
		})
	}
}

func TestQuotaPolicyKeyScopeRejectsAmbiguousLegacyPrefix(t *testing.T) {
	lookup := &fakeQuotaKeyLookup{prefixes: map[string][]*repository.InternalKey{
		"tenant_default|sk-ambiguous": {
			{ID: "key_a", TenantID: "tenant_default", KeyPrefix: "sk-ambiguous"},
			{ID: "key_b", TenantID: "tenant_default", KeyPrefix: "sk-ambiguous"},
		},
	}}
	quotaRepo := &fakeQuotaPolicyRepo{}
	deps := &Dependencies{SystemRepo: &quotaAuditSystemRepo{}, QuotaPolicyRepo: quotaRepo, QuotaKeyLookup: lookup}
	w := httptest.NewRecorder()
	req := adminCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/policies/quota?scope_type=key&scope_id=sk-ambiguous", nil))
	GetQuotaPolicy(deps).ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", w.Code, w.Body.String())
	}
	if quotaRepo.scopeCalledType != "" {
		t.Fatal("ambiguous prefix must not reach quota repository")
	}
}

// TestGetQuotaPolicyTeamScope: GET ?scope_type=team&scope_id=team_001 应走 GetByScope(team)，
// 并在响应中回显 scope_type / scope_id。
func TestGetQuotaPolicyTeamScope(t *testing.T) {
	systemRepo := &quotaAuditSystemRepo{}
	quotaRepo := &fakeQuotaPolicyRepo{}
	deps := &Dependencies{
		SystemRepo:      systemRepo,
		QuotaPolicyRepo: quotaRepo,
		DepartmentStore: &quotaTeamLookupStub{team: &repository.Team{ID: "team_001", TenantID: "tenant_default"}},
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/policies/quota?scope_type=team&scope_id=team_001", nil)
	req = adminCtx(req)
	w := httptest.NewRecorder()

	GetQuotaPolicy(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if quotaRepo.scopeCalledType != "team" {
		t.Fatalf("GetByScope scope type = %q, want team", quotaRepo.scopeCalledType)
	}
	if quotaRepo.scopeCalledTeam != "team_001" {
		t.Fatalf("GetByScope team id = %q, want team_001", quotaRepo.scopeCalledTeam)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
	}
	if resp["scope_type"] != "team" {
		t.Fatalf("resp scope_type = %v, want team", resp["scope_type"])
	}
	if resp["scope_id"] != "team_001" {
		t.Fatalf("resp scope_id = %v, want team_001", resp["scope_id"])
	}
}

func (r *quotaAuditSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, r.Get, keys)
}
