package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
)

type contentConfigSystemRepo struct {
	settings map[string]string
	audits   []*repository.AuditOperation
}

type contentExceptionKeyLookupStub struct {
	key      *repository.InternalKey
	err      error
	tenantID string
	keyID    string
}

func (s *contentExceptionKeyLookupStub) GetByID(_ context.Context, tenantID, keyID string) (*repository.InternalKey, error) {
	s.tenantID, s.keyID = tenantID, keyID
	return s.key, s.err
}

type contentExceptionTeamLookupStub struct {
	team *repository.Team
	err  error
	id   string
}

func (s *contentExceptionTeamLookupStub) GetByID(_ context.Context, id string) (*repository.Team, error) {
	s.id = id
	return s.team, s.err
}

func (r *contentConfigSystemRepo) Get(_ context.Context, key string) (*repository.SystemSetting, error) {
	if r.settings == nil {
		return nil, nil
	}
	value, ok := r.settings[key]
	if !ok {
		return nil, nil
	}
	return &repository.SystemSetting{Key: key, Value: value, UpdatedAt: time.Now()}, nil
}
func (r *contentConfigSystemRepo) GetAll(_ context.Context) ([]*repository.SystemSetting, error) {
	settings := make([]*repository.SystemSetting, 0, len(r.settings))
	for key, value := range r.settings {
		settings = append(settings, &repository.SystemSetting{Key: key, Value: value, UpdatedAt: time.Now()})
	}
	return settings, nil
}
func (r *contentConfigSystemRepo) Set(_ context.Context, key, value string) error {
	if r.settings == nil {
		r.settings = map[string]string{}
	}
	r.settings[key] = value
	return nil
}
func (r *contentConfigSystemRepo) SetMultiple(ctx context.Context, settings map[string]string) error {
	for key, value := range settings {
		if err := r.Set(ctx, key, value); err != nil {
			return err
		}
	}
	return nil
}
func (r *contentConfigSystemRepo) CreateAuditOperation(_ context.Context, op *repository.AuditOperation) error {
	r.audits = append(r.audits, op)
	return nil
}
func (r *contentConfigSystemRepo) ListAuditOperations(_ context.Context, _, _ int, _ string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, nil
}
func (r *contentConfigSystemRepo) GetBool(_ context.Context, key string) (bool, error) {
	if r.settings == nil {
		return false, nil
	}
	return r.settings[key] == "true", nil
}

func withContentConfigUser(req *http.Request, role, tenantID string) *http.Request {
	user := &repository.User{ID: "user_content_admin", TenantID: tenantID, Role: role, Status: "active"}
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
}

func serveCreateContentExceptionWithoutDatabase(body []byte) (recorder *httptest.ResponseRecorder, panicValue any) {
	recorder = httptest.NewRecorder()
	request := withContentConfigUser(
		httptest.NewRequest(http.MethodPost, "/admin/v1/content-security/exceptions", bytes.NewReader(body)),
		"tenant_owner",
		"tenant-content-boundary",
	)
	defer func() {
		panicValue = recover()
	}()
	CreateContentAuditException(&Dependencies{RuleRepo: repository.NewRuleRepository(nil)}).ServeHTTP(recorder, request)
	return recorder, nil
}

func marshalContentExceptionRequest(t *testing.T, fields map[string]string) []byte {
	t.Helper()
	body, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal content exception request: %v", err)
	}
	return body
}

func TestCreateContentAuditExceptionRejectsInvalidStrictPackScopeWith422(t *testing.T) {
	tests := []struct {
		name   string
		fields map[string]string
	}{
		{name: "empty scope", fields: map[string]string{"reason": "required reason", "decision": "audit"}},
		{name: "unknown scope", fields: map[string]string{"scope_type": "workspace", "reason": "required reason", "decision": "audit"}},
		{name: "project without ref", fields: map[string]string{"scope_type": "project", "reason": "required reason", "decision": "audit"}},
		{name: "user with blank ref", fields: map[string]string{"scope_type": "user", "scope_ref": "   ", "reason": "required reason", "decision": "audit"}},
		{name: "rule without rule reference", fields: map[string]string{"scope_type": "rule", "reason": "required reason", "decision": "audit"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recorder, panicValue := serveCreateContentExceptionWithoutDatabase(marshalContentExceptionRequest(t, tc.fields))
			if panicValue != nil {
				t.Fatalf("invalid request reached repository database instead of returning 422: %v", panicValue)
			}
			if recorder.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status=%d want=422 body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestCreateContentAuditExceptionRejectsOversizedFieldsWith422(t *testing.T) {
	tests := []struct {
		name   string
		fields map[string]string
	}{
		{name: "scope type", fields: map[string]string{"scope_type": strings.Repeat("t", 33), "reason": "reason", "decision": "audit"}},
		{name: "scope ref", fields: map[string]string{"scope_type": "project", "scope_ref": strings.Repeat("p", 256), "reason": "reason", "decision": "audit"}},
		{name: "rule id", fields: map[string]string{"scope_type": "rule", "rule_id": strings.Repeat("r", 65), "reason": "reason", "decision": "audit"}},
		{name: "rule ref", fields: map[string]string{"scope_type": "rule", "rule_ref": strings.Repeat("r", 256), "reason": "reason", "decision": "audit"}},
		{name: "reason", fields: map[string]string{"scope_type": "tenant", "reason": strings.Repeat("x", 2049), "decision": "audit"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recorder, panicValue := serveCreateContentExceptionWithoutDatabase(marshalContentExceptionRequest(t, tc.fields))
			if panicValue != nil {
				t.Fatalf("oversized field reached repository database instead of returning 422: %v", panicValue)
			}
			if recorder.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status=%d want=422 body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestCreateContentAuditExceptionRejectsOversizedBodyWith413(t *testing.T) {
	body := marshalContentExceptionRequest(t, map[string]string{
		"scope_type": "tenant",
		"decision":   "audit",
		"reason":     strings.Repeat("x", 20<<10),
	})
	recorder, panicValue := serveCreateContentExceptionWithoutDatabase(body)
	if panicValue != nil {
		t.Fatalf("oversized body reached repository database instead of returning 413: %v", panicValue)
	}
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want=413 body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestCreateContentAuditExceptionRejectsOversizedTrailingBodyWith413(t *testing.T) {
	body := marshalContentExceptionRequest(t, map[string]string{
		"scope_type": "tenant",
		"decision":   "audit",
		"reason":     "valid prefix",
	})
	body = append(body, bytes.Repeat([]byte(" "), 20<<10)...)
	recorder, panicValue := serveCreateContentExceptionWithoutDatabase(body)
	if panicValue != nil {
		t.Fatalf("oversized trailing body reached repository: %v", panicValue)
	}
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want=413 body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestCreateContentAuditExceptionRejectsInvalidExpiryWith422(t *testing.T) {
	body := marshalContentExceptionRequest(t, map[string]string{
		"scope_type": "tenant",
		"decision":   "audit",
		"reason":     "required reason",
		"expires_at": "tomorrow",
	})
	recorder, panicValue := serveCreateContentExceptionWithoutDatabase(body)
	if panicValue != nil {
		t.Fatalf("invalid expiry panicked instead of returning 422: %v", panicValue)
	}
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d want=422 body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestCreateContentAuditExceptionRejectsCrossTenantStableKey(t *testing.T) {
	lookup := &contentExceptionKeyLookupStub{key: &repository.InternalKey{
		ID: "key-other", TenantID: "tenant-other",
	}}
	body := []byte(`{"scope_type":"key_v1","scope_ref":"key-other","decision":"audit","reason":"reviewed","expires_at":"never"}`)
	request := withContentConfigUser(
		httptest.NewRequest(http.MethodPost, "/admin/v1/content-security/exceptions", bytes.NewReader(body)),
		"tenant_owner",
		"tenant-a",
	)
	request.Header.Set("X-User-ID", "spoofed-cross-tenant-user")
	recorder := httptest.NewRecorder()

	CreateContentAuditException(&Dependencies{
		RuleRepo:                  repository.NewRuleRepository(nil),
		ContentExceptionKeyLookup: lookup,
	}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d want=422 body=%s", recorder.Code, recorder.Body.String())
	}
	if lookup.tenantID != "tenant-a" || lookup.keyID != "key-other" {
		t.Fatalf("stable key lookup was not tenant scoped: tenant=%q key=%q", lookup.tenantID, lookup.keyID)
	}
}

func TestCreateContentAuditExceptionRejectsCrossTenantActorDepartment(t *testing.T) {
	lookup := &contentExceptionTeamLookupStub{team: &repository.Team{
		ID: "dept-other", TenantID: "tenant-other",
	}}
	body := []byte(`{"scope_type":"actor_department_v1","scope_ref":"dept-other","include_children":true,"decision":"audit","reason":"reviewed","expires_at":"never"}`)
	request := withContentConfigUser(
		httptest.NewRequest(http.MethodPost, "/admin/v1/content-security/exceptions", bytes.NewReader(body)),
		"tenant_owner",
		"tenant-a",
	)
	request.Header.Set("X-Department-ID", "dept-spoofed")
	recorder := httptest.NewRecorder()

	CreateContentAuditException(&Dependencies{
		RuleRepo:                   repository.NewRuleRepository(nil),
		ContentExceptionTeamLookup: lookup,
	}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d want=422 body=%s", recorder.Code, recorder.Body.String())
	}
	if lookup.id != "dept-other" {
		t.Fatalf("department lookup used %q, want request scope_ref", lookup.id)
	}
}

func TestContentAuditExceptionScopeOwnershipAcceptsCurrentTenantResources(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/content-security/exceptions", nil)
	tests := []struct {
		name      string
		deps      *Dependencies
		exception *repository.ContentAuditException
	}{
		{
			name: "stable key",
			deps: &Dependencies{ContentExceptionKeyLookup: &contentExceptionKeyLookupStub{
				key: &repository.InternalKey{ID: "key-a", TenantID: "tenant-a"},
			}},
			exception: &repository.ContentAuditException{
				TenantID: "tenant-a", ScopeType: "key_v1", ScopeRef: "key-a",
			},
		},
		{
			name: "actor department",
			deps: &Dependencies{ContentExceptionTeamLookup: &contentExceptionTeamLookupStub{
				team: &repository.Team{ID: "dept-a", TenantID: "tenant-a"},
			}},
			exception: &repository.ContentAuditException{
				TenantID: "tenant-a", ScopeType: "actor_department_v1", ScopeRef: "dept-a",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			if !validateContentExceptionScopeOwnership(recorder, request, tc.deps, tc.exception) {
				t.Fatalf("current-tenant scope rejected: status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestContentRuleSetIDIsTenantScoped(t *testing.T) {
	if got := contentRuleSetID("tenant_default"); got != defaultContentRuleSetID {
		t.Fatalf("tenant_default rule set id = %q, want %q", got, defaultContentRuleSetID)
	}
	first := contentRuleSetID("tenant_a")
	second := contentRuleSetID("tenant_b")
	if first == defaultContentRuleSetID || second == defaultContentRuleSetID || first == second {
		t.Fatalf("tenant scoped rule set ids are not isolated: first=%q second=%q", first, second)
	}
}

func TestUpdateContentFilePolicyPersistsAndAudits(t *testing.T) {
	systemRepo := &contentConfigSystemRepo{}
	deps := &Dependencies{SystemRepo: systemRepo}
	body := []byte(`{"allowed_types":["pdf"],"blocked_types":["pe","script"],"review_types":["zip"],"max_file_mb":50,"max_zip_ratio":200,"max_attachments":6}`)
	req := withContentConfigUser(httptest.NewRequest(http.MethodPut, "/admin/v1/content-security/file-policy", bytes.NewReader(body)), "tenant_owner", "tenant_default")
	rr := httptest.NewRecorder()

	UpdateContentFilePolicy(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got rules.FilePolicy
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.MaxFileMB != 50 || got.MaxZipRatio != 200 || got.MaxAttachments != 6 {
		t.Fatalf("unexpected policy: %+v", got)
	}
	if systemRepo.settings[contentFilePolicySettingKey] == "" {
		t.Fatalf("file policy setting was not persisted")
	}
	if len(systemRepo.audits) != 1 || systemRepo.audits[0].ActionType != "content_file_policy.update" {
		t.Fatalf("expected content_file_policy.update audit, got %+v", systemRepo.audits)
	}
}

func TestCreateContentSensitiveRuleStoresRegexInTenantRuleset(t *testing.T) {
	dbURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	tenantID := fmt.Sprintf("tenant_content_cfg_%d", time.Now().UnixNano())
	ruleSetID := contentRuleSetID(tenantID)
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, $3, $4, true)`, tenantID, tenantID, "enterprise", "active"); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		defer db.Close()
		if _, err := db.Exec(ctx, `DELETE FROM rules WHERE rule_set_id IN (SELECT id FROM rule_sets WHERE tenant_id = $1)`, tenantID); err != nil {
			t.Errorf("cleanup rules: %v", err)
		}
		if _, err := db.Exec(ctx, `DELETE FROM rule_sets WHERE tenant_id = $1`, tenantID); err != nil {
			t.Errorf("cleanup rule_sets: %v", err)
		}
		if _, err := db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID); err != nil {
			t.Errorf("cleanup tenant: %v", err)
		}
	})

	deps := &Dependencies{RuleSetRepo: repository.NewRuleSetRepository(db), RuleRepo: repository.NewRuleRepository(db), SystemRepo: &contentConfigSystemRepo{}}
	body := []byte(`{"name":"客户病历号","regex":"MR-[0-9]{8}","category":"customer_medical_record","severity":"high","action":"block","field_names":["病历号"]}`)
	req := withContentConfigUser(httptest.NewRequest(http.MethodPost, "/admin/v1/content-security/rules", bytes.NewReader(body)), "tenant_owner", tenantID)
	rr := httptest.NewRecorder()

	CreateContentSensitiveRule(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	var storedRuleSetID string
	var matchConfig []byte
	if err := db.QueryRow(ctx, `SELECT rule_set_id, match_config_json FROM rules WHERE name = $2 AND rule_set_id = $1`, ruleSetID, "客户病历号").Scan(&storedRuleSetID, &matchConfig); err != nil {
		t.Fatalf("query stored rule: %v", err)
	}
	if storedRuleSetID != ruleSetID {
		t.Fatalf("rule_set_id = %q, want %q", storedRuleSetID, ruleSetID)
	}
	var cfg map[string]any
	if err := json.Unmarshal(matchConfig, &cfg); err != nil {
		t.Fatalf("decode match config: %v", err)
	}
	if cfg["regex"] != "MR-[0-9]{8}" || cfg["category"] != "customer_medical_record" {
		t.Fatalf("unexpected match config: %+v", cfg)
	}
}

func TestNormalizeSensitiveRuleRequestAllowsKeywordOnly(t *testing.T) {
	req := createSensitiveRuleRequest{
		Name:     " 客户项目代号 ",
		Keywords: []string{"星河计划", " ", "Alpha-7"},
	}

	normalized, err := normalizeSensitiveRuleRequest(req)

	if err != nil {
		t.Fatalf("normalize keyword rule: %v", err)
	}
	if normalized.ruleType != "keyword" {
		t.Fatalf("ruleType = %q, want keyword", normalized.ruleType)
	}
	if normalized.name != "客户项目代号" || normalized.category != "customer_sensitive_data" || normalized.severity != "high" || normalized.action != "audit" {
		t.Fatalf("unexpected defaults: %+v", normalized)
	}
	if got := normalized.matchConfig["regex"]; got != nil {
		t.Fatalf("regex should not be present for keyword rule, got %#v", got)
	}
	keywords, ok := normalized.matchConfig["keywords"].([]string)
	if !ok {
		t.Fatalf("keywords missing or wrong type: %#v", normalized.matchConfig["keywords"])
	}
	if len(keywords) != 2 || keywords[0] != "星河计划" || keywords[1] != "Alpha-7" {
		t.Fatalf("keywords = %#v", keywords)
	}
}

func TestNormalizeSensitiveRuleRequestAllowsFieldNameOnly(t *testing.T) {
	req := createSensitiveRuleRequest{
		Name:       "客户合同字段",
		FieldNames: []string{"contract_amount", "", " customer_name "},
		Severity:   "medium",
	}

	normalized, err := normalizeSensitiveRuleRequest(req)

	if err != nil {
		t.Fatalf("normalize field_name rule: %v", err)
	}
	if normalized.ruleType != "field_name" || normalized.severity != "medium" || normalized.action != "audit" {
		t.Fatalf("unexpected normalized rule: %+v", normalized)
	}
	fieldNames, ok := normalized.matchConfig["field_names"].([]string)
	if !ok {
		t.Fatalf("field_names missing or wrong type: %#v", normalized.matchConfig["field_names"])
	}
	if len(fieldNames) != 2 || fieldNames[0] != "contract_amount" || fieldNames[1] != "customer_name" {
		t.Fatalf("field_names = %#v", fieldNames)
	}
}

func TestNormalizeSensitiveRuleRequestRejectsEmptyMatcher(t *testing.T) {
	_, err := normalizeSensitiveRuleRequest(createSensitiveRuleRequest{Name: "空规则"})

	if err == nil {
		t.Fatalf("expected empty matcher to be rejected")
	}
	if !strings.Contains(err.Error(), "regex/keywords/field_names") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func (r *contentConfigSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, r.Get, keys)
}
