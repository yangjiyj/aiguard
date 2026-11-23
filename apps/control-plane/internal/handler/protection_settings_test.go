package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

type fakeProtectionStore struct {
	rows    map[string]protection.Setting
	readErr error
}

func (f *fakeProtectionStore) StoredRows(_ context.Context, _ string) ([]repository.ProtectionSettingRow, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	var out []repository.ProtectionSettingRow
	for _, item := range protection.All() {
		if s, ok := f.rows[item.Key]; ok {
			at := time.Unix(1700000000, 0).UTC()
			out = append(out, repository.ProtectionSettingRow{Key: item.Key, Action: string(s.Action), Params: s.Params, UpdatedBy: "u-x", UpdatedAt: &at})
		}
	}
	return out, nil
}

func (f *fakeProtectionStore) Settings(_ context.Context, _ string) (protection.Settings, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	out := protection.Settings{}
	for k, v := range f.rows {
		out[k] = v
	}
	return out, nil
}

func (f *fakeProtectionStore) Upsert(_ context.Context, _, _ string, in map[string]protection.Setting) (map[string]protection.Setting, error) {
	before := map[string]protection.Setting{}
	if f.rows == nil {
		f.rows = map[string]protection.Setting{}
	}
	for k, v := range in {
		if old, ok := f.rows[k]; ok {
			before[k] = old
		}
		f.rows[k] = v
	}
	return before, nil
}

type captureAuditSystemRepo struct {
	agentGuardAuditSystemRepo
	ops []*repository.AuditOperation
}

func (r *captureAuditSystemRepo) CreateAuditOperation(_ context.Context, op *repository.AuditOperation) error {
	r.ops = append(r.ops, op)
	return nil
}

func protectionReq(method, role string, body any) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, "/admin/v1/protection-settings", &buf)
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "u-" + role, TenantID: "tenant-a", Role: role}))
}

type protectionListResp struct {
	Items []struct {
		Key           string         `json:"key"`
		Group         string         `json:"group"`
		Actions       []string       `json:"actions"`
		DefaultAction string         `json:"default_action"`
		Action        string         `json:"action"`
		Configured    bool           `json:"configured"`
		Params        map[string]any `json:"params"`
		ParamSpecs    []any          `json:"param_specs"`
	} `json:"items"`
}

func TestProtectionSettingsListFillsDefaults(t *testing.T) {
	store := &fakeProtectionStore{rows: map[string]protection.Setting{"agent.env_file": {Action: protection.ActionBlock}}}
	deps := &Dependencies{ProtectionSettingsStore: store}
	rec := httptest.NewRecorder()
	// 只测 handler，不经过 RBAC/SoD 中间件（权限放行见 permission 包的三员矩阵测试）。
	GetProtectionSettings(deps)(rec, protectionReq(http.MethodGet, "security_officer", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	var resp protectionListResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	var want []protection.Item
	for _, it := range protection.All() {
		if it.Group != protection.GroupAgentRestricted {
			want = append(want, it)
		}
	}
	if len(resp.Items) != len(want) {
		t.Fatalf("items %d want %d", len(resp.Items), len(want))
	}
	for i, it := range resp.Items {
		if it.Key != want[i].Key {
			t.Fatalf("order mismatch at %d: %s vs %s", i, it.Key, want[i].Key)
		}
		if it.Key == "agent.env_file" {
			if it.Action != "block" || !it.Configured {
				t.Fatalf("configured item: %+v", it)
			}
			continue
		}
		if it.Action != "alert_allow" || it.Configured || it.DefaultAction != "alert_allow" || it.Params == nil || len(it.Actions) == 0 {
			t.Fatalf("default item: %+v", it)
		}
	}
	for _, it := range resp.Items {
		if it.Key == "agent.tool_failure_loop" && len(it.ParamSpecs) != 2 {
			t.Fatalf("param_specs missing: %+v", it)
		}
	}
}

func TestProtectionSettingsUpdateRequiresSecurityPolicyRole(t *testing.T) {
	body := map[string]any{"items": map[string]any{"agent.ssh_private_key": map[string]any{"action": "block", "params": map[string]any{}}}}
	for role, want := range map[string]int{"auditor": 403, "tenant_admin": 403, "platform_admin": 200, "security_officer": 200} {
		deps := &Dependencies{ProtectionSettingsStore: &fakeProtectionStore{}}
		rec := httptest.NewRecorder()
		UpdateProtectionSettings(deps)(rec, protectionReq(http.MethodPut, role, body))
		if rec.Code != want {
			t.Fatalf("%s: status %d want %d (%s)", role, rec.Code, want, rec.Body.String())
		}
	}
}

func TestProtectionSettingsUpdateRejectsUnknownKeyAndBadAction(t *testing.T) {
	cases := []map[string]any{
		{"agent.nope": map[string]any{"action": "block"}},
		{protection.KeyRestrictedFile: map[string]any{"action": "block"}}, // 受限文件在专页配置，不走这个接口
		{"agent.ssh_private_key": map[string]any{"action": "deny"}},
		{"agent.confirm_without_channel": map[string]any{"action": "confirm"}},
		{"agent.tool_failure_loop": map[string]any{"action": "block", "params": map[string]any{"threshold": 0}}},
	}
	for _, items := range cases {
		store := &fakeProtectionStore{}
		rec := httptest.NewRecorder()
		UpdateProtectionSettings(&Dependencies{ProtectionSettingsStore: store})(rec, protectionReq(http.MethodPut, "platform_admin", map[string]any{"items": items}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%v: status %d", items, rec.Code)
		}
		if len(store.rows) != 0 {
			t.Fatalf("rejected update must not write: %v", store.rows)
		}
	}
}

func TestProtectionSettingsUpdateWritesAudit(t *testing.T) {
	audit := &captureAuditSystemRepo{}
	store := &fakeProtectionStore{rows: map[string]protection.Setting{"agent.ssh_private_key": {Action: protection.ActionRecord}}}
	deps := &Dependencies{ProtectionSettingsStore: store, SystemRepo: audit}
	rec := httptest.NewRecorder()
	UpdateProtectionSettings(deps)(rec, protectionReq(http.MethodPut, "security_officer",
		map[string]any{"items": map[string]any{"agent.ssh_private_key": map[string]any{"action": "block"}}}))
	if rec.Code != 200 {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if len(audit.ops) != 1 || audit.ops[0].ActionType != "protection_settings.update" {
		t.Fatalf("audit: %+v", audit.ops)
	}
	// 审计详情落库时会序列化成 JSON，按序列化后的结构断言。
	raw, err := json.Marshal(audit.ops[0].ActionDetail)
	if err != nil {
		t.Fatal(err)
	}
	var detail struct {
		Before map[string]protection.Setting `json:"before"`
		After  map[string]protection.Setting `json:"after"`
	}
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Before["agent.ssh_private_key"].Action != protection.ActionRecord || detail.After["agent.ssh_private_key"].Action != protection.ActionBlock {
		t.Fatalf("before/after: %s", raw)
	}
	var resp protectionListResp
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Items) == 0 {
		t.Fatal("update must return the list")
	}
}

type effectiveProtections struct {
	Data struct {
		Protections map[string]protection.Setting `json:"protections"`
	} `json:"data"`
}

func effectiveReq() *http.Request {
	req := withAgentGuardUser(httptest.NewRequest(http.MethodGet, "/admin/v1/internal/agentguard/effective-policy", nil))
	req.Header.Set("X-Tenant-ID", "tenant-a")
	return req
}

func TestInternalEffectivePolicyCarriesProtections(t *testing.T) {
	store := &fakeProtectionStore{rows: map[string]protection.Setting{"agent.ssh_private_key": {Action: protection.ActionBlock, Params: map[string]any{}}}}
	// policy == nil 分支
	deps := &Dependencies{AgentGuardPolicyRepo: newFakeAgentGuardPolicyRepo(), ProtectionSettingsStore: store}
	rec := httptest.NewRecorder()
	GetInternalAgentGuardEffectivePolicy(deps)(rec, effectiveReq())
	var got effectiveProtections
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || len(got.Data.Protections) != 1 || got.Data.Protections["agent.ssh_private_key"].Action != protection.ActionBlock {
		t.Fatalf("nil policy branch: %d %s", rec.Code, rec.Body.String())
	}
	// 正常分支
	repo := newFakeAgentGuardPolicyRepo()
	repo.policies["agp_x"] = &repository.AgentGuardPolicy{ID: "agp_x", TenantID: "tenant-a", Name: "p", ScopeType: "tenant", Mode: "light", DefaultAction: "audit", FailPolicy: "fail_open", Enabled: true, RulesJSON: map[string]any{}}
	repo.versions["agp_x"] = []*repository.AgentGuardPolicyVersion{{PolicyVersion: "v1", Active: true}}
	deps = &Dependencies{AgentGuardPolicyRepo: repo, ProtectionSettingsStore: store, SystemRepo: &agentGuardAuditSystemRepo{}}
	rec = httptest.NewRecorder()
	GetInternalAgentGuardEffectivePolicy(deps)(rec, effectiveReq())
	got = effectiveProtections{}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Data.Protections["agent.ssh_private_key"].Action != protection.ActionBlock {
		t.Fatalf("policy branch: %d %s", rec.Code, rec.Body.String())
	}
	// 读失败必须 500
	for name, d := range map[string]*Dependencies{
		"nil":    {AgentGuardPolicyRepo: newFakeAgentGuardPolicyRepo(), ProtectionSettingsStore: &fakeProtectionStore{readErr: errors.New("db down")}},
		"policy": {AgentGuardPolicyRepo: repo, ProtectionSettingsStore: &fakeProtectionStore{readErr: errors.New("db down")}, SystemRepo: &agentGuardAuditSystemRepo{}},
	} {
		rec = httptest.NewRecorder()
		GetInternalAgentGuardEffectivePolicy(d)(rec, effectiveReq())
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("%s: read failure must be 500, got %d", name, rec.Code)
		}
	}
}

func TestInternalEffectivePolicyFoldsLegacyDLPAction(t *testing.T) {
	mk := func(dlp string) *fakeAgentGuardPolicyRepo {
		repo := newFakeAgentGuardPolicyRepo()
		repo.policies["agp_x"] = &repository.AgentGuardPolicy{ID: "agp_x", TenantID: "tenant-a", Name: "p", ScopeType: "tenant", Mode: "light", DefaultAction: "audit", FailPolicy: "fail_open", Enabled: true,
			RulesJSON: map[string]any{}, DLPJSON: map[string]any{"high_confidence_secret_egress": dlp}}
		repo.versions["agp_x"] = []*repository.AgentGuardPolicyVersion{{PolicyVersion: "v1", Active: true}}
		return repo
	}
	run := func(dlp string, rows map[string]protection.Setting) protection.Setting {
		deps := &Dependencies{AgentGuardPolicyRepo: mk(dlp), ProtectionSettingsStore: &fakeProtectionStore{rows: rows}, SystemRepo: &agentGuardAuditSystemRepo{}}
		rec := httptest.NewRecorder()
		GetInternalAgentGuardEffectivePolicy(deps)(rec, effectiveReq())
		var got effectiveProtections
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		return got.Data.Protections["agent.secret_egress"]
	}
	for dlp, want := range map[string]protection.Action{"block": protection.ActionBlock, "audit": protection.ActionRecord, "allow": protection.ActionRecord} {
		if got := run(dlp, nil); got.Action != want {
			t.Fatalf("dlp %s folded to %q want %q", dlp, got.Action, want)
		}
	}
	if got := run("block", map[string]protection.Setting{"agent.secret_egress": {Action: protection.ActionConfirm}}); got.Action != protection.ActionConfirm {
		t.Fatalf("stored row must win, got %q", got.Action)
	}
}

func TestProtectionSettingsWithoutStoreReturns503(t *testing.T) {
	deps := &Dependencies{}
	rec := httptest.NewRecorder()
	GetProtectionSettings(deps)(rec, protectionReq(http.MethodGet, "security_officer", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET status %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	UpdateProtectionSettings(deps)(rec, protectionReq(http.MethodPut, "security_officer",
		map[string]any{"items": map[string]any{"agent.ssh_private_key": map[string]any{"action": "block"}}}))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("PUT status %d", rec.Code)
	}
}
