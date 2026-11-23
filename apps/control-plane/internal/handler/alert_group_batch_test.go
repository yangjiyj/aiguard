package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// fakeBatchAlertGroupRepo 记录批量迁移调用；只有 owned 里的 id 视为本租户/本部门可处置的开放组。
type fakeBatchAlertGroupRepo struct {
	fakeAlertGroupRepo
	owned      map[string]bool
	gotTenant  string
	gotIDs     []string
	gotStatus  repository.AlertGroupStatus
	gotActor   string
	gotNote    string
	gotProject []string
	calls      int
}

func (f *fakeBatchAlertGroupRepo) BatchUpdateStatus(ctx context.Context, in repository.AlertGroupBatchStatusInput) (repository.AlertGroupBatchStatusResult, error) {
	f.calls++
	f.gotTenant, f.gotIDs, f.gotStatus, f.gotActor, f.gotNote, f.gotProject = in.TenantID, in.IDs, in.Status, in.ActorID, in.Note, in.ProjectIDs
	var res repository.AlertGroupBatchStatusResult
	for _, id := range in.IDs {
		if f.owned[id] {
			res.UpdatedIDs = append(res.UpdatedIDs, id)
		} else {
			res.Failed = append(res.Failed, repository.AlertGroupBatchFailure{ID: id, Reason: repository.AlertGroupBatchReasonNotFound})
		}
	}
	return res, nil
}

func batchRequest(t *testing.T, role string, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/alert-groups/batch-status", strings.NewReader(body))
	user := &repository.User{ID: "user_1", TenantID: "tenant_a", Role: role, Status: "active"}
	ctx := context.WithValue(req.Context(), auth.UserKey, user)
	return req.WithContext(ctx)
}

func TestBatchUpdateAlertGroupStatusMigratesOwnedAndReportsForeign(t *testing.T) {
	repo := &fakeBatchAlertGroupRepo{owned: map[string]bool{"ag_1": true, "ag_2": true}}
	sys := &capturingSystemRepo{}
	deps := &Dependencies{AlertGroupRepo: repo, SystemRepo: sys}
	body := `{"ids":["ag_1","ag_2","ag_2","ag_other_tenant"],"status":"false_positive","note":"批量误报","filters":{"type":"security_event","rule":"国内银行卡号","from":"2026-09-01","to":"2026-09-30","status":"open"}}`
	rr := httptest.NewRecorder()

	BatchUpdateAlertGroupStatus(deps)(rr, batchRequest(t, "platform_admin", body))

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if repo.gotTenant != "tenant_a" || repo.gotStatus != repository.AlertGroupStatusFalsePositive || repo.gotActor != "user_1" || repo.gotNote != "批量误报" {
		t.Fatalf("unexpected repo call: %+v", repo)
	}
	if strings.Join(repo.gotIDs, ",") != "ag_1,ag_2,ag_other_tenant" {
		t.Fatalf("ids should be deduplicated in order, got %v", repo.gotIDs)
	}
	if repo.gotProject != nil {
		t.Fatalf("full-tenant admin must not be narrowed by project, got %v", repo.gotProject)
	}
	var out struct {
		Requested int `json:"requested"`
		Updated   int `json:"updated"`
		Failed    []struct {
			ID     string `json:"id"`
			Reason string `json:"reason"`
		} `json:"failed"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Requested != 3 || out.Updated != 2 || len(out.Failed) != 1 || out.Failed[0].ID != "ag_other_tenant" || out.Failed[0].Reason != "not_found" {
		t.Fatalf("unexpected response: %s", rr.Body.String())
	}
	if len(sys.auditOps) != 1 {
		t.Fatalf("expected exactly one audit op for the batch, got %d", len(sys.auditOps))
	}
	op := sys.auditOps[0]
	if op.ActionType != "alert_group.batch_status" || op.TargetType != "alert_group" {
		t.Fatalf("unexpected audit op: %+v", op)
	}
	d := op.ActionDetail
	if d["status"] != "false_positive" || d["requested"] != 3 || d["updated"] != 2 || d["failed"] != 1 {
		t.Fatalf("audit detail missing counts: %#v", d)
	}
	filters, _ := d["filters"].(map[string]any)
	if filters["type"] != "security_event" || filters["rule"] != "国内银行卡号" || filters["from"] != "2026-09-01" {
		t.Fatalf("audit detail missing filters: %#v", d["filters"])
	}
	if _, ok := d["ids_sha256"].(string); !ok {
		t.Fatalf("audit detail missing ids digest: %#v", d)
	}
	if sample, _ := d["ids_sample"].([]string); len(sample) != 3 {
		t.Fatalf("audit detail ids_sample = %#v", d["ids_sample"])
	}
}

func TestBatchUpdateAlertGroupStatusRejectsInvalidStatus(t *testing.T) {
	for _, status := range []string{"open", "deleted", ""} {
		repo := &fakeBatchAlertGroupRepo{owned: map[string]bool{"ag_1": true}}
		sys := &capturingSystemRepo{}
		deps := &Dependencies{AlertGroupRepo: repo, SystemRepo: sys}
		rr := httptest.NewRecorder()
		BatchUpdateAlertGroupStatus(deps)(rr, batchRequest(t, "platform_admin", fmt.Sprintf(`{"ids":["ag_1"],"status":%q}`, status)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status %q: code=%d body=%s", status, rr.Code, rr.Body.String())
		}
		if repo.calls != 0 || len(sys.auditOps) != 0 {
			t.Fatalf("status %q must not reach repo or audit", status)
		}
	}
}

func TestBatchUpdateAlertGroupStatusRequiresExplicitBoundedIDs(t *testing.T) {
	many := make([]string, 0, 501)
	for i := 0; i < 501; i++ {
		many = append(many, fmt.Sprintf("%q", fmt.Sprintf("ag_%d", i)))
	}
	cases := map[string]string{
		"empty ids":     `{"ids":[],"status":"resolved"}`,
		"missing ids":   `{"status":"resolved","filters":{"type":"security_event"}}`,
		"blank id":      `{"ids":["  "],"status":"resolved"}`,
		"over limit":    `{"ids":[` + strings.Join(many, ",") + `],"status":"resolved"}`,
		"unknown field": `{"ids":["ag_1"],"status":"resolved","all_matching":true}`,
		"invalid json":  `{"ids":`,
		"overlong id":   `{"ids":["` + strings.Repeat("a", 129) + `"],"status":"resolved"}`,
	}
	for name, body := range cases {
		repo := &fakeBatchAlertGroupRepo{owned: map[string]bool{"ag_1": true}}
		deps := &Dependencies{AlertGroupRepo: repo, SystemRepo: &capturingSystemRepo{}}
		rr := httptest.NewRecorder()
		BatchUpdateAlertGroupStatus(deps)(rr, batchRequest(t, "platform_admin", body))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: code=%d body=%s", name, rr.Code, rr.Body.String())
		}
		if repo.calls != 0 {
			t.Fatalf("%s: repo must not be called", name)
		}
	}
}

func TestBatchUpdateAlertGroupStatusRequiresUser(t *testing.T) {
	repo := &fakeBatchAlertGroupRepo{}
	deps := &Dependencies{AlertGroupRepo: repo}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/alert-groups/batch-status", strings.NewReader(`{"ids":["ag_1"],"status":"resolved"}`))
	rr := httptest.NewRecorder()
	BatchUpdateAlertGroupStatus(deps)(rr, req)
	if rr.Code != http.StatusUnauthorized || repo.calls != 0 {
		t.Fatalf("code=%d calls=%d", rr.Code, repo.calls)
	}
}

func TestBatchUpdateAlertGroupStatusUnavailableWithoutBatchRepo(t *testing.T) {
	deps := &Dependencies{AlertGroupRepo: &fakeAlertGroupRepo{}}
	rr := httptest.NewRecorder()
	BatchUpdateAlertGroupStatus(deps)(rr, batchRequest(t, "platform_admin", `{"ids":["ag_1"],"status":"resolved"}`))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d", rr.Code)
	}
}

// 批量处置只允许管理员类角色（系统管理员、安全管理员、租户管理员）：RBAC 中间件默认只记录不拦截，
// handler 按角色硬性拒绝，普通用户、部门主管（只有告警只读权限）、审计员都不能调用，也不触库。
func TestBatchUpdateAlertGroupStatusRejectsNonAdminRoles(t *testing.T) {
	for _, role := range []string{"developer", "member", "dept_manager", "auditor", ""} {
		repo := &fakeBatchAlertGroupRepo{owned: map[string]bool{"ag_1": true}}
		deps := &Dependencies{AlertGroupRepo: repo, SystemRepo: &capturingSystemRepo{}}
		rr := httptest.NewRecorder()
		BatchUpdateAlertGroupStatus(deps)(rr, batchRequest(t, role, `{"ids":["ag_1"],"status":"resolved"}`))
		if rr.Code != http.StatusForbidden || repo.calls != 0 || !strings.Contains(rr.Body.String(), "无权处置告警") {
			t.Fatalf("role=%q code=%d calls=%d body=%s", role, rr.Code, repo.calls, rr.Body.String())
		}
	}
	for _, role := range []string{"platform_admin", "security_officer", "tenant_admin", "tenant_owner"} {
		repo := &fakeBatchAlertGroupRepo{owned: map[string]bool{"ag_1": true}}
		deps := &Dependencies{AlertGroupRepo: repo, SystemRepo: &capturingSystemRepo{}}
		rr := httptest.NewRecorder()
		BatchUpdateAlertGroupStatus(deps)(rr, batchRequest(t, role, `{"ids":["ag_1"],"status":"resolved"}`))
		if rr.Code != http.StatusOK || repo.calls != 1 {
			t.Fatalf("role=%q must be allowed: code=%d calls=%d", role, rr.Code, repo.calls)
		}
	}
	// 旧版 admin 角色（升级装机可能残留）按系统管理员处理，不被角色校验拒绝。
	rr := httptest.NewRecorder()
	BatchUpdateAlertGroupStatus(&Dependencies{AlertGroupRepo: &fakeBatchAlertGroupRepo{}, SystemRepo: &capturingSystemRepo{}})(rr, batchRequest(t, "admin", `{"ids":["ag_1"],"status":"resolved"}`))
	if rr.Code == http.StatusForbidden {
		t.Fatalf("legacy admin must not be rejected by the role check: %s", rr.Body.String())
	}
}

func TestListAlertGroupsPassesBacklogFilters(t *testing.T) {
	repo := &fakeAlertGroupRepo{}
	deps := &Dependencies{AlertGroupRepo: repo}
	req := alertGroupTestRequest(http.MethodGet, "/admin/v1/alert-groups?status=open&type=security_event&rule=%E5%9B%BD%E5%86%85%E9%93%B6%E8%A1%8C%E5%8D%A1%E5%8F%B7&from=2026-09-01T00:00:00Z&to=2026-09-30T00:00:00Z", "tenant_default", "user_1", nil)
	rr := httptest.NewRecorder()
	ListAlertGroups(deps)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	f := repo.listFilter
	if f.AlertType != "security_event" || f.Rule != "国内银行卡号" || f.LastSeenFrom.IsZero() || f.LastSeenTo.IsZero() {
		t.Fatalf("filters not passed: %+v", f)
	}
}

func TestListAlertGroupsRejectsBadTimeRange(t *testing.T) {
	repo := &fakeAlertGroupRepo{}
	deps := &Dependencies{AlertGroupRepo: repo}
	req := alertGroupTestRequest(http.MethodGet, "/admin/v1/alert-groups?from=yesterday", "tenant_default", "user_1", nil)
	rr := httptest.NewRecorder()
	ListAlertGroups(deps)(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code=%d", rr.Code)
	}
}

func TestAlertGroupDTOExposesRuleName(t *testing.T) {
	dto := toAlertGroupDTO(&repository.AlertGroup{ID: "ag_1", BodyJSON: map[string]any{"rule_name": "国内银行卡号", "rule_id": "regex_bank_card_cn"}})
	if dto.RuleName != "国内银行卡号" {
		t.Fatalf("rule_name = %q", dto.RuleName)
	}
}
