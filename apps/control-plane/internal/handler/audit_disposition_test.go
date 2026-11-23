package handler

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeAuditDispositionRepo struct {
	last       *repository.AuditDisposition
	authorized *bool
}

func (f *fakeAuditDispositionRepo) AuthorizeAuditDispositionSubject(context.Context, string, string, string, []string) (bool, error) {
	if f.authorized == nil {
		return true, nil
	}
	return *f.authorized, nil
}

func (f *fakeAuditDispositionRepo) UpsertAuthorized(
	ctx context.Context,
	d *repository.AuditDisposition,
	_ []string,
	_, _ string,
) (*repository.AuditDisposition, error) {
	allowed, err := f.AuthorizeAuditDispositionSubject(ctx, d.TenantID, d.SubjectType, d.SubjectID, nil)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, repository.ErrNotFound
	}
	return f.Upsert(ctx, d)
}

func (f *fakeAuditDispositionRepo) Upsert(_ context.Context, d *repository.AuditDisposition) (*repository.AuditDisposition, error) {
	f.last = d
	if d.ID == "" {
		d.ID = "disp_test"
	}
	d.CreatedAt = time.Now().UTC()
	d.UpdatedAt = d.CreatedAt
	return d, nil
}

func (f *fakeAuditDispositionRepo) List(_ context.Context, _, _, _ string, _, _ int) ([]*repository.AuditDisposition, int, error) {
	return nil, 0, nil
}

type fakeDispositionSystemRepo struct {
	ops []*repository.AuditOperation
}

func (f *fakeDispositionSystemRepo) Get(context.Context, string) (*repository.SystemSetting, error) {
	return nil, nil
}
func (f *fakeDispositionSystemRepo) GetAll(context.Context) ([]*repository.SystemSetting, error) {
	return nil, nil
}
func (f *fakeDispositionSystemRepo) Set(context.Context, string, string) error            { return nil }
func (f *fakeDispositionSystemRepo) SetMultiple(context.Context, map[string]string) error { return nil }
func (f *fakeDispositionSystemRepo) CreateAuditOperation(_ context.Context, op *repository.AuditOperation) error {
	f.ops = append(f.ops, op)
	return nil
}
func (f *fakeDispositionSystemRepo) ListAuditOperations(context.Context, int, int, string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, nil
}
func (f *fakeDispositionSystemRepo) GetBool(context.Context, string) (bool, error) { return false, nil }

// fakeDispositionEnforcer 记录处置派发的真实执行调用，用于断言「处置=吊销key→该 key 立即失效；处置=封禁→该用户被拒」
// 的派发被真正触发（执行细节由 disposition_enforcer.go 的生产实现复用既有流程承载）。
type fakeDispositionEnforcer struct {
	calls []DispositionAction
	err   error
}

func (f *fakeDispositionEnforcer) Enforce(_ context.Context, a DispositionAction) error {
	f.calls = append(f.calls, a)
	return f.err
}

func withAuditDispositionUser(req *http.Request, user *repository.User) *http.Request {
	ctx := context.WithValue(req.Context(), auth.UserKey, user)
	ctx = context.WithValue(ctx, auth.SessionKey, &repository.Session{UserID: user.ID, TenantID: user.TenantID})
	return req.WithContext(ctx)
}

func TestUpsertAuditDispositionWritesOperationAudit(t *testing.T) {
	dispositionRepo := &fakeAuditDispositionRepo{}
	systemRepo := &fakeDispositionSystemRepo{}
	deps := &Dependencies{AuditDispositionRepo: dispositionRepo, SystemRepo: systemRepo}

	body := bytes.NewBufferString(`{"subject_type":"tool_call","subject_id":"tc_agentguard","status":"false_positive","note":"已确认误报"}`)
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/audit/dispositions", body)
	req = withAuditDispositionUser(req, &repository.User{ID: "user_admin", Username: "admin", TenantID: "tenant_default", Role: "platform_admin"})
	w := httptest.NewRecorder()

	UpsertAuditDisposition(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if dispositionRepo.last == nil || dispositionRepo.last.Status != "false_positive" {
		t.Fatalf("disposition was not saved: %#v", dispositionRepo.last)
	}
	if len(systemRepo.ops) != 1 {
		t.Fatalf("expected one operation audit entry, got %d", len(systemRepo.ops))
	}
	op := systemRepo.ops[0]
	if op.ActionType != "audit_disposition.upsert" {
		t.Fatalf("action type = %s", op.ActionType)
	}
	if op.TargetType != "tool_call" || op.TargetID != "tc_agentguard" {
		t.Fatalf("unexpected target: %s/%s", op.TargetType, op.TargetID)
	}
	if op.ActionDetail["status"] != "false_positive" || op.ActionDetail["subject_type"] != "tool_call" {
		t.Fatalf("unexpected audit detail: %#v", op.ActionDetail)
	}
}

// TestUpsertAuditDispositionDispatchesRealAction 锁定退出标准「处置真生效」：
// 当处置带 action 时，必须把真实执行派发给 DispositionEnforcer（吊销 key / 封禁用户），
// 且审计明细带上 action / action_target。
func TestUpsertAuditDispositionDispatchesRealAction(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantAction string
		wantTarget string
	}{
		{
			name:       "吊销key",
			body:       `{"subject_type":"tool_call","subject_id":"tc_evil","status":"accepted","action":"revoke_key","action_target":"key_evil"}`,
			wantAction: "revoke_key",
			wantTarget: "key_evil",
		},
		{
			name:       "封禁用户",
			body:       `{"subject_type":"session","subject_id":"sess_evil","status":"escalated","action":"ban_user","action_target":"user_evil"}`,
			wantAction: "ban_user",
			wantTarget: "user_evil",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dispositionRepo := &fakeAuditDispositionRepo{}
			systemRepo := &fakeDispositionSystemRepo{}
			enforcer := &fakeDispositionEnforcer{}
			deps := &Dependencies{AuditDispositionRepo: dispositionRepo, SystemRepo: systemRepo, DispositionEnforcer: enforcer}

			body := bytes.NewBufferString(tc.body)
			req := httptest.NewRequest(http.MethodPut, "/admin/v1/audit/dispositions", body)
			req = withAuditDispositionUser(req, &repository.User{ID: "user_admin", Username: "admin", TenantID: "tenant_default", Role: "platform_admin"})
			w := httptest.NewRecorder()

			UpsertAuditDisposition(deps).ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
			}
			if len(enforcer.calls) != 1 {
				t.Fatalf("expected exactly one enforce call, got %d", len(enforcer.calls))
			}
			got := enforcer.calls[0]
			if got.Action != tc.wantAction || got.Target != tc.wantTarget {
				t.Fatalf("unexpected enforce action: %+v", got)
			}
			if got.TenantID != "tenant_default" {
				t.Fatalf("expected tenant_default operator scope, got %q", got.TenantID)
			}
			if len(systemRepo.ops) != 1 {
				t.Fatalf("expected one operation audit entry, got %d", len(systemRepo.ops))
			}
			if systemRepo.ops[0].ActionDetail["action"] != tc.wantAction || systemRepo.ops[0].ActionDetail["action_target"] != tc.wantTarget {
				t.Fatalf("audit detail missing action context: %#v", systemRepo.ops[0].ActionDetail)
			}
		})
	}
}

// TestUpsertAuditDispositionWithoutActionSkipsEnforcement 守住「仅定性、不处置」语义：
// 不带 action 的处置只落状态位与审计，绝不触发任何真实执行。
func TestUpsertAuditDispositionWithoutActionSkipsEnforcement(t *testing.T) {
	dispositionRepo := &fakeAuditDispositionRepo{}
	systemRepo := &fakeDispositionSystemRepo{}
	enforcer := &fakeDispositionEnforcer{}
	deps := &Dependencies{AuditDispositionRepo: dispositionRepo, SystemRepo: systemRepo, DispositionEnforcer: enforcer}

	body := bytes.NewBufferString(`{"subject_type":"tool_call","subject_id":"tc_agentguard","status":"false_positive","note":"已确认误报"}`)
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/audit/dispositions", body)
	req = withAuditDispositionUser(req, &repository.User{ID: "user_admin", Username: "admin", TenantID: "tenant_default", Role: "platform_admin"})
	w := httptest.NewRecorder()

	UpsertAuditDisposition(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(enforcer.calls) != 0 {
		t.Fatalf("expected no enforce calls without action, got %d", len(enforcer.calls))
	}
}

func TestUpsertAuditDispositionRejectsInvisibleSubjectBeforeWrite(t *testing.T) {
	denied := false
	repo := &fakeAuditDispositionRepo{authorized: &denied}
	deps := &Dependencies{AuditDispositionRepo: repo}
	body := bytes.NewBufferString(`{"subject_type":"request","subject_id":"request-other","status":"false_positive"}`)
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/audit/dispositions", body)
	req = withAuditDispositionUser(req, &repository.User{
		ID: "user-admin", TenantID: "tenant-a", Role: "tenant_admin",
	})
	recorder := httptest.NewRecorder()
	UpsertAuditDisposition(deps).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if repo.last != nil {
		t.Fatal("invisible subject must not be written")
	}
}

func TestUpsertAuditDispositionRejectsBlockSessionBeforeRepository(t *testing.T) {
	repo := &fakeAuditDispositionRepo{}
	deps := &Dependencies{AuditDispositionRepo: repo, DispositionEnforcer: &fakeDispositionEnforcer{}}
	body := bytes.NewBufferString(`{"subject_type":"session","subject_id":"session-a","status":"escalated","action":"block_session","action_target":"prefix-a"}`)
	req := withAuditDispositionUser(
		httptest.NewRequest(http.MethodPut, "/admin/v1/audit/dispositions", body),
		&repository.User{ID: "admin-a", TenantID: "tenant-a", Role: "tenant_admin"},
	)
	recorder := httptest.NewRecorder()
	UpsertAuditDisposition(deps).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if repo.last != nil {
		t.Fatal("unsupported block_session must not write a disposition")
	}
}

func TestUpsertAuditDispositionRejectsReadOnlyAndEmergencyRolesInHandler(t *testing.T) {
	for _, user := range []*repository.User{
		{ID: "auditor-a", TenantID: "tenant-a", Role: "auditor"},
		{ID: "manager-a", TenantID: "tenant-a", Role: "dept_manager"},
		{ID: "admin-a", TenantID: "tenant-a", Role: "tenant_admin", DepartmentAssignmentMode: "emergency"},
	} {
		t.Run(user.Role+"_"+user.DepartmentAssignmentMode, func(t *testing.T) {
			repo := &fakeAuditDispositionRepo{}
			req := withAuditDispositionUser(
				httptest.NewRequest(http.MethodPut, "/admin/v1/audit/dispositions", bytes.NewBufferString(
					`{"subject_type":"request","subject_id":"request-a","status":"resolved"}`,
				)),
				user,
			)
			recorder := httptest.NewRecorder()
			UpsertAuditDisposition(&Dependencies{AuditDispositionRepo: repo}).ServeHTTP(recorder, req)
			if recorder.Code != http.StatusForbidden || repo.last != nil {
				t.Fatalf("status=%d wrote=%v body=%s", recorder.Code, repo.last != nil, recorder.Body.String())
			}
		})
	}
}

func TestUpsertAuditDispositionReportsEnforcementFailureWithoutSuccessAudit(t *testing.T) {
	repo := &fakeAuditDispositionRepo{}
	systemRepo := &fakeDispositionSystemRepo{}
	enforcer := &fakeDispositionEnforcer{err: errors.New("execution failed")}
	req := withAuditDispositionUser(
		httptest.NewRequest(http.MethodPut, "/admin/v1/audit/dispositions", bytes.NewBufferString(
			`{"subject_type":"request","subject_id":"request-a","status":"escalated","action":"ban_user","action_target":"user-a"}`,
		)),
		&repository.User{ID: "admin-a", TenantID: "tenant-a", Role: "tenant_admin"},
	)
	recorder := httptest.NewRecorder()
	UpsertAuditDisposition(&Dependencies{
		AuditDispositionRepo: repo, SystemRepo: systemRepo, DispositionEnforcer: enforcer,
	}).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(systemRepo.ops) != 0 {
		t.Fatal("failed enforcement must not emit a success operation audit")
	}
}

func TestListAuditDispositionsUsesFullReaderContract(t *testing.T) {
	for _, tc := range []struct {
		role     string
		wantCode int
	}{
		{role: "auditor", wantCode: http.StatusOK},
		{role: "tenant_admin", wantCode: http.StatusOK},
		{role: "dept_manager", wantCode: http.StatusNotFound},
	} {
		t.Run(tc.role, func(t *testing.T) {
			req := withAuditDispositionUser(
				httptest.NewRequest(http.MethodGet, "/admin/v1/audit/dispositions", nil),
				&repository.User{ID: tc.role, TenantID: "tenant-a", Role: tc.role},
			)
			recorder := httptest.NewRecorder()
			ListAuditDispositions(&Dependencies{AuditDispositionRepo: &fakeAuditDispositionRepo{}}).ServeHTTP(recorder, req)
			if recorder.Code != tc.wantCode {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func (f *fakeDispositionSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, f.Get, keys)
}
