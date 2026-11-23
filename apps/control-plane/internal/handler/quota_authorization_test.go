package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type quotaDepartmentScopeStub struct {
	teams    []string
	projects []string
}

func (s *quotaDepartmentScopeStub) ListTeamSubtreeIDsByUser(context.Context, string, string) ([]string, error) {
	return s.teams, nil
}

func (s *quotaDepartmentScopeStub) ListProjectIDsByUserTeams(context.Context, string, string) ([]string, error) {
	return s.projects, nil
}

type quotaUserLookupStub struct {
	user *repository.User
}

func (s *quotaUserLookupStub) GetByID(context.Context, string) (*repository.User, error) {
	return s.user, nil
}

type quotaTeamLookupStub struct {
	team *repository.Team
}

func (s *quotaTeamLookupStub) GetByID(context.Context, string) (*repository.Team, error) {
	return s.team, nil
}

type quotaProjectMembershipStub struct {
	role string
}

func (s *quotaProjectMembershipStub) GetUserRole(context.Context, string, string) (string, error) {
	return s.role, nil
}

func quotaActorCtx(req *http.Request, id, role string) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       id,
		TenantID: "tenant_default",
		Role:     role,
		Status:   "active",
	}))
}

func TestQuotaScopeAuthorizationPreventsCrossObjectWrites(t *testing.T) {
	tests := []struct {
		name       string
		role       string
		body       string
		project    *repository.Project
		team       *repository.Team
		keyLookup  QuotaKeyLookup
		department QuotaDepartmentScopeLookup
		membership QuotaProjectMembershipLookup
		wantStatus int
	}{
		{
			name:       "project owner owns project",
			role:       "project_owner",
			body:       `{"scope_type":"project","scope_id":"project-own"}`,
			project:    &repository.Project{ID: "project-own", TenantID: "tenant_default", OwnerUserID: "actor"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "project owner cannot write another project",
			role:       "project_owner",
			body:       `{"scope_type":"project","scope_id":"project-other"}`,
			project:    &repository.Project{ID: "project-other", TenantID: "tenant_default", OwnerUserID: "someone-else"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "global project owner cannot write project with viewer membership",
			role:       "project_owner",
			body:       `{"scope_type":"project","scope_id":"project-viewer"}`,
			project:    &repository.Project{ID: "project-viewer", TenantID: "tenant_default", OwnerUserID: "someone-else"},
			membership: &quotaProjectMembershipStub{role: "viewer"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:    "project owner cannot write key from another project",
			role:    "project_owner",
			body:    `{"scope_type":"key","scope_id":"key-other"}`,
			project: &repository.Project{ID: "project-other", TenantID: "tenant_default", OwnerUserID: "someone-else"},
			keyLookup: &fakeQuotaKeyLookup{keys: map[string]*repository.InternalKey{
				"tenant_default|key-other": {ID: "key-other", TenantID: "tenant_default", ProjectID: "project-other", KeyPrefix: "sk-other"},
			}},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "department manager is read only",
			role:       "dept_manager",
			body:       `{"scope_type":"team","scope_id":"team-own"}`,
			team:       &repository.Team{ID: "team-own", TenantID: "tenant_default"},
			department: &quotaDepartmentScopeStub{teams: []string{"team-own"}},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "ordinary role cannot write tenant policy",
			role:       "viewer",
			body:       `{"scope_type":"tenant"}`,
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			quotaRepo := &fakeQuotaPolicyRepo{}
			deps := &Dependencies{
				SystemRepo:                   &quotaAuditSystemRepo{},
				QuotaPolicyRepo:              quotaRepo,
				ProjectRepo:                  &fakeProjectRepo{project: tc.project},
				DepartmentStore:              &quotaTeamLookupStub{team: tc.team},
				QuotaKeyLookup:               tc.keyLookup,
				QuotaDepartmentScopeLookup:   tc.department,
				QuotaProjectMembershipLookup: tc.membership,
			}
			recorder := httptest.NewRecorder()
			request := quotaActorCtx(
				httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", bytes.NewBufferString(tc.body)),
				"actor",
				tc.role,
			)
			SetQuotaPolicy(deps).ServeHTTP(recorder, request)

			if recorder.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, tc.wantStatus, recorder.Body.String())
			}
			if tc.wantStatus == http.StatusOK && quotaRepo.saved == nil {
				t.Fatal("authorized quota policy was not saved")
			}
			if tc.wantStatus != http.StatusOK && quotaRepo.saved != nil {
				t.Fatalf("unauthorized quota policy persisted: %+v", quotaRepo.saved)
			}
		})
	}
}

func TestFullTenantAdminCannotUseCrossTenantTeamOrUserScope(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		scopeType string
		scopeID   string
		deps      *Dependencies
	}{
		{
			name:      "get cross tenant team",
			method:    http.MethodGet,
			scopeType: "team",
			scopeID:   "team-other",
			deps:      &Dependencies{DepartmentStore: &quotaTeamLookupStub{team: &repository.Team{ID: "team-other", TenantID: "tenant-other"}}},
		},
		{
			name:      "put cross tenant team",
			method:    http.MethodPut,
			scopeType: "team",
			scopeID:   "team-other",
			deps:      &Dependencies{DepartmentStore: &quotaTeamLookupStub{team: &repository.Team{ID: "team-other", TenantID: "tenant-other"}}},
		},
		{
			name:      "get cross tenant user",
			method:    http.MethodGet,
			scopeType: "user",
			scopeID:   "user-other",
			deps:      &Dependencies{QuotaUserLookup: &quotaUserLookupStub{user: &repository.User{ID: "user-other", TenantID: "tenant-other"}}},
		},
		{
			name:      "put cross tenant user",
			method:    http.MethodPut,
			scopeType: "user",
			scopeID:   "user-other",
			deps:      &Dependencies{QuotaUserLookup: &quotaUserLookupStub{user: &repository.User{ID: "user-other", TenantID: "tenant-other"}}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			quotaRepo := &fakeQuotaPolicyRepo{}
			tc.deps.SystemRepo = &quotaAuditSystemRepo{}
			tc.deps.QuotaPolicyRepo = quotaRepo
			var request *http.Request
			if tc.method == http.MethodGet {
				request = httptest.NewRequest(tc.method, "/admin/v1/policies/quota?scope_type="+tc.scopeType+"&scope_id="+tc.scopeID, nil)
			} else {
				body := `{"scope_type":"` + tc.scopeType + `","scope_id":"` + tc.scopeID + `"}`
				request = httptest.NewRequest(tc.method, "/admin/v1/policies/quota", bytes.NewBufferString(body))
			}
			recorder := httptest.NewRecorder()
			if tc.method == http.MethodGet {
				GetQuotaPolicy(tc.deps).ServeHTTP(recorder, adminCtx(request))
			} else {
				SetQuotaPolicy(tc.deps).ServeHTTP(recorder, adminCtx(request))
			}
			if recorder.Code != http.StatusNotFound {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, http.StatusNotFound, recorder.Body.String())
			}
			if quotaRepo.saved != nil || quotaRepo.scopeCalledType != "" {
				t.Fatalf("cross-tenant scope reached repository: %+v", quotaRepo)
			}
		})
	}
}

func TestAuditorQuotaAccessIsReadOnlyAndDepartmentBound(t *testing.T) {
	department := &quotaDepartmentScopeStub{projects: []string{"project-own"}}
	project := &repository.Project{ID: "project-own", TenantID: "tenant_default"}
	deps := &Dependencies{
		SystemRepo:                 &quotaAuditSystemRepo{},
		QuotaPolicyRepo:            &fakeQuotaPolicyRepo{},
		ProjectRepo:                &fakeProjectRepo{project: project},
		QuotaDepartmentScopeLookup: department,
	}

	getRecorder := httptest.NewRecorder()
	GetQuotaPolicy(deps).ServeHTTP(
		getRecorder,
		quotaActorCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/policies/quota?scope_type=project&scope_id=project-own", nil), "auditor", "auditor"),
	)
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("auditor scoped read status=%d body=%s", getRecorder.Code, getRecorder.Body.String())
	}

	putRecorder := httptest.NewRecorder()
	SetQuotaPolicy(deps).ServeHTTP(
		putRecorder,
		quotaActorCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", bytes.NewBufferString(`{"scope_type":"project","scope_id":"project-own"}`)), "auditor", "auditor"),
	)
	if putRecorder.Code != http.StatusForbidden {
		t.Fatalf("auditor write status=%d body=%s", putRecorder.Code, putRecorder.Body.String())
	}
}

func TestDepartmentManagerQuotaReadsStayInDepartmentTree(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		project    *repository.Project
		team       *repository.Team
		department *quotaDepartmentScopeStub
		targetUser *repository.User
		wantStatus int
	}{
		{
			name:       "own descendant project",
			url:        "/admin/v1/policies/quota?scope_type=project&scope_id=project-child",
			project:    &repository.Project{ID: "project-child", TenantID: "tenant_default"},
			department: &quotaDepartmentScopeStub{projects: []string{"project-child"}},
			wantStatus: http.StatusOK,
		},
		{
			name:       "other project",
			url:        "/admin/v1/policies/quota?scope_type=project&scope_id=project-other",
			project:    &repository.Project{ID: "project-other", TenantID: "tenant_default"},
			department: &quotaDepartmentScopeStub{projects: []string{"project-child"}},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "own descendant team",
			url:        "/admin/v1/policies/quota?scope_type=team&scope_id=team-child",
			team:       &repository.Team{ID: "team-child", TenantID: "tenant_default"},
			department: &quotaDepartmentScopeStub{teams: []string{"team-root", "team-child"}},
			wantStatus: http.StatusOK,
		},
		{
			name:       "other team",
			url:        "/admin/v1/policies/quota?scope_type=team&scope_id=team-other",
			team:       &repository.Team{ID: "team-other", TenantID: "tenant_default"},
			department: &quotaDepartmentScopeStub{teams: []string{"team-root", "team-child"}},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "user in descendant team",
			url:        "/admin/v1/policies/quota?scope_type=user&scope_id=user-child",
			department: &quotaDepartmentScopeStub{teams: []string{"team-root", "team-child"}},
			targetUser: &repository.User{ID: "user-child", TenantID: "tenant_default", DepartmentID: "team-child"},
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := &Dependencies{
				QuotaPolicyRepo:            &fakeQuotaPolicyRepo{},
				ProjectRepo:                &fakeProjectRepo{project: tc.project},
				DepartmentStore:            &quotaTeamLookupStub{team: tc.team},
				QuotaDepartmentScopeLookup: tc.department,
				QuotaUserLookup:            &quotaUserLookupStub{user: tc.targetUser},
			}
			recorder := httptest.NewRecorder()
			request := quotaActorCtx(httptest.NewRequest(http.MethodGet, tc.url, nil), "manager", "dept_manager")
			GetQuotaPolicy(deps).ServeHTTP(recorder, request)
			if recorder.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, tc.wantStatus, recorder.Body.String())
			}
		})
	}
}
