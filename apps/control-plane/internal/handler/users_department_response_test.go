package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

type departmentAssignmentService struct {
	tenantID     string
	userID       string
	departmentID string
	actorID      string
}

func (*departmentAssignmentService) BindAndResolve(context.Context, identitybinding.ExternalIdentity) (identitybinding.Resolution, error) {
	return identitybinding.Resolution{}, nil
}
func (s *departmentAssignmentService) AssignManually(_ context.Context, tenantID, userID, departmentID, actorID string) error {
	s.tenantID, s.userID, s.departmentID, s.actorID = tenantID, userID, departmentID, actorID
	return nil
}
func (*departmentAssignmentService) AssignManyManually(context.Context, string, []string, string, string, string) error {
	return nil
}
func (*departmentAssignmentService) SetAutomatic(context.Context, string, string, string) error {
	return nil
}
func (*departmentAssignmentService) Unassign(context.Context, string, string, string) error {
	return nil
}

func TestListUsersIncludesDepartmentNameWithoutExternalSubject(t *testing.T) {
	store := &licenseUserStore{users: map[string]*repository.User{
		"user-1": {
			ID: "user-1", TenantID: "tenant-1", Username: "alice", Role: "viewer", Status: "active",
			DepartmentID: "dept-1", DepartmentName: "Engineering", ExternalSubject: "subject-sensitive",
		},
	}}
	w := httptest.NewRecorder()
	ListUsers(&Dependencies{UserStore: store}).ServeHTTP(w,
		platformAdminContext(httptest.NewRequest(http.MethodGet, "/admin/v1/users", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response types.UserListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Data) != 1 || response.Data[0].DepartmentID != "dept-1" ||
		response.Data[0].DepartmentName != "Engineering" {
		t.Fatalf("response=%+v", response)
	}
	if strings.Contains(w.Body.String(), "subject-sensitive") ||
		strings.Contains(w.Body.String(), "external_subject") {
		t.Fatalf("response leaked stable subject: %s", w.Body.String())
	}
}

func TestUpdateUserAssignsSameTenantDepartmentAndReturnsName(t *testing.T) {
	events := []string{}
	store := &lifecycleUserStore{events: &events, user: &repository.User{
		ID: "user-1", TenantID: "tenant-1", Username: "alice", Role: "viewer", Status: "active",
		DepartmentID: "dept-1", DepartmentName: "Old", DepartmentAssignmentMode: "manual",
		DepartmentAssignmentSource: "local",
	}}
	assignments := &departmentAssignmentService{}
	deps := &Dependencies{
		UserStore: store, IdentityBindingService: assignments,
		DepartmentStore: &handlerDepartmentStore{departments: map[string]*repository.Team{
			"dept-2": {ID: "dept-2", TenantID: "tenant-1", Name: "Research"},
		}},
	}
	w := httptest.NewRecorder()
	UpdateUser(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"department_id":"dept-2"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if assignments.tenantID != "tenant-1" || assignments.userID != "user-1" ||
		assignments.departmentID != "dept-2" || assignments.actorID != "admin-1" {
		t.Fatalf("assignment=%+v", assignments)
	}
	if !strings.Contains(w.Body.String(), `"department_name":"Research"`) {
		t.Fatalf("department name missing: %s", w.Body.String())
	}
}

func TestUpdateUserHidesCrossTenantDepartment(t *testing.T) {
	events := []string{}
	store := &lifecycleUserStore{events: &events, user: &repository.User{
		ID: "user-1", TenantID: "tenant-1", Username: "alice", Role: "viewer", Status: "active",
		DepartmentID: "dept-1", DepartmentName: "Old", DepartmentAssignmentMode: "manual",
		DepartmentAssignmentSource: "local",
	}}
	assignments := &departmentAssignmentService{}
	deps := &Dependencies{
		UserStore: store, IdentityBindingService: assignments,
		DepartmentStore: &handlerDepartmentStore{departments: map[string]*repository.Team{
			"dept-other": {ID: "dept-other", TenantID: "tenant-other", Name: "Other tenant"},
		}},
	}
	w := httptest.NewRecorder()
	UpdateUser(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"department_id":"dept-other"}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if assignments.departmentID != "" {
		t.Fatalf("cross-tenant department assigned: %+v", assignments)
	}
	if len(events) != 0 {
		t.Fatalf("side effects before tenant validation: %v", events)
	}
}

func TestUpdateUserRejectsStatusOutsideLifecycleEndpoint(t *testing.T) {
	events := []string{}
	store := &lifecycleUserStore{events: &events, user: &repository.User{
		ID: "user-1", TenantID: "tenant-1", Username: "alice", Role: "viewer", Status: "disabled",
		DepartmentAssignmentMode: "manual", DepartmentAssignmentSource: "local",
	}}
	w := httptest.NewRecorder()
	UpdateUser(&Dependencies{UserStore: store}).ServeHTTP(w,
		lifecycleRequest(http.MethodPatch, `{"status":"active"}`))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "status_endpoint_required") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(events) != 0 {
		t.Fatalf("status update bypassed lifecycle orchestration: %v", events)
	}
}
