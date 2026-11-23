package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeContentAuditUserSelector struct {
	filter repository.ContentAuditUserSelectorFilter
	items  []repository.ContentAuditUserOption
	more   bool
	called bool
}

func (f *fakeContentAuditUserSelector) ListContentAuditUsers(_ context.Context, filter repository.ContentAuditUserSelectorFilter) ([]repository.ContentAuditUserOption, bool, error) {
	f.called = true
	f.filter = filter
	return f.items, f.more, nil
}

type fakeContentAuditDepartmentScope struct {
	ids []string
}

func (f fakeContentAuditDepartmentScope) ListTeamSubtreeIDsByUser(context.Context, string, string) ([]string, error) {
	return f.ids, nil
}

func contentAuditUsersRequest(role, rawQuery string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/content/users?"+rawQuery, nil)
	user := &repository.User{ID: "actor-a", TenantID: "tenant-a", Role: role, DepartmentAssignmentMode: "manual"}
	ctx := context.WithValue(req.Context(), auth.UserKey, user)
	ctx = context.WithValue(ctx, auth.SessionKey, &repository.Session{UserID: user.ID, TenantID: user.TenantID})
	return req.WithContext(ctx)
}

func TestListContentAuditUsersScopesDepartmentManagerAndKeepsDuplicateNames(t *testing.T) {
	selector := &fakeContentAuditUserSelector{
		items: []repository.ContentAuditUserOption{
			{ID: "u-1", Username: "同名", IdentityKind: "key_owner", DepartmentID: "dept-a", DepartmentName: "甲部"},
			{ID: "u-2", Username: "同名", IdentityKind: "key_owner", DepartmentID: "dept-child", DepartmentName: "甲部子部门"},
		},
		more: true,
	}
	deps := &Dependencies{
		ContentAuditSelector: ContentAuditSelectorDependencies{
			Users: selector, Departments: fakeContentAuditDepartmentScope{ids: []string{"dept-a", "dept-child"}},
		},
	}
	recorder := httptest.NewRecorder()
	ListContentAuditUsers(deps).ServeHTTP(recorder, contentAuditUsersRequest("dept_manager", "q=%E5%90%8C&limit=1&offset=3"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if selector.filter.TenantID != "tenant-a" || selector.filter.Query != "同" || selector.filter.Limit != 1 || selector.filter.Offset != 3 {
		t.Fatalf("unexpected filter: %+v", selector.filter)
	}
	if !reflect.DeepEqual(selector.filter.DepartmentIDs, []string{"dept-a", "dept-child"}) {
		t.Fatalf("department scope=%v", selector.filter.DepartmentIDs)
	}
	var body struct {
		Data       []repository.ContentAuditUserOption `json:"data"`
		HasMore    bool                                `json:"has_more"`
		NextCursor string                              `json:"next_cursor"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != 2 || body.Data[0].ID == body.Data[1].ID || !body.HasMore || body.NextCursor == "" {
		t.Fatalf("unexpected selector body: %+v", body)
	}
	if body.Data[0].IdentityKind != "key_owner" || body.Data[1].IdentityKind != "key_owner" {
		t.Fatalf("unexpected selector identity kind: %+v", body.Data)
	}
}

func TestListContentAuditUsersEmptyDepartmentScopeFailsClosed(t *testing.T) {
	selector := &fakeContentAuditUserSelector{}
	deps := &Dependencies{
		ContentAuditSelector: ContentAuditSelectorDependencies{Users: selector, Departments: fakeContentAuditDepartmentScope{}},
	}
	recorder := httptest.NewRecorder()
	ListContentAuditUsers(deps).ServeHTTP(recorder, contentAuditUsersRequest("dept_manager", ""))
	if recorder.Code != http.StatusOK || selector.called {
		t.Fatalf("status=%d selector_called=%v body=%s", recorder.Code, selector.called, recorder.Body.String())
	}
}

func TestListContentAuditUsersFullTenantDoesNotAddDepartmentScope(t *testing.T) {
	selector := &fakeContentAuditUserSelector{}
	deps := &Dependencies{ContentAuditSelector: ContentAuditSelectorDependencies{Users: selector}}
	recorder := httptest.NewRecorder()
	ListContentAuditUsers(deps).ServeHTTP(recorder, contentAuditUsersRequest("tenant_admin", "limit=999"))
	if recorder.Code != http.StatusOK || !selector.called {
		t.Fatalf("status=%d called=%v body=%s", recorder.Code, selector.called, recorder.Body.String())
	}
	if selector.filter.TenantID != "tenant-a" || selector.filter.DepartmentIDs != nil || selector.filter.Limit != 100 {
		t.Fatalf("unexpected full tenant filter: %+v", selector.filter)
	}
}
