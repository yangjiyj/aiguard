package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	entlicense "github.com/yangjiyj/aiguard/apps/control-plane/internal/license"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type licenseUserStore struct {
	users   map[string]*repository.User
	created *repository.User
	updated *repository.User
}

func (s *licenseUserStore) GetByID(_ context.Context, id string) (*repository.User, error) {
	if s.users == nil {
		return nil, nil
	}
	return s.users[id], nil
}

func (s *licenseUserStore) ListAllWithStats(context.Context) ([]*repository.UserWithStats, error) {
	out := make([]*repository.UserWithStats, 0, len(s.users))
	for _, user := range s.users {
		out = append(out, &repository.UserWithStats{User: *user})
	}
	return out, nil
}

// Scoped store fixture follows the production SQL contract. Handler tests may
// no longer use a tenant-wide loader followed by in-memory authorization.
func (s *licenseUserStore) ListScopedWithStats(ctx context.Context,tenant string,limit,offset int)([]*repository.UserWithStats,int,error){
 rows,err:=s.ListAllWithStats(ctx);if err!=nil{return nil,0,err}
 scoped:=[]*repository.UserWithStats{}
 for _,row:=range rows {if tenant==""||row.TenantID==tenant {scoped=append(scoped,row)}}
 total:=len(scoped)
 if offset>total {offset=total}
 end:=total;if limit>0&&offset+limit<end {end=offset+limit}
 return scoped[offset:end],total,nil
}

func (s *licenseUserStore) Create(_ context.Context, user *repository.User) error {
	s.created = user
	return nil
}

func (s *licenseUserStore) Update(_ context.Context, user *repository.User) error {
	s.updated = user
	return nil
}

func TestCreateUserRejectsWhenMaxUsersReached(t *testing.T) {
	token, publicKeys := signedV2HandlerLicense(t, func(payload *entlicense.PayloadV2) {
		payload.MaxUsers = 1
	})
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", publicKeys)
	deps := &Dependencies{
		SystemRepo: &licenseSystemRepo{settings: map[string]string{LicenseSettingKey: token}},
		UserStore: &licenseUserStore{users: map[string]*repository.User{
			"active-1": {ID: "active-1", TenantID: "tenant-1", Username: "active", Status: "active"},
		}},
		LocalIdentityProvisioner: &handlerLocalIdentityProvisioner{events: &[]string{}},
		DepartmentStore: &handlerDepartmentStore{departments: map[string]*repository.Team{
			"dept-1": {ID: "dept-1", TenantID: "tenant-1", Name: "Engineering"},
		}},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/users",
		strings.NewReader(`{"username":"new-user","password":"secret123","department_id":"dept-1"}`))
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "admin-1",
		TenantID: "tenant-1",
		Role:     "platform_admin",
	}))
	w := httptest.NewRecorder()

	CreateUser(deps).ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusPaymentRequired, w.Body.String())
	}
}

func TestUpdateUserRejectsReactivationWhenMaxUsersReached(t *testing.T) {
	token, publicKeys := signedV2HandlerLicense(t, func(payload *entlicense.PayloadV2) {
		payload.MaxUsers = 1
	})
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", publicKeys)
	store := &licenseUserStore{users: map[string]*repository.User{
		"active-1": {ID: "active-1", TenantID: "tenant-1", Username: "active", Status: "active"},
		"inactive-1": {
			ID: "inactive-1", TenantID: "tenant-1", Username: "inactive", Status: "inactive",
			DepartmentAssignmentMode: "emergency",
		},
	}}
	deps := &Dependencies{
		SystemRepo: &licenseSystemRepo{settings: map[string]string{LicenseSettingKey: token}},
		UserStore:  store,
	}
	req := httptest.NewRequest(http.MethodPatch, "/admin/v1/users/inactive-1", strings.NewReader(`{"status":"active"}`))
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "admin-1",
		TenantID: "tenant-1",
		Role:     "platform_admin",
	}))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", "inactive-1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
	w := httptest.NewRecorder()

	ToggleUserStatus(deps).ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusPaymentRequired, w.Body.String())
	}
	if store.updated != nil {
		t.Fatalf("reactivation should not update user")
	}
}
