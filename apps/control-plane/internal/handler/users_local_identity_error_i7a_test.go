package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// writeLocalIdentityError 把 Keycloak 客户端错误映射到稳定的 HTTP 状态码，
// 让客户端能区分"用户名冲突"(409)、"Keycloak 未授权"(502 unauthorized)、
// "Keycloak 不可达"(502 unavailable) 等语义，而非全部坍缩成 502 sync_failed。
// 不泄露原始错误细节、subject、DSN 或 secret。
func TestWriteLocalIdentityErrorMapsConflictTo409(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "conflict maps to 409 username_conflict",
			err:        localidentity.ErrConflict,
			wantStatus: http.StatusConflict,
			wantCode:   "username_conflict",
		},
		{
			name:       "unauthorized maps to 502 local_identity_unauthorized",
			err:        localidentity.ErrUnauthorized,
			wantStatus: http.StatusBadGateway,
			wantCode:   "local_identity_unauthorized",
		},
		{
			name:       "unavailable maps to 502 local_identity_unavailable",
			err:        localidentity.ErrUnavailable,
			wantStatus: http.StatusBadGateway,
			wantCode:   "local_identity_unavailable",
		},
		{
			name:       "rejected falls back to 502 local_identity_sync_failed",
			err:        localidentity.ErrRejected,
			wantStatus: http.StatusBadGateway,
			wantCode:   "local_identity_sync_failed",
		},
		{
			name:       "not found maps to 502 local_identity_not_found",
			err:        localidentity.ErrNotFound,
			wantStatus: http.StatusBadGateway,
			wantCode:   "local_identity_not_found",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeLocalIdentityError(w, tc.err, "local_identity_sync_failed", "fallback message")
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			if code := decodeErrorCode(t, w.Body.String()); code != tc.wantCode {
				t.Fatalf("error.code = %q, want %q; body=%s", code, tc.wantCode, w.Body.String())
			}
		})
	}
}

// I7a 集成测试：CreateUser(KC) 返回 ErrConflict 时，createManagedUser
// 必须返 409 username_conflict（而非 502 local_identity_sync_failed），
// 让客户端能区分"用户名冲突"和"Keycloak 挂了"。
func TestCreateManagedUserReturnsConflictOnKeycloak409(t *testing.T) {
	events := []string{}
	client := &handlerLocalIdentityClient{
		events:    &events,
		createErr: localidentity.ErrConflict,
	}
	provisioner := &handlerLocalIdentityProvisioner{events: &events}
	deps := &Dependencies{
		LocalIdentityClient:      client,
		LocalIdentityProvisioner: provisioner,
		DepartmentStore: &handlerDepartmentStore{departments: map[string]*repository.Team{
			"dept-1": {ID: "dept-1", TenantID: "tenant-1", Name: "Engineering"},
		}},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/users",
		strings.NewReader(`{"username":"alice","password":"secret123","department_id":"dept-1"}`))
	req = platformAdminContext(req)
	w := httptest.NewRecorder()
	CreateUser(deps).ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	if code := decodeErrorCode(t, w.Body.String()); code != "username_conflict" {
		t.Fatalf("error.code = %q, want username_conflict; body=%s", code, w.Body.String())
	}
	// 不应泄露原始错误细节
	body := w.Body.String()
	if strings.Contains(body, "ErrConflict") || strings.Contains(body, "user conflict") {
		t.Fatalf("响应体泄露内部错误: %s", body)
	}
}
