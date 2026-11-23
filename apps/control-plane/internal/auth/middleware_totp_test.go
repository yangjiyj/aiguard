package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// W3 3.5：管理员被要求启用双因素但尚未绑定时，会话只能访问绑定相关接口。
func TestMiddlewareRestrictsTOTPEnrollmentSession(t *testing.T) {
	session := &repository.Session{ID: "s", UserID: "u", Role: "platform_admin", TOTPSetupPending: true}
	user := &repository.User{ID: "u", Role: "platform_admin", Status: "active"}
	cases := map[string]int{
		"/admin/v1/users":           http.StatusForbidden,
		"/admin/v1/system/settings": http.StatusForbidden,
		"/admin/v1/me":              http.StatusNoContent,
		"/admin/v1/me/totp/setup":   http.StatusNoContent,
		"/admin/v1/me/totp/enable":  http.StatusNoContent,
		"/admin/v1/logout":          http.StatusNoContent,
	}
	for path, want := range cases {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer s")
		rec := httptest.NewRecorder()
		Middleware(fakeSessionReader{session: session}, fakeUserReader{user: user})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s: expected %d, got %d: %s", path, want, rec.Code, rec.Body.String())
		}
	}
}
