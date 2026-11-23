package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type failingSessionReader struct{}

func (failingSessionReader) Get(context.Context, string) (*repository.Session, error) {
	return nil, errors.New("redis: i/o timeout")
}
func (failingSessionReader) Extend(context.Context, string) error { return nil }

type failingUserReader struct{}

func (failingUserReader) GetByID(context.Context, string) (*repository.User, error) {
	return nil, errors.New("failed to get user: sorry, too many clients already")
}

// 客户现场回归：磁盘抖动时 Redis/PostgreSQL 暂时查不动，原实现一律返回 401，
// 前端收到 401 就登出，管理员被成批踢回登录页。会话存储故障必须返回 503（可重试），
// 只有会话确实不存在/过期/用户不存在时才是 401。
func TestMiddlewareStoreFailureIsServiceUnavailableNotUnauthorized(t *testing.T) {
	session := &repository.Session{ID: "s1", UserID: "u1", TenantID: "t1", Role: "tenant_admin"}
	cases := []struct {
		name     string
		sessions sessionReader
		users    userReader
		want     int
	}{
		{"会话存储故障", failingSessionReader{}, fakeUserReader{}, http.StatusServiceUnavailable},
		{"用户库故障", fakeSessionReader{session: session}, failingUserReader{}, http.StatusServiceUnavailable},
		{"会话不存在仍是 401", fakeSessionReader{}, fakeUserReader{}, http.StatusUnauthorized},
		{"用户不存在仍是 401", fakeSessionReader{session: session}, fakeUserReader{}, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
			req := httptest.NewRequest(http.MethodGet, "/admin/v1/stats/overview", nil)
			req.Header.Set("Authorization", "Bearer s1")
			rec := httptest.NewRecorder()
			Middleware(tc.sessions, tc.users)(next).ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want %d body=%s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == http.StatusServiceUnavailable && rec.Header().Get("Retry-After") == "" {
				t.Fatal("503 应带 Retry-After，提示前端稍后重试")
			}
		})
	}
}
