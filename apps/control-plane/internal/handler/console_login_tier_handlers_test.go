package handler

// SoD 项：登录边界（CanLoginConsole）放开三员后，handler 里「按登录档判定管理能力」的三处不得因此变宽。
// DeleteKey、UnlockUserLogin、ResetUserTOTP 过去用 CanLoginConsole 当作「管理员」判定，登录档放开会连带放开它们。
// 现改用 roles.IsConsoleAdministrator（管理员档）。这些路由在 SoD 里是 system 类，对三员本来就 Deny，
// 这里再钉一层 handler 自身的判断，防止 SoD 之外的任何路径（测试、内部调用、将来的路由）绕过。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func officerRequest(method, path, role string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "target-1")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, auth.UserKey, &repository.User{ID: "actor-1", TenantID: "tenant-a", Role: role})
	return req.WithContext(ctx)
}

func TestLoginTierDoesNotWidenAdministrativeHandlers(t *testing.T) {
	for _, role := range []string{"security_officer", "auditor"} {
		t.Run(role, func(t *testing.T) {
			deps := &Dependencies{}
			for name, h := range map[string]http.HandlerFunc{
				"unlock-login": UnlockUserLogin(deps),
				"reset-totp":   ResetUserTOTP(deps),
				"delete-key":   DeleteKey(deps),
			} {
				rec := httptest.NewRecorder()
				h(rec, officerRequest(http.MethodPost, "/x", role))
				if rec.Code != http.StatusForbidden {
					t.Fatalf("%s 对 %s 必须 403（登录放开不等于管理授权），实际 %d %s", name, role, rec.Code, rec.Body.String())
				}
			}
		})
	}
}
