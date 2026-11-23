package handler

// 控制台巡检（11-10）：本地账号的“身份托管”要看身份链接，不能看部门是谁分配的。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 本地账号被管理员挪过部门后来源变成 admin，仍可禁用/启用；先前直接回 409 “由外部身份源管理”。
func TestToggleUserStatusAllowsLocalAccountWhoseDepartmentWasAssignedByAdmin(t *testing.T) {
	events := []string{}
	deps := lifecycleDependencies(&events, &lifecycleIdentityClient{events: &events})
	deps.UserStore.(*lifecycleUserStore).user.DepartmentAssignmentSource = "admin"
	deps.UserIdentityLinkLookup = ownershipLinkLookup{local: true, nativeSubject: "subject-sensitive"}

	w := httptest.NewRecorder()
	ToggleUserStatus(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"status":"disabled"}`))

	if w.Code != http.StatusOK || strings.Join(events, ",") != "keycloak.disable,sessions.revoke,database.status.disabled" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
}

// 目录/SSO 同步来的账号（没有本地身份链接）仍由外部身份源管状态。
func TestToggleUserStatusStillRejectsAccountWithoutLocalIdentityLink(t *testing.T) {
	events := []string{}
	deps := lifecycleDependencies(&events, &lifecycleIdentityClient{events: &events})
	deps.UserStore.(*lifecycleUserStore).user.DepartmentAssignmentSource = "admin"
	deps.UserIdentityLinkLookup = ownershipLinkLookup{local: false}

	w := httptest.NewRecorder()
	ToggleUserStatus(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"status":"disabled"}`))

	if w.Code != http.StatusConflict || decodeErrorCode(t, w.Body.String()) != "identity_managed_externally" || len(events) != 0 {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
}
