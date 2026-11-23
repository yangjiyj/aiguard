package handler

// 控制台巡检（11-10）：单机模式（没有 Keycloak）的本地账号删除不能去调 Keycloak 客户端。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 在 lifecycleIdentityLinkLookup 上补上“本地密码归属”查询（身份链接是否存在、是否由运行时托管）。
type ownershipLinkLookup struct {
	lifecycleIdentityLinkLookup
	local         bool
	nativeSubject string
}

func (l ownershipLinkLookup) LocalPasswordOwnership(context.Context, string, string) (bool, string, error) {
	return l.local, l.nativeSubject, l.err
}

// 单机模式：账号的凭据只在控制面里，没有 Keycloak 账号。删除用户不能去调 Keycloak 客户端
// （那是个 nil 指针，调用即 panic，页面上表现为删除任何用户都返回空的 500）。
func TestPlanLocalIdentityDeletionSkipsStandaloneCredential(t *testing.T) {
	events := []string{}
	deps := lifecycleDependencies(&events, nil)
	deps.UserIdentityLinkLookup = ownershipLinkLookup{local: true, nativeSubject: ""}
	user := &repository.User{ID: "user-1", TenantID: "tenant-1", DepartmentAssignmentSource: "local"}

	plan := planLocalIdentityDeletion(httptest.NewRequest(http.MethodDelete, "/admin/v1/users/user-1", nil), deps, user)

	if plan.subject != "" || plan.unresolved {
		t.Fatalf("单机本地账号不应有 Keycloak 清理计划: %+v", plan)
	}
}

// Keycloak 托管的本地账号照旧要先解析 subject（删库后链接就查不到了）。
func TestPlanLocalIdentityDeletionKeepsKeycloakSubjectForRuntimeManagedAccount(t *testing.T) {
	events := []string{}
	deps := lifecycleDependencies(&events, &lifecycleIdentityClient{events: &events})
	deps.UserIdentityLinkLookup = ownershipLinkLookup{local: true, nativeSubject: "subject-sensitive"}
	user := &repository.User{ID: "user-1", TenantID: "tenant-1", DepartmentAssignmentSource: "local"}

	plan := planLocalIdentityDeletion(httptest.NewRequest(http.MethodDelete, "/admin/v1/users/user-1", nil), deps, user)

	if plan.subject != "subject-sensitive" || plan.unresolved {
		t.Fatalf("plan=%+v", plan)
	}
}

// 归属查询失败时不能带着未知状态删库。
func TestPlanLocalIdentityDeletionIsUnresolvedWhenOwnershipLookupFails(t *testing.T) {
	events := []string{}
	deps := lifecycleDependencies(&events, &lifecycleIdentityClient{events: &events})
	deps.UserIdentityLinkLookup = ownershipLinkLookup{lifecycleIdentityLinkLookup: lifecycleIdentityLinkLookup{err: localidentity.ErrUnavailable}}
	user := &repository.User{ID: "user-1", TenantID: "tenant-1", DepartmentAssignmentSource: "local"}

	plan := planLocalIdentityDeletion(httptest.NewRequest(http.MethodDelete, "/admin/v1/users/user-1", nil), deps, user)

	if !plan.unresolved {
		t.Fatalf("plan=%+v", plan)
	}
}
