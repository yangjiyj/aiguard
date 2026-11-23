package handler

// N1：删除用户后同名账号无法重建（409 用户名已被占用）。
//
// 根因：DeleteUser 先删 users 行、再按 user_identity_links 查 Keycloak subject 做清理；而 user_identity_links 对 users
// 是 ON DELETE CASCADE（137_enterprise_identity_department.sql），users 一删 link 就没了，随后 ExternalSubject 必然
// ErrNotFound，orchestrateLocalIdentityDeletion 静默 return，Keycloak 用户从未被禁用或删除。
// 再建同名账号时 Keycloak 返回 409，被 writeLocalIdentityError 译成「用户名已被占用」。
//
// 这个测试用真实 Postgres 的外键级联复现：用只认 subject 的桩 Keycloak 客户端，断言删除用户后 Keycloak 收到了
// SetEnabled(false) 与 DeleteUser。旧实现下两个调用都是 0 次。

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// cascadeAwareProvisioner 与生产的 PostgresProvisioner.ExternalSubject 一样去查 user_identity_links，
// 因此能暴露「users 先删、link 被级联删光」的问题（原有 C2 测试用的桩直接返回固定 subject，永远测不到这一点）。
type cascadeAwareProvisioner struct {
	fakeLocalIdentityProvisionerForDelete
	lookup func(ctx context.Context, tenantID, userID string) (string, error)
}

func (p *cascadeAwareProvisioner) ExternalSubject(ctx context.Context, tenantID, userID string) (string, error) {
	return p.lookup(ctx, tenantID, userID)
}

func TestDeleteLocalUserCleansKeycloakEvenThoughIdentityLinkCascadesAway(t *testing.T) {
	pool, tenantID, userID := setupDeleteUserTestDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `UPDATE users SET department_assignment_source='local' WHERE tenant_id=$1 AND id=$2`, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_identity_links (id, tenant_id, user_id, issuer, source_id, source_type, external_subject)
		VALUES ($1,$2,$3,'local-issuer','','local','kc-subject-n1')`, "link-n1-"+userID, tenantID, userID); err != nil {
		t.Fatal(err)
	}

	client := &fakeLocalIdentityClientForDelete{}
	prov := &cascadeAwareProvisioner{lookup: func(ctx context.Context, tenant, user string) (string, error) {
		var subject string
		err := pool.QueryRow(ctx, `SELECT external_subject FROM user_identity_links WHERE tenant_id=$1 AND user_id=$2 AND source_type='local'`, tenant, user).Scan(&subject)
		if err != nil {
			return "", localidentity.ErrNotFound
		}
		return subject, nil
	}}
	deps := &Dependencies{UserRepo: repository.NewUserRepository(pool), LocalIdentityClient: client, LocalIdentityProvisioner: prov}

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/users/"+userID, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "platform_admin_user", TenantID: "tenant_default", Role: "platform_admin", Status: "active"}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	DeleteUser(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(client.deleteCalls) != 1 || client.deleteCalls[0] != "kc-subject-n1" {
		t.Fatalf("Keycloak 用户没有被删除（link 被级联删光后查不到 subject）：deleteCalls=%v enabledCalls=%v", client.deleteCalls, client.enabledCalls)
	}
	if len(client.enabledCalls) != 1 || client.enabledCalls[0].enabled {
		t.Fatalf("删除前应先禁用 Keycloak 用户：%+v", client.enabledCalls)
	}
}

// 删库前解析 subject 失败（既不是「非本地身份」，也没解析出来）：无法确认 Keycloak 里有没有可登录的用户，
// 不能带着未知状态删库——中止删除，返回 502，库里什么都不动（High-1：先保证不会留下可登录的孤儿）。
func TestDeleteLocalUserAbortsWhenSubjectCannotBeResolvedBeforeDelete(t *testing.T) {
	pool, tenantID, userID := setupDeleteUserTestDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `UPDATE users SET department_assignment_source='local' WHERE tenant_id=$1 AND id=$2`, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	client := &fakeLocalIdentityClientForDelete{}
	prov := &cascadeAwareProvisioner{lookup: func(context.Context, string, string) (string, error) {
		return "", localidentity.ErrUnavailable
	}}
	deps := &Dependencies{UserRepo: repository.NewUserRepository(pool), LocalIdentityClient: client, LocalIdentityProvisioner: prov}

	rr := deleteUserAs(t, deps, userID)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("subject 解析失败应中止删除并返回 502：status=%d body=%s", rr.Code, rr.Body.String())
	}
	if n := userRowCount(t, pool, tenantID, userID); n != 1 {
		t.Fatalf("中止删除时 users 行必须保留，实际 %d", n)
	}
	if len(client.deleteCalls) != 0 || len(client.enabledCalls) != 0 {
		t.Fatalf("没有 subject 不应调用 Keycloak：enabled=%v delete=%v", client.enabledCalls, client.deleteCalls)
	}
}

// 删除用户是高风险管理操作，必须留下操作审计（谁删了谁、Keycloak 清理是否走了对账）。
// 审计详情不得包含 Keycloak subject 原文。
func TestDeleteUserWritesOperationAudit(t *testing.T) {
	pool, tenantID, userID := setupDeleteUserTestDB(t)
	sys := &capturingSystemRepo{}
	deps := &Dependencies{UserRepo: repository.NewUserRepository(pool), SystemRepo: sys}

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/users/"+userID, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "platform_admin_user", TenantID: "tenant_default", Role: "platform_admin", Status: "active"}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	DeleteUser(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(sys.auditOps) != 1 {
		t.Fatalf("删除用户应写一条操作审计，实际 %d 条", len(sys.auditOps))
	}
	op := sys.auditOps[0]
	if op.ActionType != "user.delete" || op.TargetType != "user" || op.TargetID != userID || op.UserID != "platform_admin_user" {
		t.Fatalf("审计内容不对：%+v", op)
	}
	if op.ActionDetail["tenant_id"] != tenantID || op.ActionDetail["username"] != "delete_me" {
		t.Fatalf("审计应记录被删账号的租户与用户名（账号已不存在，事后只能靠审计追溯）：%v", op.ActionDetail)
	}
	if strings.Contains(fmt.Sprint(op.ActionDetail), "kc-subject") {
		t.Fatalf("审计不得含 Keycloak subject：%v", op.ActionDetail)
	}
}
