package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// fakeLocalIdentityClientForDelete 记录 SetEnabled/DeleteUser 调用，
// 供 C2 删除本地用户编排断言。
type fakeLocalIdentityClientForDelete struct {
	enabledCalls []struct {
		subject string
		enabled bool
	}
	deleteCalls   []string
	setEnabledErr error
	deleteErr     error
}

func (c *fakeLocalIdentityClientForDelete) CreateUser(context.Context, localidentity.CreateUserInput) (string, error) {
	return "", localidentity.ErrRejected
}
func (c *fakeLocalIdentityClientForDelete) SetEnabled(_ context.Context, subject string, enabled bool) error {
	c.enabledCalls = append(c.enabledCalls, struct {
		subject string
		enabled bool
	}{subject, enabled})
	return c.setEnabledErr
}
func (c *fakeLocalIdentityClientForDelete) ResetPassword(context.Context, string, string, bool) error {
	return nil
}
func (c *fakeLocalIdentityClientForDelete) DeleteUser(_ context.Context, subject string) error {
	c.deleteCalls = append(c.deleteCalls, subject)
	return c.deleteErr
}

// fakeLocalIdentityProvisionerForDelete 提供 ExternalSubject / MarkReconciliationRequired 桩。
type fakeLocalIdentityProvisionerForDelete struct {
	subject           string
	subjectErr        error
	reconciliations   []localidentity.ReconciliationInput
	reconciliationErr error
}

func (p *fakeLocalIdentityProvisionerForDelete) Provision(context.Context, localidentity.ProvisionInput) error {
	return nil
}
func (p *fakeLocalIdentityProvisionerForDelete) Activate(context.Context, string, string) error {
	return nil
}
func (p *fakeLocalIdentityProvisionerForDelete) MarkReconciliationRequired(_ context.Context, in localidentity.ReconciliationInput) error {
	p.reconciliations = append(p.reconciliations, in)
	return p.reconciliationErr
}
func (p *fakeLocalIdentityProvisionerForDelete) DeleteProvisioned(context.Context, string, string) error {
	return nil
}
func (p *fakeLocalIdentityProvisionerForDelete) ExternalSubject(context.Context, string, string) (string, error) {
	return p.subject, p.subjectErr
}
func (p *fakeLocalIdentityProvisionerForDelete) UpdatePasswordHash(context.Context, string, string, string, bool) error {
	return nil
}

// C2：删除 assignment_source=local 的活跃用户必须先编排 Keycloak 清理
// （先 best-effort SetEnabled(false) 再 DeleteUser），再删 DB。
// 旧实现只删 DB，KC subject 以 enabled=true 永久遗留，成为可登录但本地
// 已删的孤儿。
func TestDeleteLocalUserOrchestratesKeycloakCleanup(t *testing.T) {
	pool, tenantID, userID := setupDeleteUserTestDB(t)
	ctx := context.Background()
	// 标记为本地身份源用户，并插一条 user_identity_links 记录
	if _, err := pool.Exec(ctx, `
		UPDATE users SET department_assignment_source = $3
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, userID, "local"); err != nil {
		t.Fatalf("update user assignment source: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_identity_links (id, tenant_id, user_id, issuer, source_id, source_type, external_subject)
		VALUES ($1, $2, $3, 'local-issuer', 'local-source', 'local', 'kc-subject-c2')
	`, "link-c2-"+userID, tenantID, userID); err != nil {
		t.Fatalf("insert user_identity_links: %v", err)
	}

	client := &fakeLocalIdentityClientForDelete{}
	provisioner := &fakeLocalIdentityProvisionerForDelete{subject: "kc-subject-c2"}
	deps := &Dependencies{
		UserRepo:                 repository.NewUserRepository(pool),
		LocalIdentityClient:      client,
		LocalIdentityProvisioner: provisioner,
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/users/"+userID, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "platform_admin_user",
		TenantID: "tenant_default",
		Role:     "platform_admin",
		Status:   "active",
	}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	DeleteUser(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusNoContent, rr.Body.String())
	}
	// 必须先禁用再删除
	if len(client.enabledCalls) != 1 || client.enabledCalls[0].subject != "kc-subject-c2" || client.enabledCalls[0].enabled != false {
		t.Fatalf("SetEnabled 调用 = %+v, want [{kc-subject-c2 false}]", client.enabledCalls)
	}
	if len(client.deleteCalls) != 1 || client.deleteCalls[0] != "kc-subject-c2" {
		t.Fatalf("DeleteUser 调用 = %+v, want [kc-subject-c2]", client.deleteCalls)
	}
	// DB 用户行必须删除
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE tenant_id = $1 AND id = $2`, tenantID, userID).Scan(&count); err != nil {
		t.Fatalf("count user: %v", err)
	}
	if count != 0 {
		t.Fatalf("deleted user row count = %d, want 0", count)
	}
}

// C2：Keycloak 清理失败时必须标 reconciliation_required，但仍删 DB 行
// （DB 为准；KC 侧由对账 worker 后续清理）。
func TestDeleteLocalUserMarksReconciliationWhenKeycloakFails(t *testing.T) {
	// High-1 之前：禁用与删除都失败也照常 204。现在禁用失败会中止删除（见 TestDeleteLocalUserAbortsWhenKeycloakDisableFails），
	// 所以这里只模拟「禁用成功、删除失败」：账号已无法登录，DB 行照删，清理进持久化队列由 worker 重试。
	pool, tenantID, userID := setupDeleteUserTestDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		UPDATE users SET department_assignment_source = $3
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, userID, "local"); err != nil {
		t.Fatalf("update user assignment source: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_identity_links (id, tenant_id, user_id, issuer, source_id, source_type, external_subject)
		VALUES ($1, $2, $3, 'local-issuer', 'local-source', 'local', 'kc-subject-c2-fail')
	`, "link-c2-fail-"+userID, tenantID, userID); err != nil {
		t.Fatalf("insert user_identity_links: %v", err)
	}

	client := &fakeLocalIdentityClientForDelete{deleteErr: localidentity.ErrRejected}
	provisioner := &cascadeAwareProvisioner{lookup: func(c context.Context, tenant, user string) (string, error) {
		var s string
		if err := pool.QueryRow(c, `SELECT external_subject FROM user_identity_links WHERE tenant_id=$1 AND user_id=$2 AND source_type='local'`, tenant, user).Scan(&s); err != nil {
			return "", localidentity.ErrNotFound
		}
		return s, nil
	}}
	queue := &memCleanupQueue{}
	deps := &Dependencies{
		UserRepo:                 repository.NewUserRepository(pool),
		LocalIdentityClient:      client,
		LocalIdentityProvisioner: provisioner,
		LocalIdentityCleanupQ:    queue,
	}

	rr := deleteUserAs(t, deps, userID)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusNoContent, rr.Body.String())
	}
	if len(client.enabledCalls) != 1 || client.enabledCalls[0].enabled {
		t.Fatalf("删库前应先禁用一次：%+v", client.enabledCalls)
	}
	if len(client.deleteCalls) != 1 {
		t.Fatalf("DeleteUser 调用次数 = %d, want 1", len(client.deleteCalls))
	}
	// 删除失败必须进持久化重试队列（subject 在内存桩里可见，生产里是加密存储）。
	if len(queue.items) != 1 || queue.items[0].Subject != "kc-subject-c2-fail" || queue.items[0].UserID != userID {
		t.Fatalf("清理应入队：%+v", queue.items)
	}
	// 原始 KC 错误不应泄露到响应体
	body := rr.Body.String()
	if strings.Contains(body, "ErrUnavailable") || strings.Contains(body, "ErrRejected") || strings.Contains(body, "kc-subject") {
		t.Fatalf("响应体泄露内部信息: %s", body)
	}
	// DB 用户行仍必须删除（DB 为准）
	if n := userRowCount(t, pool, tenantID, userID); n != 0 {
		t.Fatalf("deleted user row count = %d, want 0（DB 为准）", n)
	}
}

// C2：非 local 用户（无 local identity subject）不应触发 Keycloak 编排，
// 直接走 DB 删除。避免对 SSO 用户误调 KC 清理。
func TestDeleteNonLocalUserSkipsKeycloakOrchestration(t *testing.T) {
	pool, tenantID, userID := setupDeleteUserTestDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		UPDATE users SET department_assignment_source = $3
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, userID, "local"); err != nil {
		t.Fatalf("update user assignment source: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_identity_links (id, tenant_id, user_id, issuer, source_id, source_type, external_subject)
		VALUES ($1, $2, $3, 'local-issuer', 'local-source', 'local', 'kc-subject-c2-dbfail')
	`, "link-c2-dbfail-"+userID, tenantID, userID); err != nil {
		t.Fatalf("insert user_identity_links: %v", err)
	}
	// 本用例把 Provisioner.ExternalSubject 返回 ErrNotFound 模拟"非 local 身份"，
	// 断言此分支完全不触发 Keycloak 编排。
	client := &fakeLocalIdentityClientForDelete{}
	provisioner := &fakeLocalIdentityProvisionerForDelete{
		subject:    "",
		subjectErr: localidentity.ErrNotFound,
	}
	deps := &Dependencies{
		UserRepo:                 repository.NewUserRepository(pool),
		LocalIdentityClient:      client,
		LocalIdentityProvisioner: provisioner,
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/users/"+userID, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "platform_admin_user",
		TenantID: "tenant_default",
		Role:     "platform_admin",
		Status:   "active",
	}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	DeleteUser(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusNoContent, rr.Body.String())
	}
	// 非 local 用户（无 subject）：KC 完全不被调用
	if len(client.enabledCalls) != 0 || len(client.deleteCalls) != 0 {
		t.Fatalf("非 local 用户不应触发 KC 操作: enabled=%+v delete=%+v", client.enabledCalls, client.deleteCalls)
	}
	// 不应标 reconciliation（无 subject，无需对账）
	if len(provisioner.reconciliations) != 0 {
		t.Fatalf("非 local 用户不应标 reconciliation: %+v", provisioner.reconciliations)
	}
}

// C2-补：assignment_source="admin"（手动管理或迁移来源）的用户删除时，
// 必须在最外层 guard 直接 return，完全不触碰 Keycloak 编排，也不标
// reconciliation。现有测试用 ErrNotFound 模拟"非 local"，覆盖的是更
// 内层分支；本用例冻结 source != "local" 的最早 return 点。
func TestDeleteAdminSourceUserSkipsKeycloakOrchestration(t *testing.T) {
	pool, tenantID, userID := setupDeleteUserTestDB(t)
	ctx := context.Background()
	// 标记为 admin 来源（非 local），命中 orchestrateLocalIdentityDeletion 最外层 guard
	if _, err := pool.Exec(ctx, `
		UPDATE users SET department_assignment_source = $3
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, userID, "admin"); err != nil {
		t.Fatalf("update user assignment source: %v", err)
	}

	client := &fakeLocalIdentityClientForDelete{}
	// 即便 provisioner 能解出 subject，guard 也应先 return 不调它
	provisioner := &fakeLocalIdentityProvisionerForDelete{subject: "should-not-be-reached"}
	deps := &Dependencies{
		UserRepo:                 repository.NewUserRepository(pool),
		LocalIdentityClient:      client,
		LocalIdentityProvisioner: provisioner,
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/users/"+userID, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "platform_admin_user",
		TenantID: "tenant_default",
		Role:     "platform_admin",
		Status:   "active",
	}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	DeleteUser(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusNoContent, rr.Body.String())
	}
	// admin 来源用户：KC 完全不被调用（guard 在 ExternalSubject 之前 return）
	if len(client.enabledCalls) != 0 || len(client.deleteCalls) != 0 {
		t.Fatalf("admin 来源用户不应触发 KC 操作: enabled=%+v delete=%+v", client.enabledCalls, client.deleteCalls)
	}
	// 不应标 reconciliation（guard 早 return，未进入编排路径）
	if len(provisioner.reconciliations) != 0 {
		t.Fatalf("admin 来源用户不应标 reconciliation: %+v", provisioner.reconciliations)
	}
	// DB 用户行必须正常删除
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE tenant_id = $1 AND id = $2`, tenantID, userID).Scan(&count); err != nil {
		t.Fatalf("count user: %v", err)
	}
	if count != 0 {
		t.Fatalf("deleted user row count = %d, want 0", count)
	}
}
