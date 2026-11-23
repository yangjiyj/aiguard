package handler

// High-1：删除用户时 Keycloak 清理失败，孤儿账号仍可凭 Keycloak 登录 Chat 门户并被 JIT 重新建成新的 chat_user。
//
// 新顺序：解析 subject → 在 Keycloak 禁用（失败则中止删除，502，库里什么都不动）→ 删 users 行 → 吊销会话 → 删除 Keycloak 用户
//（失败则进持久化重试队列，账号此时已禁用，无法登录）。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func deleteUserAs(t *testing.T, deps *Dependencies, userID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/users/"+userID, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "platform_admin_user", TenantID: "tenant_default", Role: "platform_admin", Status: "active"}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	DeleteUser(deps).ServeHTTP(rr, req)
	return rr
}

func userRowCount(t *testing.T, pool *pgxpool.Pool, tenantID, userID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE tenant_id=$1 AND id=$2`, tenantID, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// 禁用失败 => 中止删除：返回 502 + 中文提示，users 行与会话原样保留，不调用 Keycloak 删除。
func TestDeleteLocalUserAbortsWhenKeycloakDisableFails(t *testing.T) {
	pool, tenantID, userID := setupDeleteUserTestDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `UPDATE users SET department_assignment_source='local' WHERE tenant_id=$1 AND id=$2`, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_identity_links (id, tenant_id, user_id, issuer, source_id, source_type, external_subject)
		VALUES ($1,$2,$3,'local-issuer','','local','kc-subject-h1')`, "link-h1-"+userID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	client := &fakeLocalIdentityClientForDelete{setEnabledErr: localidentity.ErrUnavailable}
	prov := &cascadeAwareProvisioner{lookup: func(c context.Context, tenant, user string) (string, error) {
		var s string
		if err := pool.QueryRow(c, `SELECT external_subject FROM user_identity_links WHERE tenant_id=$1 AND user_id=$2 AND source_type='local'`, tenant, user).Scan(&s); err != nil {
			return "", localidentity.ErrNotFound
		}
		return s, nil
	}}
	sessions := &recordingSessionStore{}
	deps := &Dependencies{UserRepo: repository.NewUserRepository(pool), LocalIdentityClient: client, LocalIdentityProvisioner: prov, SessionRepo: sessions}

	rr := deleteUserAs(t, deps, userID)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("Keycloak 禁用失败应返回 502，实际 %d %s", rr.Code, rr.Body.String())
	}
	if !containsChinese(rr.Body.String()) {
		t.Fatalf("提示应为中文：%s", rr.Body.String())
	}
	if n := userRowCount(t, pool, tenantID, userID); n != 1 {
		t.Fatalf("禁用失败不得删除 users 行，实际行数 %d", n)
	}
	if len(client.deleteCalls) != 0 {
		t.Fatalf("禁用失败不得继续删除 Keycloak 用户：%v", client.deleteCalls)
	}
	if len(sessions.revoked) != 0 {
		t.Fatalf("禁用失败不得吊销会话（账号还在）：%v", sessions.revoked)
	}
}

// 入队失败 => 中止删除（High-A）：Keycloak 不被禁用，users 行与会话原样保留，返回 503 中文提示。
func TestDeleteLocalUserAbortsWhenCleanupEnqueueFails(t *testing.T) {
	pool, tenantID, userID := setupDeleteUserTestDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `UPDATE users SET department_assignment_source='local' WHERE tenant_id=$1 AND id=$2`, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_identity_links (id, tenant_id, user_id, issuer, source_id, source_type, external_subject)
		VALUES ($1,$2,$3,'local-issuer','','local','kc-subject-ha')`, "link-ha-"+userID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	client := &fakeLocalIdentityClientForDelete{}
	prov := &cascadeAwareProvisioner{lookup: func(c context.Context, tenant, user string) (string, error) {
		var s string
		if err := pool.QueryRow(c, `SELECT external_subject FROM user_identity_links WHERE tenant_id=$1 AND user_id=$2 AND source_type='local'`, tenant, user).Scan(&s); err != nil {
			return "", localidentity.ErrNotFound
		}
		return s, nil
	}}
	sessions := &recordingSessionStore{}
	queue := &memCleanupQueue{err: errors.New("db down")}
	deps := &Dependencies{UserRepo: repository.NewUserRepository(pool), LocalIdentityClient: client, LocalIdentityProvisioner: prov, SessionRepo: sessions, LocalIdentityCleanupQ: queue}

	rr := deleteUserAs(t, deps, userID)

	if rr.Code != http.StatusServiceUnavailable || !containsChinese(rr.Body.String()) {
		t.Fatalf("入队失败应返回 503 中文提示，实际 %d %s", rr.Code, rr.Body.String())
	}
	if n := userRowCount(t, pool, tenantID, userID); n != 1 {
		t.Fatalf("入队失败不得删除 users 行：%d", n)
	}
	if len(client.enabledCalls) != 0 || len(client.deleteCalls) != 0 {
		t.Fatalf("入队失败不得改动 Keycloak：enabled=%v delete=%v", client.enabledCalls, client.deleteCalls)
	}
	if len(sessions.revoked) != 0 {
		t.Fatalf("入队失败不得吊销会话：%v", sessions.revoked)
	}
}

// 正常删除：先预登记清理，同步删除 Keycloak 成功后把预登记行标记完成。
func TestDeleteLocalUserPreRegistersCleanupAndClosesItOnSyncSuccess(t *testing.T) {
	pool, tenantID, userID := setupDeleteUserTestDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `UPDATE users SET department_assignment_source='local' WHERE tenant_id=$1 AND id=$2`, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_identity_links (id, tenant_id, user_id, issuer, source_id, source_type, external_subject)
		VALUES ($1,$2,$3,'local-issuer','','local','kc-subject-ok')`, "link-ok-"+userID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	client := &fakeLocalIdentityClientForDelete{}
	prov := &cascadeAwareProvisioner{lookup: func(c context.Context, tenant, user string) (string, error) {
		var s string
		if err := pool.QueryRow(c, `SELECT external_subject FROM user_identity_links WHERE tenant_id=$1 AND user_id=$2 AND source_type='local'`, tenant, user).Scan(&s); err != nil {
			return "", localidentity.ErrNotFound
		}
		return s, nil
	}}
	queue := &memCleanupQueue{}
	deps := &Dependencies{UserRepo: repository.NewUserRepository(pool), LocalIdentityClient: client, LocalIdentityProvisioner: prov, SessionRepo: &recordingSessionStore{}, LocalIdentityCleanupQ: queue}

	rr := deleteUserAs(t, deps, userID)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("应删除成功：%d %s", rr.Code, rr.Body.String())
	}
	if len(queue.items) != 1 || queue.items[0].Subject != "kc-subject-ok" {
		t.Fatalf("删库前应预登记清理：%+v", queue.items)
	}
	if len(queue.doneSubjects) != 1 || queue.doneSubjects[0] != "kc-subject-ok" {
		t.Fatalf("同步删除成功后应关闭预登记行：%v", queue.doneSubjects)
	}
}

func containsChinese(s string) bool {
	for _, r := range s {
		if r >= 0x4e00 && r <= 0x9fff {
			return true
		}
	}
	return false
}

var _ = errors.New

// memCleanupQueue 是 localidentity.CleanupQueue 的内存桩，只记录入队的条目。
type memCleanupQueue struct {
	items        []localidentity.CleanupItem
	doneSubjects []string
	err          error
}

func (q *memCleanupQueue) Enqueue(_ context.Context, tenantID, userID, _ string, subject string, _ time.Time) error {
	if q.err != nil {
		return q.err
	}
	q.items = append(q.items, localidentity.CleanupItem{TenantID: tenantID, UserID: userID, Subject: subject, Fingerprint: localidentity.SubjectFingerprint(tenantID, subject)})
	return nil
}
func (q *memCleanupQueue) ClaimDue(context.Context, time.Time, int) ([]localidentity.CleanupItem, error) {
	return nil, nil
}
func (q *memCleanupQueue) MarkDone(context.Context, string, time.Time) error { return nil }
func (q *memCleanupQueue) MarkDoneBySubject(_ context.Context, _ string, subject string, _ time.Time) error {
	q.doneSubjects = append(q.doneSubjects, subject)
	return nil
}
func (q *memCleanupQueue) MarkRetry(context.Context, string, string, time.Time) (bool, error) {
	return false, nil
}
