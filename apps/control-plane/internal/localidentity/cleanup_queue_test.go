package localidentity

// High-1：删除用户后的 Keycloak 孤儿清理。覆盖：
//   - MarkReconciliationRequired 在 users 行已删除时，审计里 user_id 不能是 NULL（原缺陷：子查询命中 0 行）；
//   - 持久化重试队列：入队加密存储、重复入队合并、到期领取、指数退避；
//   - CleanupWorker：重试成功、重试到上限置 exhausted 并触发告警回调、不泄露 subject 明文。
// 需要真实 Postgres（setupProvisionerDB 已有约定，没配置时跳过）。

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// 原缺陷：audit_operations.user_id 取 (SELECT id FROM users WHERE ... AND id=<ActorID>)——当执行人账号在库里查不到时命中 0 行，
// user_id 变成 NULL，审计里只剩 target_id；而删除用户流程里被操作的用户恰好已经被删。
// 事后既不知道是谁删的，也看不到该对账项属于哪个用户的哪个 subject。
// 修复：user_id 列保持外键语义（存在才写），但无论如何都在 action_detail 里记下被操作用户与执行人的原值，加上 subject 指纹。
func TestMarkReconciliationKeepsTheOriginalIdentifiersWhenTheUserRowsAreGone(t *testing.T) {
	db, tenantID, _, _ := setupProvisionerDB(t)
	ctx := context.Background()
	p, err := NewProvisioner(db, "https://sso.example.test/sso/realms/jjdguard")
	if err != nil {
		t.Fatal(err)
	}
	deletedUserID := "deleted_user_" + tenantID[len(tenantID)-12:]
	goneActorID := "gone_actor_" + tenantID[len(tenantID)-12:] // 执行人在库里也查不到
	fp := SubjectFingerprint(tenantID, "kc-subject-deleted")

	if err := p.MarkReconciliationRequired(ctx, ReconciliationInput{
		ID: "reconcile_deleted_" + tenantID[len(tenantID)-12:], TenantID: tenantID,
		UserID: deletedUserID, ActorID: goneActorID, Reason: "delete_user_keycloak_cleanup_failed",
		SubjectFingerprint: fp, Operation: "delete_user", Stage: "delete_user_keycloak_cleanup_failed",
		Provider: "keycloak", Source: "local",
	}); err != nil {
		t.Fatalf("users 行不存在时仍应能记录对账标记：%v", err)
	}

	var target, detail string
	var userCol *string
	if err := db.QueryRow(ctx, `
		SELECT target_id, user_id, action_detail::text FROM audit_operations
		WHERE tenant_id=$1 AND target_id=$2 AND action_type='local_identity.reconciliation_required'
	`, tenantID, deletedUserID).Scan(&target, &userCol, &detail); err != nil {
		t.Fatalf("没有记下审计：%v", err)
	}
	if target != deletedUserID {
		t.Fatalf("target_id 应是被删用户 ID：%q", target)
	}
	for _, want := range []string{deletedUserID, goneActorID, fp} {
		if !strings.Contains(detail, want) {
			t.Fatalf("审计详情必须含原值 %q（user_id 列为 NULL 时这是唯一线索）：%s", want, detail)
		}
	}
	if strings.Contains(detail, "kc-subject-deleted") {
		t.Fatalf("审计不得含 subject 明文：%s", detail)
	}
	if userCol != nil {
		t.Fatalf("执行人不存在时 user_id 列为 NULL 是预期，线索在详情里：%v", *userCol)
	}
}

func newQueueForTest(t *testing.T) (*PostgresCleanupQueue, string) {
	t.Helper()
	db, tenantID, _, _ := setupProvisionerDB(t)
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "cleanup-queue-test-key-not-production")
	// ClaimDue 是全局领取（生产里就该如此）。共享测试库里别的用例可能遗留了待处理行，
	// 先把它们收尾，保证本用例只看到自己租户的行。
	if _, err := db.Exec(context.Background(), `UPDATE local_identity_cleanup_queue SET status='done' WHERE tenant_id <> $1 AND status='pending'`, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec(context.Background(), `DELETE FROM local_identity_cleanup_queue WHERE tenant_id=$1`, tenantID)
	})
	return NewPostgresCleanupQueue(db), tenantID
}

func TestCleanupQueueStoresTheSubjectEncryptedAndMergesDuplicates(t *testing.T) {
	q, tenantID := newQueueForTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := q.Enqueue(ctx, tenantID, "u1", "actor", "kc-subject-secret-1", now); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(ctx, tenantID, "u1", "actor", "kc-subject-secret-1", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var count int
	var ciphertext string
	if err := q.db.QueryRow(ctx, `SELECT count(*), max(subject_ciphertext) FROM local_identity_cleanup_queue WHERE tenant_id=$1`, tenantID).Scan(&count, &ciphertext); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("同一 subject 重复入队应合并成一条，实际 %d", count)
	}
	if strings.Contains(ciphertext, "kc-subject-secret-1") || !strings.HasPrefix(ciphertext, "enc:") {
		t.Fatalf("subject 必须加密存储：%q", ciphertext)
	}
	// 入队带宽限期（给请求内同步删除留时间），越过宽限后才可领取。
	items, err := q.ClaimDue(ctx, now.Add(3*time.Minute), 10)
	if err != nil || len(items) != 1 || items[0].Subject != "kc-subject-secret-1" {
		t.Fatalf("到期领取应解密出 subject：items=%+v err=%v", items, err)
	}
	// 被领取的行有租约，立刻再领取不应重复拿到（多副本不重复处理）。
	again, _ := q.ClaimDue(ctx, now.Add(3*time.Minute), 10)
	if len(again) != 0 {
		t.Fatalf("租约期内不应被重复领取：%+v", again)
	}
}

func TestCleanupBackoffIsExponentialAndCapped(t *testing.T) {
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute}
	for i, w := range want {
		if got := CleanupBackoff(i + 1); got != w {
			t.Fatalf("第 %d 次失败后的退避应为 %v，实际 %v", i+1, w, got)
		}
	}
	if got := CleanupBackoff(50); got != time.Hour {
		t.Fatalf("退避应封顶 1 小时，实际 %v", got)
	}
}

type flakyClient struct {
	failures  int
	deleted   []string
	disabled  []string
	deleteErr error
}

func (c *flakyClient) CreateUser(context.Context, CreateUserInput) (string, error) { return "", nil }
func (c *flakyClient) SetEnabled(_ context.Context, subject string, enabled bool) error {
	if !enabled {
		c.disabled = append(c.disabled, subject)
	}
	return nil
}
func (c *flakyClient) ResetPassword(context.Context, string, string, bool) error { return nil }
func (c *flakyClient) DeleteUser(_ context.Context, subject string) error {
	if c.failures > 0 {
		c.failures--
		return c.deleteErr
	}
	c.deleted = append(c.deleted, subject)
	return nil
}

func TestCleanupWorkerRetriesUntilKeycloakDeleteSucceeds(t *testing.T) {
	q, tenantID := newQueueForTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	client := &flakyClient{failures: 2, deleteErr: ErrUnavailable}
	var done []CleanupItem
	w := &CleanupWorker{Queue: q, Client: client, Now: func() time.Time { return now }, OnDone: func(_ context.Context, it CleanupItem) { done = append(done, it) }}
	if err := q.Enqueue(ctx, tenantID, "u1", "actor", "kc-subject-retry", now); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 3; round++ {
		now = now.Add(2 * time.Hour) // 越过任何退避/租约
		if _, err := w.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !containsString(client.deleted, "kc-subject-retry") || countString(client.deleted, "kc-subject-retry") != 1 {
		t.Fatalf("重试成功后应恰好删除一次 Keycloak 用户：%v", client.deleted)
	}
	if len(client.disabled) < 1 {
		t.Fatalf("每次重试都应先确保禁用：%v", client.disabled)
	}
	var status string
	var attempts int
	if err := q.db.QueryRow(ctx, `SELECT status, attempts FROM local_identity_cleanup_queue WHERE tenant_id=$1`, tenantID).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != CleanupStatusDone || attempts != 2 {
		t.Fatalf("应记 2 次失败后完成：status=%s attempts=%d", status, attempts)
	}
	if len(done) != 1 {
		t.Fatalf("完成回调应触发一次：%d", len(done))
	}
}

func TestCleanupWorkerStopsAtTheMaximumAndRaisesTheAlert(t *testing.T) {
	q, tenantID := newQueueForTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	client := &flakyClient{failures: 1000, deleteErr: ErrRejected}
	var exhausted []CleanupItem
	w := &CleanupWorker{Queue: q, Client: client, Now: func() time.Time { return now }, OnExhausted: func(_ context.Context, it CleanupItem) { exhausted = append(exhausted, it) }}
	if err := q.Enqueue(ctx, tenantID, "u1", "actor", "kc-subject-forever", now); err != nil {
		t.Fatal(err)
	}
	if _, err := q.db.Exec(ctx, `UPDATE local_identity_cleanup_queue SET max_attempts=3 WHERE tenant_id=$1`, tenantID); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 6; round++ {
		now = now.Add(2 * time.Hour)
		if _, err := w.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var status, code string
	var attempts int
	if err := q.db.QueryRow(ctx, `SELECT status, attempts, last_error_code FROM local_identity_cleanup_queue WHERE tenant_id=$1`, tenantID).Scan(&status, &attempts, &code); err != nil {
		t.Fatal(err)
	}
	if status != CleanupStatusExhausted || attempts != 3 {
		t.Fatalf("达到上限应置 exhausted 且不再重试：status=%s attempts=%d", status, attempts)
	}
	if len(exhausted) != 1 {
		t.Fatalf("达到上限应告警恰好一次：%d", len(exhausted))
	}
	if strings.Contains(exhausted[0].Fingerprint, "kc-subject") {
		t.Fatalf("告警里只能有指纹：%q", exhausted[0].Fingerprint)
	}
	if code != "rejected" {
		t.Fatalf("错误码应是稳定的 rejected，而不是 Keycloak 原文：%q", code)
	}
	// 耗尽不是终点：之后按天低频续试（不再重复告警），Keycloak 恢复后最终完成（High-A）。
	before := 1000 - client.failures
	now = now.Add(2 * time.Hour)
	_, _ = w.RunOnce(ctx)
	if after := 1000 - client.failures; after != before {
		t.Fatalf("耗尽后未满一天不应续试：%d -> %d", before, after)
	}
	now = now.Add(CleanupExhaustedRetryInterval + time.Minute)
	_, _ = w.RunOnce(ctx)
	if after := 1000 - client.failures; after != before+1 {
		t.Fatalf("耗尽后满一天应低频续试一次：%d -> %d", before, after)
	}
	if len(exhausted) != 1 {
		t.Fatalf("续试失败不应重复告警：%d", len(exhausted))
	}
	client.failures = 0
	now = now.Add(CleanupExhaustedRetryInterval + time.Minute)
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := q.db.QueryRow(ctx, `SELECT status FROM local_identity_cleanup_queue WHERE tenant_id=$1`, tenantID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != CleanupStatusDone || !containsString(client.deleted, "kc-subject-forever") {
		t.Fatalf("Keycloak 恢复后续试应最终完成：status=%s deleted=%v", status, client.deleted)
	}
}

func TestCleanupQueueMarkDoneBySubjectClosesThePreRegisteredRow(t *testing.T) {
	q, tenantID := newQueueForTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := q.Enqueue(ctx, tenantID, "u1", "actor", "kc-subject-sync", now); err != nil {
		t.Fatal(err)
	}
	// 预登记的行在宽限期内不会被 worker 抢先领取。
	if items, err := q.ClaimDue(ctx, now, 10); err != nil || len(items) != 0 {
		t.Fatalf("宽限期内不应被领取：items=%d err=%v", len(items), err)
	}
	if err := q.MarkDoneBySubject(ctx, tenantID, "kc-subject-sync", now); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := q.db.QueryRow(ctx, `SELECT status FROM local_identity_cleanup_queue WHERE tenant_id=$1`, tenantID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != CleanupStatusDone {
		t.Fatalf("同步删除成功后预登记行应完成：%s", status)
	}
	if items, _ := q.ClaimDue(ctx, now.Add(48*time.Hour), 10); len(items) != 0 {
		t.Fatalf("已完成的行不应再被领取：%d", len(items))
	}
}

func containsString(list []string, v string) bool { return countString(list, v) > 0 }
func countString(list []string, v string) int {
	n := 0
	for _, s := range list {
		if s == v {
			n++
		}
	}
	return n
}

var _ = errors.New
