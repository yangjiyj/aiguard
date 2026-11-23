package repository

import (
	"context"
	"testing"
	"time"
)

// 集成测试(需 CONTENT_LOGS_TEST_DATABASE_URL):误报处置组集合查询。
// 关键语义:按 group_key 查(含已关闭组)——组被处置后新事件会新建 open 组,
// 静默判定必须仍能命中旧的 false_positive 组。
func TestAlertGroupListFalsePositiveGroupKeys(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()

	// 组 A:处置为误报。
	fpGroup, _, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{
		TenantID: tenantID, GroupKey: "fp-key-a", Severity: "high",
		AlertType: "security_event", Title: "误报组", OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("upsert fp group: %v", err)
	}
	if _, err := repo.UpdateStatus(ctx, tenantID, fpGroup.ID, AlertGroupStatusFalsePositive, "user_1", "确认误报"); err != nil {
		t.Fatalf("UpdateStatus false_positive: %v", err)
	}
	// 组 B:保持 open,不应进集合。
	if _, _, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{
		TenantID: tenantID, GroupKey: "open-key-b", Severity: "high",
		AlertType: "security_event", Title: "在办组", OccurredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upsert open group: %v", err)
	}
	// 同 key 再开一个新 open 组(模拟处置后复发):静默集合仍须含该 key。
	if _, created, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{
		TenantID: tenantID, GroupKey: "fp-key-a", Severity: "high",
		AlertType: "security_event", Title: "误报组复发", OccurredAt: time.Now().UTC(),
	}); err != nil || !created {
		t.Fatalf("reopen after fp created=%v err=%v", created, err)
	}

	keys, err := repo.ListFalsePositiveGroupKeys(ctx, []string{tenantID}, time.Now().UTC().Add(-time.Hour))
	if err != nil {
		t.Fatalf("ListFalsePositiveGroupKeys: %v", err)
	}
	if !keys[tenantID][ScopedAlertGroupKey("fp-key-a", "", "")] {
		t.Fatalf("fp-key-a must be in the silence set (even with a new open group), got %+v", keys)
	}
	if keys[tenantID][ScopedAlertGroupKey("open-key-b", "", "")] {
		t.Fatalf("open group must not be in the silence set, got %+v", keys)
	}

	// 有效期过滤:since 在处置时间之后 → 集合为空(过期恢复)。
	expired, err := repo.ListFalsePositiveGroupKeys(ctx, []string{tenantID}, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("ListFalsePositiveGroupKeys(expired): %v", err)
	}
	if expired[tenantID][ScopedAlertGroupKey("fp-key-a", "", "")] {
		t.Fatalf("disposition outside the window must not silence, got %+v", expired)
	}

	// 空租户集合 → 空结果不报错。
	empty, err := repo.ListFalsePositiveGroupKeys(ctx, nil, time.Now().UTC())
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty tenant set should be a no-op, got %v err=%v", empty, err)
	}
}
