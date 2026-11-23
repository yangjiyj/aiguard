package repository

import (
	"context"
	"testing"
)

// 触发器缺着（物化作废）期间删掉的事件不会登记；重建收尾要清掉这些事件留下的命中行，结果与实时一致。
func TestAlertCaseRebuildDropsMembersOfDeletedEvents(t *testing.T) {
	db, ctx := alertCaseLimitsDB(t)
	tenant := seedAlertCaseGroupTenant(t, ctx, db, 5)
	repo := NewAlertOccurrenceRepository(db)
	if err := repo.PrepareAlertCases(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	var definition string
	if err := db.QueryRow(ctx, `SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgname='trg_alert_case_dirty_event_delete'`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `DROP TRIGGER trg_alert_case_dirty_event_delete ON security_events`); err != nil {
		t.Fatal(err)
	}
	restored := false
	t.Cleanup(func() {
		if !restored {
			_, _ = db.Exec(context.Background(), definition)
		}
		resetAlertCaseStoreCheckCache()
	})
	resetAlertCaseStoreCheckCache()
	if _, err := db.Exec(ctx, `DELETE FROM security_events WHERE id=$1`, tenant+"_e3"); err != nil {
		t.Fatal(err)
	}
	f := AlertOccurrenceFilter{TenantID: tenant, Grouping: "cases", IncludeSuppressed: true, IncludeDevTraffic: true, Limit: 100}
	if _, err := repo.List(ctx, f); err != nil { // 发现触发器不一致，作废物化结果
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, definition); err != nil {
		t.Fatal(err)
	}
	restored = true
	resetAlertCaseStoreCheckCache()
	if err := repo.PrepareAlertCases(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	var orphans int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_case_members WHERE tenant_id=$1 AND event_id=$2`, tenant, tenant+"_e3").Scan(&orphans); err != nil || orphans != 0 {
		t.Fatalf("rebuild must drop members of deleted events: %d %v", orphans, err)
	}
	live := &AlertOccurrenceRepository{db: db, caseStoreDisabled: true}
	want, err := live.List(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := repo.List(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, "after rebuild", want, got)
}
