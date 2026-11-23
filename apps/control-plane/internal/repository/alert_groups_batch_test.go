package repository

import (
	"context"
	"testing"
	"time"
)

// TestAlertGroupBatchUpdateStatusIsTenantScoped 验证批量迁移只动本租户的开放组，
// 跨租户 id、不存在 id 与已关闭组都以明细返回失败，且 security_events 不被触碰。
func TestAlertGroupBatchUpdateStatusIsTenantScoped(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	_, otherTenant := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	mk := func(tenant, key string) *AlertGroup {
		g, _, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{TenantID: tenant, GroupKey: key, Severity: "high", AlertType: "security_event", Title: "t", OccurredAt: now})
		if err != nil {
			t.Fatalf("upsert %s: %v", key, err)
		}
		return g
	}
	a1 := mk(tenantID, "batch-a1")
	a2 := mk(tenantID, "batch-a2")
	closed := mk(tenantID, "batch-closed")
	if _, err := repo.UpdateStatus(ctx, tenantID, closed.ID, AlertGroupStatusResolved, "u", ""); err != nil {
		t.Fatal(err)
	}
	foreign := mk(otherTenant, "batch-foreign")
	// 关联一条真实安全事件，证明批量处置不改 security_events。
	userID, projectID := "user_"+tenantID, "project_"+tenantID
	reqID, seID := "req_batch_"+a1.ID, "se_batch_"+a1.ID
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1,$2,$1,'developer','active')`, []any{userID, tenantID}},
		{`INSERT INTO projects (id, tenant_id, name, owner_user_id, status) VALUES ($1,$2,$1,$3,'active')`, []any{projectID, tenantID, userID}},
		{`INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status, created_at) VALUES ($1,$2,$3,$4,$5,'chat_completions','success',$6)`, []any{"log_" + seID, reqID, tenantID, projectID, userID, now}},
		{`INSERT INTO security_events (id, request_id, tenant_id, project_id, event_type, severity, action_taken, matched_summary, alert_group_id, created_at) VALUES ($1,$2,$3,$4,'security_check','high','security_audit','{}'::jsonb,$5,$6)`, []any{seID, reqID, tenantID, projectID, a1.ID, now}},
	} {
		if _, err := db.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}

	res, err := repo.BatchUpdateStatus(ctx, AlertGroupBatchStatusInput{
		TenantID: tenantID,
		IDs:      []string{a1.ID, a2.ID, closed.ID, foreign.ID, "ag_missing"},
		Status:   AlertGroupStatusFalsePositive,
		ActorID:  "user_batch",
		Note:     "批量误报",
	})
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if len(res.UpdatedIDs) != 2 {
		t.Fatalf("updated = %v, want a1,a2", res.UpdatedIDs)
	}
	reasons := map[string]string{}
	for _, f := range res.Failed {
		reasons[f.ID] = f.Reason
	}
	if reasons[foreign.ID] != AlertGroupBatchReasonNotFound || reasons["ag_missing"] != AlertGroupBatchReasonNotFound {
		t.Fatalf("foreign/missing must fail as not_found: %+v", res.Failed)
	}
	if reasons[closed.ID] != AlertGroupBatchReasonNotOpen {
		t.Fatalf("closed group must fail as not_open: %+v", res.Failed)
	}

	for _, id := range []string{a1.ID, a2.ID} {
		g, err := repo.GetByID(ctx, tenantID, id)
		if err != nil {
			t.Fatal(err)
		}
		if g.Status != AlertGroupStatusFalsePositive {
			t.Fatalf("%s status = %s", id, g.Status)
		}
		var by, note string
		var fpAt, closedAt *time.Time
		if err := db.QueryRow(ctx, `SELECT COALESCE(disposition_by,''), COALESCE(disposition_note,''), false_positive_at, closed_at FROM alert_groups WHERE id=$1`, id).Scan(&by, &note, &fpAt, &closedAt); err != nil {
			t.Fatal(err)
		}
		if by != "user_batch" || note != "批量误报" || fpAt == nil || closedAt == nil {
			t.Fatalf("%s lifecycle columns not set like UpdateStatus: by=%q note=%q fp=%v closed=%v", id, by, note, fpAt, closedAt)
		}
	}
	gotClosed, _ := repo.GetByID(ctx, tenantID, closed.ID)
	if gotClosed.Status != AlertGroupStatusResolved {
		t.Fatalf("already-closed group must not be rewritten, got %s", gotClosed.Status)
	}
	gotForeign, _ := repo.GetByID(ctx, otherTenant, foreign.ID)
	if gotForeign.Status != AlertGroupStatusOpen {
		t.Fatalf("foreign tenant group changed: %s", gotForeign.Status)
	}
	var seGroup string
	if err := db.QueryRow(ctx, `SELECT COALESCE(alert_group_id,'') FROM security_events WHERE id=$1`, seID).Scan(&seGroup); err != nil {
		t.Fatal(err)
	}
	if seGroup != a1.ID {
		t.Fatalf("security event must be untouched, alert_group_id=%q", seGroup)
	}
}

func TestAlertGroupBatchUpdateStatusAcknowledgeAndProjectScope(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()
	inScope, _, _ := repo.UpsertOpen(ctx, AlertGroupUpsertInput{TenantID: tenantID, ProjectID: "proj_mine", GroupKey: "scope-in", Severity: "high", AlertType: "security_event", Title: "t", OccurredAt: now})
	outScope, _, _ := repo.UpsertOpen(ctx, AlertGroupUpsertInput{TenantID: tenantID, ProjectID: "proj_other", GroupKey: "scope-out", Severity: "high", AlertType: "security_event", Title: "t", OccurredAt: now})

	res, err := repo.BatchUpdateStatus(ctx, AlertGroupBatchStatusInput{
		TenantID: tenantID, IDs: []string{inScope.ID, outScope.ID}, Status: AlertGroupStatusAcknowledged,
		ActorID: "dept_user", ProjectIDs: []string{"proj_mine"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.UpdatedIDs) != 1 || res.UpdatedIDs[0] != inScope.ID {
		t.Fatalf("updated = %v", res.UpdatedIDs)
	}
	if len(res.Failed) != 1 || res.Failed[0].ID != outScope.ID || res.Failed[0].Reason != AlertGroupBatchReasonNotFound {
		t.Fatalf("out-of-scope must fail as not_found: %+v", res.Failed)
	}
	g, _ := repo.GetByID(ctx, tenantID, inScope.ID)
	if g.Status != AlertGroupStatusAcknowledged {
		t.Fatalf("status = %s", g.Status)
	}
	// 已确认的组可继续批量关闭（open/acknowledged 都算待处置）。
	res2, err := repo.BatchUpdateStatus(ctx, AlertGroupBatchStatusInput{TenantID: tenantID, IDs: []string{inScope.ID}, Status: AlertGroupStatusResolved, ActorID: "u"})
	if err != nil || len(res2.UpdatedIDs) != 1 {
		t.Fatalf("ack->resolved: %+v %v", res2, err)
	}
	// 已确认 -> 再确认：不算待处置迁移，按 not_open 失败，避免重复刷新确认时间。
	res3, _ := repo.BatchUpdateStatus(ctx, AlertGroupBatchStatusInput{TenantID: tenantID, IDs: []string{inScope.ID}, Status: AlertGroupStatusAcknowledged, ActorID: "u"})
	if len(res3.UpdatedIDs) != 0 || len(res3.Failed) != 1 || res3.Failed[0].Reason != AlertGroupBatchReasonNotOpen {
		t.Fatalf("resolved group must not be re-acknowledged: %+v", res3)
	}
}

func TestAlertGroupBatchUpdateStatusRejectsInvalidInput(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()
	if _, err := repo.BatchUpdateStatus(ctx, AlertGroupBatchStatusInput{TenantID: tenantID, IDs: []string{"x"}, Status: AlertGroupStatusOpen}); err == nil {
		t.Fatal("open must be rejected for batch")
	}
	if _, err := repo.BatchUpdateStatus(ctx, AlertGroupBatchStatusInput{TenantID: "", IDs: []string{"x"}, Status: AlertGroupStatusResolved}); err == nil {
		t.Fatal("tenant required")
	}
	if _, err := repo.BatchUpdateStatus(ctx, AlertGroupBatchStatusInput{TenantID: tenantID, Status: AlertGroupStatusResolved}); err == nil {
		t.Fatal("ids required")
	}
	ids := make([]string, AlertGroupBatchMaxIDs+1)
	for i := range ids {
		ids[i] = "x"
	}
	if _, err := repo.BatchUpdateStatus(ctx, AlertGroupBatchStatusInput{TenantID: tenantID, IDs: ids, Status: AlertGroupStatusResolved}); err == nil {
		t.Fatal("over limit must be rejected")
	}
}

func TestAlertGroupListPageFiltersTypeRuleAndTime(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()
	old := time.Now().UTC().Add(-40 * 24 * time.Hour)
	recent := time.Now().UTC().Add(-time.Hour)
	mk := func(key, alertType, rule string, at time.Time) {
		if _, _, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{TenantID: tenantID, GroupKey: key, Severity: "high", AlertType: alertType, Title: key, OccurredAt: at,
			BodyJSON: map[string]any{"rule_name": rule, "rule_id": "rid_" + key}}); err != nil {
			t.Fatal(err)
		}
	}
	mk("f-old-card", "security_event", "国内银行卡号", old)
	mk("f-new-card", "security_event", "国内银行卡号", recent)
	mk("f-new-other", "security_event", "身份证号", recent)
	mk("f-new-fault", "runtime_fault", "国内银行卡号", recent)

	page, err := repo.ListPage(ctx, AlertGroupListFilter{TenantID: tenantID, AlertType: "security_event", Rule: "国内银行卡号", LastSeenFrom: time.Now().UTC().Add(-7 * 24 * time.Hour), IncludeDevTraffic: true, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].GroupKey != "f-new-card" {
		t.Fatalf("unexpected page: total=%d items=%+v", page.Total, page.Items)
	}
	if page.Items[0].BodyJSON["rule_name"] != "国内银行卡号" {
		t.Fatalf("list must carry rule_name for display: %#v", page.Items[0].BodyJSON)
	}
	// rule 也可按规则 id 精确匹配；时间上界只取到 old 这一条。
	page2, err := repo.ListPage(ctx, AlertGroupListFilter{TenantID: tenantID, Rule: "rid_f-old-card", LastSeenTo: time.Now().UTC().Add(-30 * 24 * time.Hour), IncludeDevTraffic: true, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if page2.Total != 1 || page2.Items[0].GroupKey != "f-old-card" {
		t.Fatalf("unexpected page2: %+v", page2.Items)
	}
}
