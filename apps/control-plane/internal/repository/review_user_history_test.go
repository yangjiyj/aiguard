package repository

import (
	"context"
	"testing"
	"time"
)

func TestReviewAuditFindsDisabledAndMergedSourceContent(t *testing.T) {
	db, tenant, target, dept, project, _ := employeeKeyFixture(t)
	ctx := context.Background()
	source := tenant + "_source"
	if _, err := db.Exec(ctx, "INSERT INTO users(id,tenant_id,username,role,status,department_id) VALUES($1,$2,$1,'chat_user','disabled',$3)", source, tenant, dept); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec(ctx, "DELETE FROM content_logs WHERE tenant_id=$1", tenant)
		db.Exec(ctx, "DELETE FROM portal_upload_events WHERE tenant_id=$1", tenant)
		db.Exec(ctx, "DELETE FROM user_account_merges WHERE tenant_id=$1", tenant)
	})
	if _, err := db.Exec(ctx, "INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status) VALUES($1,$1,$2,$3,$4,'chat','success')", tenant+"_request", tenant, project, source); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec(ctx, "DELETE FROM content_logs WHERE tenant_id=$1", tenant)
		db.Exec(ctx, "DELETE FROM request_logs WHERE tenant_id=$1", tenant)
	})
	logs := NewContentLogRepository(db)
	if err := logs.Create(ctx, &ContentLog{ID: tenant + "_log", TenantID: tenant, UserID: source, RequestID: tenant + "_request", SessionID: "session", Role: "user", Content: "retained evidence", EnvironmentScope: "customer"}); err != nil {
		t.Fatal(err)
	}
	uploads := NewPortalUploadEventRepository(db)
	if err := uploads.Insert(ctx, PortalUploadEvent{ID: tenant + "_upload", TenantID: tenant, UserID: source, Filename: "evidence.txt", SHA256: "fixture", Size: 1}); err != nil {
		t.Fatal(err)
	}
	check := func(label string) {
		t.Run(label, func(t *testing.T) {
			rows, total, err := logs.ListByUser(ctx, tenant, source, 10, 0)
			if err != nil || total != 1 || len(rows) != 1 {
				t.Errorf("content evidence total=%d rows=%d err=%v", total, len(rows), err)
			}
			rows, total, err = logs.ListByUserScoped(ctx, tenant, source, 10, 0, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), "customer")
			if err != nil || total != 1 || len(rows) != 1 {
				t.Errorf("scoped evidence total=%d rows=%d err=%v", total, len(rows), err)
			}
			files, total, err := uploads.ListByUser(ctx, tenant, source, 10, 0)
			if err != nil || total != 1 || len(files) != 1 {
				t.Errorf("upload evidence total=%d rows=%d err=%v", total, len(files), err)
			}
		})
	}
	check("disabled")
	if _, err := db.Exec(ctx, "INSERT INTO user_account_merges(tenant_id,source_user_id,target_user_id,merged_by) VALUES($1,$2,$3,$3)", tenant, source, target); err != nil {
		t.Fatal(err)
	}
	check("merged_source")
}
