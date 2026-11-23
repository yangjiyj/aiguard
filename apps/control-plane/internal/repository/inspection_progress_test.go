package repository

import (
	"context"
	"testing"
	"time"
)

func TestInspectionProgressTenantEnvironmentAndWindow(t *testing.T) {
	db := verifiedModelsTestDB(t)
	ctx := context.Background()
	_, err := db.Exec(ctx, `CREATE TABLE proxy_inspection_jobs(tenant_id text,request_id text,environment_scope text,status text,completed_parts int,total_parts int,admission text,updated_at timestamptz);
 ALTER TABLE request_logs RENAME TO fixture_base_request_logs;
 CREATE TABLE request_logs(tenant_id text,request_id text,environment_scope text,created_at timestamptz, agent_instance_id varchar(128));
 INSERT INTO proxy_inspection_jobs VALUES('tenant','same','customer','running',3,7,'forwarded',now()),('other','same','customer','failed',0,2,'blocked',now()),('tenant','home','home','completed',1,1,'forwarded',now()),('tenant','old','customer','completed',1,1,'forwarded',now());
 INSERT INTO request_logs VALUES('tenant','same','customer',now()),('other','same','customer',now()),('tenant','home','home',now()),('tenant','old','customer',now()-interval '2 days');`)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(ctx, inspectionProgressQuery+" AND rl.environment_scope=ANY($3) AND rl.created_at >= $4 AND rl.created_at < $5", "tenant", []string{"same", "home", "old"}, []string{"customer"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id, status, admission string
		var completed, total int
		var updated time.Time
		if err = rows.Scan(&id, &status, &completed, &total, &admission, &updated); err != nil {
			t.Fatal(err)
		}
		count++
		if id != "same" || status != "running" || completed != 3 || total != 7 || admission != "forwarded" {
			t.Fatalf("wrong progress: %s %s %d/%d %s", id, status, completed, total, admission)
		}
	}
	if rows.Err() != nil || count != 1 {
		t.Fatalf("progress isolation failed count=%d err=%v", count, rows.Err())
	}
}
