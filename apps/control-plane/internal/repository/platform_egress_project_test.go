package repository

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
	"time"
)

// 多租户：租户有项目时事件挂它自己的项目；没有项目时不写事件、不写请求日志，只打一条日志
// （含原租户 ID、类型、目标主机），也不新建项目，项目列表照常。
func TestPlatformEgressEventUsesTenantProjectOnRealPostgres(t *testing.T) {
	db := platformEgressTestPool(t)
	ctx := context.Background()
	suffix := time.Now().Format("150405.000000")
	withProject, without := "t_pe_p_"+suffix, "t_pe_n_"+suffix
	for _, tenant := range []string{withProject, without} {
		if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',true)`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects(id,tenant_id,name,code,status) VALUES($1,$2,'默认应用','default','active')`, "proj_"+withProject, withProject); err != nil {
		t.Fatal(err)
	}
	id, err := RecordPlatformEgressDenied(ctx, db, withProject, "", "ldap", "dc.example")
	if err != nil || id == "" {
		t.Fatalf("tenant with a project: id=%q err=%v", id, err)
	}
	var tenant, project string
	if err := db.QueryRow(ctx, `SELECT tenant_id, project_id FROM security_events WHERE id=$1`, id).Scan(&tenant, &project); err != nil || tenant != withProject || project != "proj_"+withProject {
		t.Fatalf("event attached to %s/%s err=%v", tenant, project, err)
	}

	projectsBefore, err := NewProjectRepository(db).List(ctx, "tenant_default")
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	original := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(original) })
	target := "noproject-" + suffix + ".example"
	id, err = RecordPlatformEgressDenied(ctx, db, without, "", "notify_channel:webhook", target)
	log.SetOutput(original)
	if err != nil || id != "" {
		t.Fatalf("tenant without projects must not write an event: id=%q err=%v", id, err)
	}
	for _, want := range []string{without, "notify_channel:webhook", target} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("log line must carry %q: %s", want, logs.String())
		}
	}
	var events, requestLogs, created int
	_ = db.QueryRow(ctx, `SELECT count(*) FROM security_events WHERE matched_summary->>'target' = $1`, target).Scan(&events)
	_ = db.QueryRow(ctx, `SELECT count(*) FROM request_logs WHERE endpoint_type='platform_egress' AND tenant_id = $1`, without).Scan(&requestLogs)
	_ = db.QueryRow(ctx, `SELECT count(*) FROM projects WHERE tenant_id=$1`, without).Scan(&created)
	if events != 0 || requestLogs != 0 || created != 0 {
		t.Fatalf("no event, request log or project may be written: events=%d logs=%d projects=%d", events, requestLogs, created)
	}
	projectsAfter, err := NewProjectRepository(db).List(ctx, "tenant_default")
	if err != nil || len(projectsAfter) != len(projectsBefore) {
		t.Fatalf("project list must stay unchanged and readable: before=%d after=%d err=%v", len(projectsBefore), len(projectsAfter), err)
	}
}
