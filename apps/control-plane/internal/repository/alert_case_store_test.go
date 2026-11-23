package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 物化表上的告警读法必须与实时查询逐条一致：同一份数据、同一组参数，案件集合、各项计数、排序、
// 每行的全部字段、汇总、命中明细、处置授权都相同；处置、例外、误报、凭据标记、告警组状态、请求记录、
// 留存会话、事件增删改之后，读接口先消化待重算队列，结果仍与实时查询一致。
// 只在 ALERT_CASES_TEST_DATABASE_URL 指向按正式流程迁移（含 1002/1003）的一次性库时运行。
func TestAlertCaseStoreMatchesLiveQuery(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ALERT_CASES_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("ALERT_CASES_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	fx := seedAlertCaseStoreFixture(t, ctx, db)
	t.Cleanup(func() { fx.cleanup(); db.Close() })
	live := &AlertOccurrenceRepository{db: db, caseStoreDisabled: true}
	stored := NewAlertOccurrenceRepository(db)
	stored.caseStoreDisabled = false
	// 两个租户都先准备好（全新迁移库上租户 B 也可能还没有回填记录），首次运行的比较才稳定。
	for _, tenant := range []string{fx.tenantA, fx.tenantB} {
		if err := stored.PrepareAlertCases(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	var backfillDone bool
	if err := db.QueryRow(ctx, `SELECT done FROM alert_case_backfill WHERE tenant_id=$1`, fx.tenantA).Scan(&backfillDone); err != nil || !backfillDone {
		t.Fatalf("tenant A backfill not finished: %v %v", backfillDone, err)
	}
	cases := compareAlertCaseStore(t, ctx, live, stored, fx, "initial")
	if cases < 8 {
		t.Fatalf("fixture produced only %d cases; the comparison would not cover lanes, dispositions and folding", cases)
	}

	fx.mutate(t, ctx)
	var pending int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_case_dirty WHERE tenant_id = ANY($1)`, []string{fx.tenantA, fx.tenantB}).Scan(&pending); err != nil || pending == 0 {
		t.Fatalf("mutations did not enqueue recomputation: %d %v", pending, err)
	}
	// 夹具里的告警组、凭据都只牵动几条事件，读前消化就会处理：不经后台，下一次读即与实时一致
	// （牵动上千条事件的大告警组、大凭据留给后台，见 TestAlertCaseReadDrainTakesNewestEntriesFirst）。
	compareAlertCaseStore(t, ctx, live, stored, fx, "after mutations")
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_case_dirty WHERE tenant_id = ANY($1)`, []string{fx.tenantA, fx.tenantB}).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("reads did not drain the queue: %d %v", pending, err)
	}
	// 处置和新证据不经后台：下一次读就与实时一致。
	fx.mutateNarrow(t, ctx)
	compareAlertCaseStore(t, ctx, live, stored, fx, "after narrow mutations")
}

type alertCaseStoreFixture struct {
	db                 *pgxpool.Pool
	suffix             string
	tenantA, tenantB   string
	projectA, projectB string
	t0, mid            time.Time
	cleanup            func()
	mutate             func(*testing.T, context.Context)
	mutateNarrow       func(*testing.T, context.Context)
}

func compareAlertCaseStore(t *testing.T, ctx context.Context, live, stored *AlertOccurrenceRepository, fx *alertCaseStoreFixture, round string) int {
	t.Helper()
	now := time.Now().UTC()
	future := now.Add(time.Hour)
	start := fx.t0.Add(-36 * time.Hour)
	compare := func(name string, f AlertOccurrenceFilter) *AlertOccurrencePage {
		t.Helper()
		want, err := live.List(ctx, f)
		if err != nil {
			t.Fatalf("%s %s live: %v", round, name, err)
		}
		got, err := stored.List(ctx, f)
		if err != nil {
			t.Fatalf("%s %s stored: %v", round, name, err)
		}
		if !alertCaseStoreUsed(t, ctx, stored, f) {
			t.Fatalf("%s %s: read did not use the materialized store", round, name)
		}
		assertSameJSON(t, round+" "+name, want, got)
		return want
	}
	ends := []*time.Time{nil, &future, &fx.mid}
	caseIDs := map[string]bool{}
	for _, tenant := range []string{fx.tenantA, fx.tenantB} {
		for _, lane := range []string{"-", "", "action", "watch", "eval"} {
			for _, disposition := range []string{"", "pending", "handled", "false_positive", "all"} {
				for _, dev := range []bool{false, true} {
					for _, recent := range []int{0, 2, 100} {
						for e, end := range ends {
							f := AlertOccurrenceFilter{TenantID: tenant, Grouping: "cases", Disposition: disposition, IncludeDevTraffic: dev,
								RecentLimit: recent, EndTime: end, Limit: 100, CanReadEvidence: true, CanViewRawEvidence: true,
								IncludeSuppressed: disposition == "all" || disposition == "false_positive"}
							if lane != "-" {
								f.LaneAware, f.Lane = true, lane
							}
							page := compare(fmt.Sprintf("cases tenant=%s lane=%s disposition=%s dev=%v recent=%d end=%d", tenant, lane, disposition, dev, recent, e), f)
							for _, item := range page.Items {
								caseIDs[tenant+"|"+item.CaseID] = true
							}
						}
					}
				}
			}
		}
	}
	for i, f := range []AlertOccurrenceFilter{
		{Severity: "high"}, {Severity: "low", IncludeSuppressed: true}, {Category: "email"}, {Category: "secret,semantic_jailbreak", Disposition: "pending"},
		{ProjectIDs: []string{fx.projectA}}, {ProjectIDs: []string{}}, {ProjectID: fx.projectB, IncludeSuppressed: true},
		{StartTime: &start}, {StartTime: &start, EndTime: &fx.mid}, {Limit: 2, Offset: 1}, {Limit: 2, Offset: 3, LaneAware: true},
		{IncludeSuppressed: true, Disposition: "pending"}, {LaneAware: true, Lane: "watch", RecentLimit: 1, IncludeSuppressed: true},
		// 只作用于部分命中的筛选：案件只按命中筛选条件的命中聚合。
		{UserID: fx.tenantA + "_u1"}, {UserID: fx.tenantA + "_u2", IncludeSuppressed: true}, {UserID: fx.tenantA + "_u1", LaneAware: true, Lane: "action", EndTime: &fx.mid},
		{SessionID: "s1"}, {SessionID: "as1", IncludeSuppressed: true}, {SessionID: "s3", IncludeDevTraffic: true}, {SessionID: "s1", UserID: fx.tenantA + "_u1"},
		{ConversationKey: "ck1", IncludeSuppressed: true}, {ConversationKey: "ck2"}, {UserID: "nobody"},
	} {
		f.TenantID, f.Grouping, f.CanReadEvidence = fx.tenantA, "cases", true
		if f.Limit == 0 {
			f.Limit = 100
		}
		compare(fmt.Sprintf("cases filter #%d", i), f)
	}
	for i, f := range []AlertOccurrenceFilter{
		{Disposition: "pending"}, {Disposition: "pending", IncludeDevTraffic: true}, {StartTime: &start, EndTime: &fx.mid},
		{Category: "email"}, {ProjectIDs: []string{fx.projectA}}, {Disposition: "false_positive", IncludeSuppressed: true},
		{UserID: fx.tenantA + "_u1"}, {SessionID: "s1", Disposition: "pending"},
	} {
		f.TenantID = fx.tenantA
		want, err := live.SummarizeCases(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		got, err := stored.SummarizeCases(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		assertSameJSON(t, fmt.Sprintf("%s summary #%d", round, i), want, got)
	}
	seenPast := fx.t0.Add(-time.Hour)
	for key := range caseIDs {
		tenant, caseID, _ := strings.Cut(key, "|")
		for _, suppressed := range []bool{true, false} {
			for e, end := range ends {
				for _, page := range [][2]int{{100, 0}, {2, 1}} {
					compare(fmt.Sprintf("hits case=%s suppressed=%v end=%d page=%v", caseID, suppressed, e, page), AlertOccurrenceFilter{
						TenantID: tenant, Grouping: "hits", CaseID: caseID, IncludeSuppressed: suppressed, EndTime: end,
						Limit: page[0], Offset: page[1], CanReadEvidence: true, IncludeRaw: true})
				}
			}
		}
		compare("hits case scoped "+caseID, AlertOccurrenceFilter{TenantID: tenant, Grouping: "hits", CaseID: caseID, ProjectIDs: []string{fx.projectA}, IncludeSuppressed: true, Limit: 100})
		compare("hits case by user "+caseID, AlertOccurrenceFilter{TenantID: tenant, Grouping: "hits", CaseID: caseID, UserID: fx.tenantA + "_u1", IncludeSuppressed: true, Limit: 100})
		compare("hits case by session "+caseID, AlertOccurrenceFilter{TenantID: tenant, Grouping: "hits", CaseID: caseID, SessionID: "s1", IncludeSuppressed: true, Limit: 100})
		for _, projects := range [][]string{nil, {fx.projectA}, {fx.projectB}} {
			for _, seen := range []*time.Time{nil, &seenPast, &now} {
				wantOK, wantErr := authorizeAlertCaseSnapshotWith(ctx, live.db, tenant, caseID, projects, seen, false)
				gotOK, gotErr := authorizeAlertCaseSnapshotWith(ctx, stored.db, tenant, caseID, projects, seen, true)
				if wantOK != gotOK || fmt.Sprint(wantErr) != fmt.Sprint(gotErr) {
					t.Fatalf("%s authorize case=%s projects=%v seen=%v: live=(%v,%v) stored=(%v,%v)", round, caseID, projects, seen, wantOK, wantErr, gotOK, gotErr)
				}
			}
		}
		// 别的租户猜中案件编号也不能授权。
		other := fx.tenantA
		if tenant == fx.tenantA {
			other = fx.tenantB
		}
		if ok, err := authorizeAlertCaseSnapshotWith(ctx, stored.db, other, caseID, nil, nil, true); ok || err != nil {
			t.Fatalf("%s case %s authorized for another tenant: %v %v", round, caseID, ok, err)
		}
	}
	return len(caseIDs)
}

// alertCaseStoreUsed 确认这次读确实走了物化表（比较才有意义）。
func alertCaseStoreUsed(t *testing.T, ctx context.Context, repo *AlertOccurrenceRepository, f AlertOccurrenceFilter) bool {
	t.Helper()
	meta, err := repo.useReadMetadata(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.useReadMetadata = meta
	_, _, materialized, err := repo.alertQuery(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	return materialized
}

func assertSameJSON(t *testing.T, name string, want, got any) {
	t.Helper()
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(got)
	if string(a) == string(b) {
		return
	}
	var wantPage, gotPage map[string]any
	_ = json.Unmarshal(a, &wantPage)
	_ = json.Unmarshal(b, &gotPage)
	for key := range wantPage {
		if fmt.Sprint(wantPage[key]) == fmt.Sprint(gotPage[key]) {
			continue
		}
		if key == "items" {
			wantItems, _ := wantPage[key].([]any)
			gotItems, _ := gotPage[key].([]any)
			for i := 0; i < len(wantItems) && i < len(gotItems); i++ {
				wi, _ := json.Marshal(wantItems[i])
				gi, _ := json.Marshal(gotItems[i])
				if string(wi) != string(gi) {
					t.Fatalf("%s: item %d differs\nlive:   %s\nstored: %s", name, i, wi, gi)
				}
			}
			t.Fatalf("%s: item count live=%d stored=%d", name, len(wantItems), len(gotItems))
		}
		t.Fatalf("%s: %s differs\nlive:   %v\nstored: %v", name, key, wantPage[key], gotPage[key])
	}
	t.Fatalf("%s differs\nlive:   %s\nstored: %s", name, a, b)
}

func seedAlertCaseStoreFixture(t *testing.T, ctx context.Context, db *pgxpool.Pool) *alertCaseStoreFixture {
	t.Helper()
	suffix := fmt.Sprint(time.Now().UnixNano())
	fx := &alertCaseStoreFixture{db: db, suffix: suffix, tenantA: "acs_a_" + suffix, tenantB: "acs_b_" + suffix,
		projectA: "acs_pa_" + suffix, projectB: "acs_pb_" + suffix}
	id := func(name string) string { return name + "_" + suffix }
	now := time.Now().UTC().Truncate(time.Second)
	fx.t0 = now.Add(-72 * time.Hour)
	fx.mid = now.Add(-30 * time.Hour)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
	}
	fx.cleanup = func() {
		tenants := []string{fx.tenantA, fx.tenantB}
		for _, statement := range []string{
			`DELETE FROM audit_dispositions WHERE tenant_id = ANY($1)`,
			`DELETE FROM security_events WHERE tenant_id = ANY($1)`,
			`DELETE FROM alert_groups WHERE tenant_id = ANY($1)`,
			`DELETE FROM access_content_logs WHERE tenant_id = ANY($1)`,
			`DELETE FROM request_logs WHERE tenant_id = ANY($1)`,
			`DELETE FROM internal_keys WHERE tenant_id = ANY($1)`,
			`DELETE FROM users WHERE tenant_id = ANY($1)`,
			`DELETE FROM teams WHERE tenant_id = ANY($1)`,
			`DELETE FROM projects WHERE tenant_id = ANY($1)`,
			`DELETE FROM alert_case_members WHERE tenant_id = ANY($1)`,
			`DELETE FROM alert_cases WHERE tenant_id = ANY($1)`,
			`DELETE FROM alert_case_dirty WHERE tenant_id = ANY($1)`,
			`DELETE FROM alert_case_dirty_quarantine WHERE tenant_id = ANY($1)`,
			`DELETE FROM alert_case_backfill WHERE tenant_id = ANY($1)`,
			`DELETE FROM tenants WHERE id = ANY($1)`,
		} {
			if _, err := db.Exec(context.Background(), statement, tenants); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}
	}
	for _, tenant := range []string{fx.tenantA, fx.tenantB} {
		exec(`INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',TRUE)`, tenant)
		exec(`INSERT INTO teams(id,tenant_id,name,path) VALUES($1,$2,'部门',$1)`, tenant+"_team", tenant)
		exec(`INSERT INTO users(id,tenant_id,username,department_id) VALUES($1,$2,'甲',$3),($4,$2,'乙',$3)`, tenant+"_u1", tenant, tenant+"_team", tenant+"_u2")
	}
	exec(`INSERT INTO projects(id,tenant_id,name) VALUES($1,$3,'甲应用'),($2,$3,'乙应用'),($4,$3,'自检'),($5,$6,'他租户应用')`,
		fx.projectA, fx.projectB, fx.tenantA, "project_upgrade_verify_"+suffix, id("acs_pc"), fx.tenantB)
	exec(`INSERT INTO internal_keys(id,tenant_id,project_id,key_hash,key_prefix,user_id,name,traffic_class) VALUES
 ($1::text,$4,$5,md5($1::text),'sk','`+fx.tenantA+`_u1','评测','evaluation'),
 ($2::text,$4,$5,md5($2::text),'sk','`+fx.tenantA+`_u1','编程','coding'),
 ($3::text,$4,$5,md5($3::text),'sk','`+fx.tenantA+`_u2','普通','')`, id("k_eval"), id("k_code"), id("k_plain"), fx.tenantA, fx.projectA)
	type request struct {
		name, tenant, project, key, session, scope string
		at                                         time.Time
		principal                                  string
	}
	requests := []request{
		{"r1", fx.tenantA, fx.projectA, id("k_plain"), "s1", "customer", fx.t0, `{"trust_level":"authenticated","actor_user_id":"` + fx.tenantA + `_u1","key_id":"` + id("k_plain") + `"}`},
		{"r2", fx.tenantA, fx.projectA, id("k_plain"), "s1", "customer", fx.t0.Add(time.Hour), `{"trust_level":"key_bound","key_owner_user_id":"` + fx.tenantA + `_u2","key_id":"` + id("k_plain") + `"}`},
		{"r3", fx.tenantA, fx.projectB, id("k_code"), "", "customer", now.Add(-50 * time.Hour), `{}`},
		{"r4", fx.tenantA, fx.projectA, id("k_eval"), "s2", "customer", fx.t0.Add(2 * time.Hour), `{"key_id":"` + id("k_eval") + `"}`},
		{"r5", fx.tenantA, fx.projectA, id("k_plain"), "s3", "codex", fx.t0.Add(3 * time.Hour), `{}`},
		{"r6", fx.tenantA, fx.projectB, "", "", "customer", now.Add(-20 * time.Hour), `{}`},
		{"r7", fx.tenantA, "project_upgrade_verify_" + suffix, "", "", "customer", now.Add(-10 * time.Hour), `{}`},
		{"r8", fx.tenantA, fx.projectA, id("k_code"), "s4", "customer", now.Add(-2 * time.Hour), `{}`},
		{"r9", fx.tenantA, fx.projectA, id("k_plain"), "s3", "codex", fx.t0.Add(4 * time.Hour), `{}`},
		{"rb1", fx.tenantB, id("acs_pc"), "", "sb", "customer", fx.t0, `{}`},
	}
	for _, r := range requests {
		var key, session any
		if r.key != "" {
			key = r.key
		}
		if r.session != "" {
			session = r.session
		}
		exec(`INSERT INTO request_logs(id,request_id,tenant_id,project_id,client_id,session_id,environment_scope,principal_context_json,source_ip,proxy_target_host,created_at)
 VALUES($1,$1,$2,$3,$4,$5,$6,$7::jsonb,'10.0.0.8','chat.example.test',$8)`, id(r.name), r.tenant, r.project, key, session, r.scope, r.principal, r.at)
	}
	// 记录在请求上的用户（非认证身份时按它算操作人）。
	exec(`UPDATE request_logs SET user_id=$1 WHERE id = ANY($2)`, fx.tenantA+"_u2", []string{id("r3"), id("r6"), id("r8")})
	exec(`INSERT INTO access_content_logs(request_id,tenant_id,conversation_id,section_id,request_content_redacted,environment_scope,created_at)
 VALUES($1,$2,'conv6','sec6','你好','customer',$3)`, id("r6"), fx.tenantA, now.Add(-20*time.Hour))
	exec(`INSERT INTO alert_groups(id,tenant_id,project_id,group_key,status,severity,alert_type,title,request_id,first_seen_at,last_seen_at,class_key) VALUES
 ($1,$4,$5,$1,'open','high','semantic','开发作用域语义告警',$6,now(),now(),'semantic_jailbreak'),
 ($2,$4,$5,$2,'false_positive','low','content','误报组',$7,now(),now(),'catalog_policy'),
 ($3,$4,$5,$3,'open','high','content','普通组',$8,now(),now(),'pii_email')`,
		id("g_dev"), id("g_fp"), id("g_open"), fx.tenantA, fx.projectA, id("r5"), id("r3"), id("r1"))
	finding := func(kind, category, severity, source, location string, index int, extra map[string]any) map[string]any {
		f := map[string]any{"type": kind, "category": category, "severity": severity, "rule_id": "rule_" + category, "rule_name": "规则" + category,
			"message_index": index, "stage": "input", "content_source": source, "matched_location": location, "action": "audit",
			"redacted_evidence": "e***" + category, "raw_evidence": "evidence " + category + location, "raw_evidence_sha256": fmt.Sprintf("%064d", index),
			"evidence_reason": "命中" + category}
		if source == "model_output" {
			f["stage"] = "output"
		}
		for k, v := range extra {
			f[k] = v
		}
		return f
	}
	event := func(name, tenant, request, project, kind, severity, action string, created time.Time, summary any, group, conversation string) {
		t.Helper()
		body, _ := json.Marshal(summary)
		var req, grp, conv, proj any
		if request != "" {
			req = id(request)
		}
		if group != "" {
			grp = id(group)
		}
		if conversation != "" {
			conv = conversation
		}
		if project != "" {
			proj = project
		}
		exec(`INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary,alert_group_id,conversation_key,created_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11)`, id(name), req, tenant, proj, kind, severity, action, string(body), grp, conv, created)
	}
	findings := func(items ...map[string]any) map[string]any {
		list := make([]any, len(items))
		for i := range items {
			list[i] = items[i]
		}
		return map[string]any{"stage": "input", "findings": list}
	}
	pa, pb := fx.projectA, fx.projectB
	event("e1", fx.tenantA, "r1", pa, "security_check", "high", "flag", fx.t0.Add(time.Minute), findings(
		finding("pii", "email", "medium", "user", "content[1:5]", 0, nil),
		finding("secret", "api_key", "high", "user", "content[7:20]", 1, nil),
		finding("pii", "email", "low", "model_output", "content[3:9]", 2, nil),
		finding("pii", "email", "high", "model_output", "content[3:9]", 2, map[string]any{"rule_id": "rule_email_b"}),
	), "g_open", "")
	event("e2", fx.tenantA, "r1", pa, "security_check", "high", "block", fx.t0.Add(2*time.Minute), findings(
		finding("pii", "email", "high", "user", "content[1:5]", 0, map[string]any{"rule_id": "rule_email_dup"}),
	), "g_open", "")
	event("e3", fx.tenantA, "r2", pa, "security_check", "high", "flag", fx.t0.Add(time.Hour+time.Minute), findings(
		finding("semantic_attack", "semantic_jailbreak", "high", "user", "content[0:30]", 0, nil),
	), "", "")
	event("e4", fx.tenantA, "r3", pb, "security_check", "low", "block", now.Add(-time.Hour), findings(
		finding("catalog_policy", "confidential_keyword", "low", "user", "content[2:6]", 0, nil),
	), "g_fp", "")
	event("e5", fx.tenantA, "r4", pa, "security_check", "high", "flag", fx.t0.Add(2*time.Hour+time.Minute), findings(
		finding("prompt_injection", "prompt_injection", "high", "user", "content[0:9]", 0, nil),
		finding("secret", "api_key", "critical", "user", "content[10:22]", 0, nil),
	), "", "")
	event("e6", fx.tenantA, "r5", pa, "security_check", "high", "flag", fx.t0.Add(3*time.Hour+time.Minute), findings(
		finding("semantic_attack", "semantic_jailbreak", "high", "user", "content[0:12]", 0, nil),
	), "g_dev", "")
	event("e6b", fx.tenantA, "r9", pa, "security_check", "high", "flag", fx.t0.Add(4*time.Hour+time.Minute), findings(
		finding("semantic_attack", "semantic_jailbreak", "high", "user", "content[0:12]", 0, nil),
	), "g_dev", "")
	event("e7", fx.tenantA, "r6", pb, "security_check", "medium", "flag", now.Add(-20*time.Hour+time.Minute),
		map[string]any{"category": "legacy_risk", "rule_id": "legacy_rule", "redacted_evidence": "旧格式命中"}, "", "")
	event("e8", fx.tenantA, "r7", "project_upgrade_verify_"+suffix, "security_check", "high", "flag", now.Add(-10*time.Hour+time.Minute), findings(
		finding("prompt_injection", "prompt_injection", "high", "user", "content[0:9]", 0, nil),
	), "", "")
	event("e9", fx.tenantA, "r1", pa, "security_check", "high", "flag", fx.t0.Add(3*time.Minute), findings(
		finding("pii", "email", "high", "user", "content[30:40]", 3, map[string]any{"exception_id": "exc1"}),
	), "", "")
	event("e10", fx.tenantA, "r2", pa, "security_check", "medium", "flag", fx.t0.Add(time.Hour+2*time.Minute), findings(
		finding("pii", "phone_cn", "medium", "user", "content[5:16]", 1, map[string]any{"suppressed": true}),
	), "", "")
	event("e11", fx.tenantA, "r1", pa, "security_check", "critical", "flag", fx.t0.Add(4*time.Minute), findings(
		map[string]any{"type": "agent", "category": "agent_detected", "rule_type": "agent_detect", "action": "audit", "severity": "critical"},
	), "", "")
	event("e12", fx.tenantA, "r3", pb, "security_check", "medium", "flag", now.Add(-49*time.Hour), findings(
		finding("pii", "email", "medium", "user", "content[1:5]", 0, nil),
	), "", "ck1")
	event("e13", fx.tenantA, "r2", pa, "security_check", "low", "flag", fx.t0.Add(time.Hour+3*time.Minute), findings(
		finding("pii", "id_card_cn", "low", "user", "content[0:18]", 0, map[string]any{"rule_type": "hard_floor"}),
	), "", "")
	event("e14", fx.tenantA, "", "", "tool_execution_risk", "high", "flag", now.Add(-5*time.Hour), map[string]any{
		"source": "agent_endpoint", "risk_level": "high", "decision": "alert", "agent_event_id": "ae1", "endpoint_id": "ep1",
		"session_id": "as1", "event_type": "tool.pre", "tool_use_id": "tu1", "tool_name": "Bash"}, "", "")
	event("e15", fx.tenantA, "r8", pa, "security_check", "medium", "flag", now.Add(-2*time.Hour+time.Minute), findings(
		finding("pii", "email", "medium", "user", "content[1:5]", 0, nil),
		finding("catalog_policy", "confidential_keyword", "high", "user", "content[9:15]", 0, nil),
	), "", "")
	event("eb1", fx.tenantB, "rb1", id("acs_pc"), "security_check", "high", "flag", fx.t0.Add(time.Minute), findings(
		finding("pii", "email", "high", "user", "content[1:5]", 0, nil),
		finding("secret", "api_key", "high", "user", "content[6:9]", 0, nil),
	), "", "")
	exec(`INSERT INTO audit_dispositions(tenant_id,subject_type,subject_id,status,operator_id,operator_name) VALUES
 ($1,'security_event',$2,'resolved','u','甲'),($1,'request',$3,'false_positive','u','甲')`, fx.tenantA, id("e2"), id("r6"))
	// 租户 A 模拟升级前的历史：有回填行、没有排队条目，靠回填建出物化结果；租户 B 只靠触发器。
	exec(`DELETE FROM alert_case_dirty WHERE tenant_id=$1`, fx.tenantA)
	exec(`INSERT INTO alert_case_backfill(tenant_id) VALUES($1) ON CONFLICT (tenant_id) DO UPDATE SET done=FALSE,cursor_event_id=''`, fx.tenantA)

	fx.mutate = func(t *testing.T, ctx context.Context) {
		t.Helper()
		// 案件处置：一个用早于最新证据的快照（应回到待处置），一个用当前快照。
		page, err := (&AlertOccurrenceRepository{db: db, caseStoreDisabled: true}).List(ctx, AlertOccurrenceFilter{TenantID: fx.tenantA, Grouping: "cases", IncludeSuppressed: true, IncludeDevTraffic: true, Limit: 100})
		if err != nil || len(page.Items) < 3 {
			t.Fatalf("list cases for dispositions: %v", err)
		}
		exec(`INSERT INTO audit_dispositions(tenant_id,subject_type,subject_id,status,operator_id,operator_name,case_seen_through) VALUES
 ($1,'alert_case',$2,'resolved','u','甲',$4),($1,'alert_case',$3,'false_positive','u','甲',now())`,
			fx.tenantA, page.Items[0].CaseID, page.Items[1].CaseID, fx.t0.Add(-time.Hour))
		// 已有案件来了新证据；新命中进普通案件。
		event("e20", fx.tenantA, "r1", pa, "security_check", "critical", "block", now.Add(-time.Minute), findings(
			finding("pii", "email", "critical", "user", "content[50:60]", 5, nil),
		), "g_open", "")
		exec(`UPDATE internal_keys SET traffic_class='' WHERE id=$1`, id("k_eval"))
		exec(`UPDATE internal_keys SET traffic_class='evaluation' WHERE id=$1`, id("k_code"))
		exec(`UPDATE alert_groups SET status='open' WHERE id=$1`, id("g_fp"))
		exec(`DELETE FROM security_events WHERE id=$1`, id("e9"))
		exec(`UPDATE request_logs SET session_id='s9' WHERE id=$1`, id("r3"))
		exec(`UPDATE request_logs SET user_id=$1 WHERE id=$2`, fx.tenantA+"_u1", id("r8"))
		exec(`UPDATE access_content_logs SET conversation_id='conv6b' WHERE request_id=$1`, id("r6"))
		exec(`UPDATE security_events SET conversation_key='ck2' WHERE id=$1`, id("e12"))
		exec(`INSERT INTO audit_dispositions(tenant_id,subject_type,subject_id,status,operator_id,operator_name) VALUES ($1,'security_event',$2,'false_positive','u','甲')`, fx.tenantA, id("e15"))
		exec(`UPDATE audit_dispositions SET status='open' WHERE tenant_id=$1 AND subject_type='security_event' AND subject_id=$2`, fx.tenantA, id("e2"))
		// 开发作用域告警组里混进客户流量后不再折叠。
		event("e21", fx.tenantA, "r2", pa, "security_check", "high", "flag", now.Add(-2*time.Minute), findings(
			finding("semantic_attack", "semantic_jailbreak", "high", "user", "content[0:12]", 0, nil),
		), "g_dev", "")
		event("eb2", fx.tenantB, "rb1", id("acs_pc"), "security_check", "low", "flag", now.Add(-time.Minute), findings(
			finding("pii", "phone_cn", "low", "user", "content[1:12]", 0, nil),
		), "", "")
	}
	fx.mutateNarrow = func(t *testing.T, ctx context.Context) {
		t.Helper()
		exec(`INSERT INTO audit_dispositions(tenant_id,subject_type,subject_id,status,operator_id,operator_name) VALUES ($1,'security_event',$2,'resolved','u','甲')`, fx.tenantA, id("e11"))
		event("e22", fx.tenantA, "r1", pa, "security_check", "high", "flag", now.Add(-30*time.Second), findings(
			finding("pii", "phone_cn", "high", "user", "content[3:14]", 0, nil),
		), "g_open", "")
	}
	return fx
}
