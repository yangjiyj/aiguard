package repository

import (
	"context"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/alertcounter"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
	"time"
)

func qualityRequest(t *testing.T, db *pgxpool.Pool, tenant, request string) {
	t.Helper()
	_, err := db.Exec(context.Background(), `INSERT INTO request_logs(id,request_id,tenant_id,project_id,endpoint_type,request_status) VALUES($1,$1,$2,'project_default','chat_completions','success') ON CONFLICT DO NOTHING`, request, tenant)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSecurityQualityReviewStatesPostgres(t *testing.T) {
	db, tenant := setupAlertGroupTestDB(t)
	t.Setenv("SECEVENT_ALERT_GRACE_SECONDS", "0")
	t.Setenv("SECEVENT_REVIEW_PENDING_TIMEOUT_SECONDS", "60")
	type item struct {
		name, summary, kind, severity string
		age                           time.Duration
		want                          bool
	}
	cases := []item{
		{"missing", `{}`, "security_check", "high", time.Second, true},
		{"null", `{"review_state":null}`, "security_check", "high", time.Second, true},
		{"empty", `{"review_state":""}`, "security_check", "high", time.Second, true},
		{"complete", `{"review_state":"confirmed"}`, "security_check", "high", time.Second, true},
		{"pending", `{"review_state":"review_pending"}`, "security_check", "high", time.Second, false},
		{"expired", `{"review_state":"review_pending"}`, "security_check", "high", 2 * time.Minute, true},
		{"fault", `{"category":"system","counts_as_security_finding":false}`, "security_check_failed", "low", time.Second, true},
	}
	expected := map[string]bool{}
	for _, c := range cases {
		id := tenant + "_" + c.name
		qualityRequest(t, db, tenant, id)
		_, err := db.Exec(context.Background(), `INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary,created_at) VALUES($1,$1,$2,'project_default',$3,$4,'audit',$5::jsonb,$6)`, id, tenant, c.kind, c.severity, c.summary, time.Now().Add(-c.age))
		if err != nil {
			t.Fatal(err)
		}
		expected[id] = c.want
	}
	events, err := NewSecurityEventRepository(db).ListUnalerted(context.Background(), 10000)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, e := range events {
		if e.TenantID == tenant {
			found[e.ID] = true
		}
	}
	for id, want := range expected {
		if found[id] != want {
			t.Errorf("%s eligible=%v want=%v", id, found[id], want)
		}
	}
}

func TestSecurityQualityDistinctCountersPostgres(t *testing.T) {
	for _, tc := range []struct {
		name          string
		conversations []string
		occurrence    bool
		want          int
	}{
		{"same_session", []string{"chat1", "chat1"}, false, 1},
		{"two_sessions", []string{"chat1", "chat2"}, false, 2},
		{"without_session", []string{"", ""}, false, 2},
		{"mixed_fact_paths", []string{"chat1", "chat1"}, true, 1},
		{"representative_without_facts", nil, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, tenant := setupAlertGroupTestDB(t)
			ctx := context.Background()
			repo := NewAlertGroupRepository(db)
			rep := tenant + "_r0"
			qualityRequest(t, db, tenant, rep)
			group, _, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{TenantID: tenant, ProjectID: "project_default", GroupKey: tc.name, Severity: "high", AlertType: "security_event", Title: "synthetic risk", RepresentativeEventID: tenant + "_e0", RequestID: rep, PrincipalKey: "subject1", OccurredAt: time.Now(), BodyJSON: map[string]any{}})
			if err != nil {
				t.Fatal(err)
			}
			for i, conv := range tc.conversations {
				request := fmt.Sprintf("%s_r%d", tenant, i)
				qualityRequest(t, db, tenant, request)
				if tc.occurrence && i > 0 {
					for n := 0; n < 2; n++ {
						_, err = db.Exec(ctx, `INSERT INTO security_event_occurrences(tenant_id,representative_event_id,request_id,principal_key,conversation_key,alert_group_id,context_key) VALUES($1,$2,$3,'subject1',$4,$5,'synthetic') ON CONFLICT DO NOTHING`, tenant, tenant+"_e0", request, conv, group.ID)
					}
				} else {
					_, err = db.Exec(ctx, `INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,conversation_key,principal_key,alert_group_id) VALUES($1,$2,$3,'project_default','security_check','high','audit',$4,'subject1',$5)`, fmt.Sprintf("%s_e%d", tenant, i), request, tenant, conv, group.ID)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 3; i++ {
				occ, users, err := repo.RecalcCounters(ctx, tenant, group.ID)
				if err != nil {
					t.Fatal(err)
				}
				if len(tc.conversations) > 0 {
					gocc, gusers, gerr := alertcounter.RecalculateRepresentative(ctx, db, tenant, tenant+"_e0")
					if gerr != nil || gocc != occ || gusers != users {
						t.Errorf("gateway recount=(%d,%d,%v) CP=(%d,%d)", gocc, gusers, gerr, occ, users)
					}
				}
				if occ != tc.want || users != 1 {
					t.Errorf("recalc %d got (%d,%d), want (%d,1)", i, occ, users, tc.want)
				}
			}
		})
	}
}

func TestSecurityQualityRecountWaitsForCommittedFactsPostgres(t *testing.T) {
	db, tenant := setupAlertGroupTestDB(t)
	ctx := context.Background()
	repo := NewAlertGroupRepository(db)
	rep := tenant + "_rep"
	qualityRequest(t, db, tenant, rep)
	group, _, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{TenantID: tenant, ProjectID: "project_default", GroupKey: "concurrent", Severity: "high", AlertType: "security_event", Title: "test", RequestID: rep, PrincipalKey: "a", OccurredAt: time.Now(), BodyJSON: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	other := tenant + "_other"
	qualityRequest(t, db, tenant, other)
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT id FROM alert_groups WHERE id=$1 FOR UPDATE`, group.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,principal_key,alert_group_id) VALUES($1,$1,$2,'project_default','security_check','high','audit','b',$3)`, other, tenant, group.ID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		o, u, e := repo.RecalcCounters(ctx, tenant, group.ID)
		if e == nil && (o != 2 || u != 2) {
			e = fmt.Errorf("counts=(%d,%d),want(2,2)", o, u)
		}
		done <- e
	}()
	select {
	case e := <-done:
		t.Fatalf("recount returned before writer committed: %v", e)
	case <-time.After(75 * time.Millisecond):
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("recount did not finish")
	}
}

func TestSecurityQualityUnlinkedRepresentativeUsesConversationPostgres(t *testing.T) {
	db, tenant := setupAlertGroupTestDB(t)
	ctx := context.Background()
	repo := NewAlertGroupRepository(db)
	rep := tenant + "_rep"
	qualityRequest(t, db, tenant, rep)
	group, _, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{TenantID: tenant, ProjectID: "project_default", GroupKey: "unlinked", Severity: "high", AlertType: "security_event", Title: "test", RequestID: rep, RepresentativeEventID: rep, PrincipalKey: "a", OccurredAt: time.Now(), BodyJSON: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,conversation_key,principal_key) VALUES($1,$1,$2,'project_default','security_check','high','audit','session','a')`, rep, tenant); err != nil {
		t.Fatal(err)
	}
	other := tenant + "_other"
	qualityRequest(t, db, tenant, other)
	if _, err = db.Exec(ctx, `INSERT INTO security_event_occurrences(tenant_id,representative_event_id,request_id,conversation_key,principal_key,context_key,alert_group_id) VALUES($1,$2,$3,'session','b','synthetic',$4)`, tenant, rep, other, group.ID); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		o, u, e := repo.RecalcCounters(ctx, tenant, group.ID)
		if e != nil || o != 1 || u != 2 {
			t.Fatalf("unlinked=(%d,%d,%v)", o, u, e)
		}
	}
	if _, err = db.Exec(ctx, `UPDATE security_events SET alert_group_id=$1 WHERE id=$2`, group.ID, rep); err != nil {
		t.Fatal(err)
	}
	o, u, e := repo.RecalcCounters(ctx, tenant, group.ID)
	if e != nil || o != 1 || u != 2 {
		t.Fatalf("linked=(%d,%d,%v)", o, u, e)
	}
	if _, _, e = repo.RecalcCounters(ctx, "unrelated", group.ID); e == nil {
		t.Fatal("cross-tenant recount succeeded")
	}
}
