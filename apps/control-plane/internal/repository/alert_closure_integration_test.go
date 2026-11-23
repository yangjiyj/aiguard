package repository

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"testing"
	"time"
)

func closureDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ALERT_CLOSURE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ALERT_CLOSURE_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "closure_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	q := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+q); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec(ctx, "DROP SCHEMA "+q+" CASCADE"); admin.Close() })
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	cfg.MaxConns = 2
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	for _, table := range []string{"alert_groups", "security_events", "security_event_occurrences", "request_logs", "audit_dispositions", "alert_inbox"} {
		if _, err = db.Exec(ctx, "CREATE TABLE "+pgx.Identifier{table}.Sanitize()+" (LIKE public."+pgx.Identifier{table}.Sanitize()+" INCLUDING ALL)"); err != nil {
			t.Fatal(err)
		}
	}
	return db
}
func putClosureEvent(t *testing.T, db *pgxpool.Pool, id, group, sev string, at time.Time) {
	t.Helper()
	_, err := db.Exec(context.Background(), `INSERT INTO security_events(id,tenant_id,project_id,request_id,event_type,severity,action_taken,created_at,alert_group_id,conversation_key) VALUES($1,'tenant-a','project-a',$1,'data_security',$3,'audit',$4,NULLIF($2,''),'conversation')`, id, group, sev, at)
	if err != nil {
		t.Fatal(err)
	}
}
func TestClosureRepresentativeKeepsSeverityEvidenceAndLatestTimeSeparate(t *testing.T) {
	db := closureDB(t)
	ctx := context.Background()
	r := NewAlertGroupRepository(db)
	now := time.Now().UTC().Truncate(time.Microsecond)
	putClosureEvent(t, db, "critical", "", "critical", now.Add(-time.Hour))
	in := AlertGroupUpsertInput{TenantID: "tenant-a", GroupKey: "same", Severity: "critical", AlertType: "secret", Title: "credential", RepresentativeEventID: "critical", RequestID: "critical", OccurredAt: now.Add(-time.Hour), BodyJSON: map[string]any{"rule_name": "credential"}}
	g, _, err := r.UpsertOpen(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.AttachEvent(ctx, "tenant-a", "critical", g.ID); err != nil {
		t.Fatal(err)
	}
	putClosureEvent(t, db, "email", g.ID, "low", now)
	in.Severity = "low"
	in.AlertType = "email"
	in.Title = "email"
	in.RepresentativeEventID = "email"
	in.RequestID = "email"
	in.OccurredAt = now
	in.BodyJSON = map[string]any{"rule_name": "email"}
	g, _, err = r.UpsertOpen(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if g.RepresentativeEventID != "critical" || g.Severity != "critical" || g.BodyJSON["rule_name"] != "credential" || !g.LastSeenAt.Equal(now) {
		t.Fatalf("group evidence mismatch: %+v", g)
	}
	rows, _, err := r.ListGroupEvents(ctx, "tenant-a", g.ID, AlertGroupEventListFilter{View: AlertGroupEventViewConversations})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].EventID != "critical" || rows[0].Severity != "critical" || !rows[0].LastSeenAt.Equal(now) {
		t.Fatalf("conversation attributes low event as critical: %+v", rows)
	}
}
func TestClosureDispositionAtomicallySilencesAndRevokes(t *testing.T) {
	db := closureDB(t)
	ctx := context.Background()
	groups := NewAlertGroupRepository(db)
	now := time.Now().UTC()
	putClosureEvent(t, db, "event", "", "medium", now)
	group, _, err := groups.UpsertOpen(ctx, AlertGroupUpsertInput{TenantID: "tenant-a", GroupKey: "scoped-key", Severity: "medium", AlertType: "security_event", Title: "sample", RepresentativeEventID: "event", RequestID: "event", OccurredAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if err = groups.AttachEvent(ctx, "tenant-a", "event", group.ID); err != nil {
		t.Fatal(err)
	}
	repo := NewAuditDispositionRepository(db)
	save := repo.Upsert
	if linked, ok := any(repo).(interface {
		UpsertLinked(context.Context, *AuditDisposition) (*AuditDisposition, error)
	}); ok {
		save = linked.UpsertLinked
	}
	d := &AuditDisposition{TenantID: "tenant-a", SubjectType: "security_event", SubjectID: "event", Status: "false_positive", Note: "synthetic sample", OperatorID: "operator"}
	if _, err = save(ctx, d); err != nil {
		t.Fatal(err)
	}
	keys, err := groups.ListFalsePositiveGroupKeys(ctx, []string{"tenant-a", "tenant-b"}, now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !keys["tenant-a"][ScopedAlertGroupKey("scoped-key", "", "")] || keys["tenant-b"][ScopedAlertGroupKey("scoped-key", "", "")] {
		t.Fatalf("linked disposition not effective/scoped: %v", keys)
	}
	// Expired group decisions cannot silently extend their notification scope.
	if _, err = db.Exec(ctx, `UPDATE alert_groups SET false_positive_at=NOW()-INTERVAL '31 days' WHERE id=$1`, group.ID); err != nil {
		t.Fatal(err)
	}
	expired, err := groups.ListFalsePositiveGroupKeys(ctx, []string{"tenant-a"}, time.Now().AddDate(0, 0, -30))
	if err != nil || len(expired["tenant-a"]) != 0 {
		t.Fatalf("expired disposition still active: %v %v", expired, err)
	}
	if _, err = save(ctx, d); err != nil {
		t.Fatal(err)
	}
	d.Status = "open"
	if _, err = save(ctx, d); err != nil {
		t.Fatal(err)
	}
	keys, err = groups.ListFalsePositiveGroupKeys(ctx, []string{"tenant-a"}, now.Add(-time.Minute))
	if err != nil || keys["tenant-a"][ScopedAlertGroupKey("scoped-key", "", "")] {
		t.Fatalf("revoked disposition still suppresses: %v %v", keys, err)
	}
	d.TenantID = "tenant-b"
	d.Status = "false_positive"
	if _, err = save(ctx, d); err == nil {
		t.Fatal("cross tenant event disposition accepted")
	}
	d.TenantID = "tenant-a"
	if _, err = db.Exec(ctx, `ALTER TABLE alert_groups ADD CONSTRAINT inject_disposition_failure CHECK(status <> 'false_positive')`); err != nil {
		t.Fatal(err)
	}
	if _, err = save(ctx, d); err == nil {
		t.Fatal("expected group write failure")
	}
	var status string
	if err = db.QueryRow(ctx, `SELECT status FROM audit_dispositions WHERE subject_id='event' AND tenant_id='tenant-a'`).Scan(&status); err != nil || status != "open" {
		t.Fatalf("partial audit write survived group failure: %s %v", status, err)
	}
	var count int
	if err = db.QueryRow(ctx, `SELECT COUNT(*) FROM security_events WHERE id='event'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("disposition destroyed security evidence")
	}
}

func TestAlertSeverityRankUnderstandsStoredMediumAndLow(t *testing.T) {
	if severityRank("medium") <= severityRank("low") || severityRank("low") <= 0 {
		t.Fatal("stored severities cannot rank representative evidence")
	}
}

func TestClosureInboxRetainsDominantEvidenceButRefreshesCounters(t *testing.T) {
	db := closureDB(t)
	ctx := context.Background()
	repo := NewAlertInboxRepository(db)
	first := &AlertInboxItem{TenantID: "tenant-a", Severity: "medium", Type: "security_event", Title: "dominant risk", TargetURL: "/security-events/dominant", BodyJSON: map[string]any{"rule_name": "dominant", "distinct_occurrences": 1, "affected_users": 1, "occurrence_count": 1}}
	if _, err := repo.UpsertByGroup(ctx, first, "same"); err != nil {
		t.Fatal(err)
	}
	second := &AlertInboxItem{TenantID: "tenant-a", Severity: "low", Type: "security_event", Title: "email", TargetURL: "/security-events/email", BodyJSON: map[string]any{"rule_name": "email", "distinct_occurrences": 4, "affected_users": 3, "occurrence_count": 7}}
	if _, err := repo.UpsertByGroup(ctx, second, "same"); err != nil {
		t.Fatal(err)
	}
	var sev, title, rule string
	var occ, users, raw int
	err := db.QueryRow(ctx, `SELECT severity,title,body_json->>'rule_name',(body_json->>'distinct_occurrences')::int,(body_json->>'affected_users')::int,(body_json->>'occurrence_count')::int FROM alert_inbox WHERE tenant_id='tenant-a'`).Scan(&sev, &title, &rule, &occ, &users, &raw)
	if err != nil {
		t.Fatal(err)
	}
	if sev != "medium" || title != "dominant risk" || rule != "dominant" || occ != 4 || users != 3 || raw != 7 {
		t.Fatalf("inbox representative/counter mismatch: %s %s %s %d %d %d", sev, title, rule, occ, users, raw)
	}
	// A newer higher-risk representative must also keep authoritative counters;
	// mutating the input map must not turn the supplied total into delivery +1.
	third := &AlertInboxItem{TenantID: "tenant-a", Severity: "critical", Type: "security_event", Title: "credential", BodyJSON: map[string]any{"rule_name": "credential", "distinct_occurrences": 9, "affected_users": 4, "occurrence_count": 20}}
	if _, err = repo.UpsertByGroup(ctx, third, "same"); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, `SELECT (body_json->>'occurrence_count')::int FROM alert_inbox WHERE tenant_id='tenant-a'`).Scan(&raw); err != nil || raw != 20 {
		t.Fatalf("authoritative count replaced by delivery count: %d %v", raw, err)
	}

}

func TestClosureSchemaAcceptsOperationalNotificationTypes(t *testing.T) {
	db := closureDB(t)
	ctx := context.Background()
	groups := NewAlertGroupRepository(db)
	inbox := NewAlertInboxRepository(db)
	for _, kind := range []string{"runtime_fault", "access_governance"} {
		if _, _, err := groups.UpsertOpen(ctx, AlertGroupUpsertInput{TenantID: "tenant-a", GroupKey: kind, Severity: "low", AlertType: kind, Title: kind}); err != nil {
			t.Fatalf("group type %s rejected: %v", kind, err)
		}
		if _, err := inbox.UpsertByGroup(ctx, &AlertInboxItem{ID: kind, TenantID: "tenant-a", Severity: "low", Type: kind, Title: kind}, kind); err != nil {
			t.Fatalf("notification type %s rejected: %v", kind, err)
		}
	}
}

func TestClosureDailyCountsUseDominantRiskAcrossFindingOrder(t *testing.T) {
	db := closureDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	from := now.Truncate(24 * time.Hour)
	summaries := []string{
		`{"category":"email","findings":[{"type":"pii","category":"email","severity":"low","confidence":0.99},{"type":"semantic_attack","category":"semantic_harassment","severity":"critical","confidence":1},{"type":"secret","category":"api_key","severity":"critical","confidence":0.8}]}`,
		`{"category":"email","findings":[{"type":"secret","category":"api_key","severity":"critical","confidence":0.8},{"type":"pii","category":"email","severity":"low","confidence":0.99},{"type":"semantic_attack","category":"semantic_harassment","severity":"critical","confidence":1}]}`,
	}
	for i, summary := range summaries {
		id := []string{"daily-a", "daily-b"}[i]
		putClosureEvent(t, db, id, "", "critical", now)
		if _, err := db.Exec(ctx, `UPDATE security_events SET matched_summary=$2::jsonb WHERE id=$1`, id, summary); err != nil {
			t.Fatal(err)
		}
	}
	counts, err := NewSecurityEventRepository(db).CountAlertableDaily(ctx, []string{"tenant-a"}, from, from.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != 1 || counts[0].Dimension != "api_key" || counts[0].Count != 2 {
		t.Fatalf("daily aggregation still attributes mixed critical risks to email: %+v", counts)
	}
}

func TestClosureUnreadRepeatFoldsAndNewOccurrenceAfterReadReopensInbox(t *testing.T) {
	db := closureDB(t)
	ctx := context.Background()
	repo := NewAlertInboxRepository(db)
	first := &AlertInboxItem{ID: "notice-1", TenantID: "tenant-a", Severity: "high", Type: "security_event", Title: "synthetic", BodyJSON: map[string]any{"event_id": "event-1", "occurrence_count": 1}}
	if created, err := repo.UpsertByGroup(ctx, first, "group"); err != nil || !created {
		t.Fatalf("first notice: %v %v", created, err)
	}
	repeat := &AlertInboxItem{ID: "notice-2", TenantID: "tenant-a", Severity: "high", Type: "security_event", Title: "synthetic", BodyJSON: map[string]any{"event_id": "event-1", "occurrence_count": 1}}
	if created, err := repo.UpsertByGroup(ctx, repeat, "group"); err != nil || created {
		t.Fatalf("duplicate unread delivery: %v %v", created, err)
	}
	if _, err := db.Exec(ctx, `UPDATE alert_inbox SET read_at=NOW() WHERE tenant_id='tenant-a' AND id='notice-1'`); err != nil {
		t.Fatal(err)
	}
	next := &AlertInboxItem{ID: "notice-3", TenantID: "tenant-a", Severity: "high", Type: "security_event", Title: "synthetic", BodyJSON: map[string]any{"event_id": "event-2", "occurrence_count": 2}}
	if created, err := repo.UpsertByGroup(ctx, next, "group"); err != nil || !created {
		t.Fatalf("new occurrence after read lost: %v %v", created, err)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_inbox WHERE tenant_id='tenant-a'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("inbox recurrence row count=%d err=%v", count, err)
	}
}
