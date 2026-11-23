package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setupAlertGroupTestDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	tenantID := fmt.Sprintf("tenant_ag_%d", time.Now().UnixNano())
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$2,'enterprise','active', TRUE)`, tenantID, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM security_events WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM security_event_occurrences WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM alert_groups WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM request_logs WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM projects WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})
	if _, err := db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS security_event_occurrences (
			tenant_id TEXT NOT NULL,
			representative_event_id TEXT NOT NULL,
			request_id TEXT NOT NULL,
			principal_key TEXT,
			conversation_key TEXT,
			context_key TEXT NOT NULL DEFAULT '',
			alert_group_id TEXT,
			occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (tenant_id, representative_event_id, request_id)
		)
	`); err != nil {
		t.Fatalf("ensure occurrence ledger: %v", err)
	}
	if _, err := db.Exec(ctx, `ALTER TABLE security_event_occurrences ADD COLUMN IF NOT EXISTS context_key TEXT NOT NULL DEFAULT ''`); err != nil {
		t.Fatalf("ensure occurrence context key: %v", err)
	}
	return db, tenantID
}

func TestAlertGroupUpsertOpenCreatesWhenNoExistingGroup(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()
	firstSeen := time.Date(2026, 6, 19, 13, 40, 0, 0, time.UTC)

	group, created, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{
		TenantID:              tenantID,
		ProjectID:             "project_default",
		GroupKey:              "first-runtime-finding",
		Severity:              "high",
		AlertType:             "security_event",
		Title:                 "首次运行时攻击告警",
		RepresentativeEventID: "evt_first",
		RequestID:             "req_first",
		OccurredAt:            firstSeen,
		BodyJSON:              map[string]any{"event_id": "evt_first"},
	})
	if err != nil {
		t.Fatalf("first UpsertOpen should create instead of returning not found: %v", err)
	}
	if !created {
		t.Fatal("first UpsertOpen should report created=true")
	}
	if group == nil || group.ID == "" || group.GroupKey != "first-runtime-finding" || group.OccurrenceCount != 1 {
		t.Fatalf("created group lost input context: %+v", group)
	}
}

func TestAlertGroupUpsertOpenFoldsSameTenantGroupKey(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()
	firstSeen := time.Date(2026, 6, 18, 10, 0, 0, 0, time.UTC)

	first, created, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{
		TenantID:              tenantID,
		ProjectID:             "project_default",
		GroupKey:              "secret|sha256:abc",
		Severity:              "high",
		AlertType:             "security_event",
		Title:                 "疑似密钥泄露",
		RepresentativeEventID: "sec_1",
		RequestID:             "req_1",
		OccurredAt:            firstSeen,
		BodyJSON:              map[string]any{"event_id": "sec_1"},
	})
	if err != nil || !created {
		t.Fatalf("first UpsertOpen created=%v err=%v", created, err)
	}

	second, created, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{
		TenantID:              tenantID,
		ProjectID:             "project_default",
		GroupKey:              "secret|sha256:abc",
		Severity:              "critical",
		AlertType:             "security_event",
		Title:                 "疑似密钥泄露升级",
		RepresentativeEventID: "sec_2",
		RequestID:             "req_2",
		OccurredAt:            firstSeen.Add(5 * time.Minute),
		BodyJSON:              map[string]any{"event_id": "sec_2"},
	})
	if err != nil || created {
		t.Fatalf("second UpsertOpen created=%v err=%v", created, err)
	}
	if second.ID != first.ID {
		t.Fatalf("same open group should fold into id %s, got %s", first.ID, second.ID)
	}
	if second.OccurrenceCount != 2 || second.Severity != "critical" || second.RepresentativeEventID != "sec_2" {
		t.Fatalf("folded group not refreshed: %+v", second)
	}
}

func TestAlertGroupClaimsPendingFingerprintOccurrencesIdempotently(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()
	firstSeen := time.Date(2026, 7, 25, 9, 0, 0, 0, time.UTC)
	lastSeen := firstSeen.Add(2 * time.Minute)

	for index, occurredAt := range []time.Time{firstSeen.Add(time.Minute), lastSeen} {
		if _, err := db.Exec(ctx, `
			INSERT INTO security_event_occurrences (
				tenant_id, representative_event_id, request_id, principal_key,
				conversation_key, context_key, occurred_at
			) VALUES ($1, 'evt_first', $2, $3, $4, 'stable-context', $5)
		`, tenantID, fmt.Sprintf("req_%d", index+2), fmt.Sprintf("user_%d", index+2), fmt.Sprintf("conv_%d", index+2), occurredAt); err != nil {
			t.Fatalf("insert pending occurrence %d: %v", index+2, err)
		}
	}

	group, created, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{
		TenantID:              tenantID,
		ProjectID:             "project_default",
		GroupKey:              "prompt_injection|stable-context",
		Severity:              "high",
		AlertType:             "security_event",
		Title:                 "语义攻击",
		RepresentativeEventID: "evt_first",
		RequestID:             "req_1",
		PrincipalKey:          "user_1",
		OccurredAt:            firstSeen,
	})
	if err != nil || !created {
		t.Fatalf("create group with pending occurrences: created=%v err=%v", created, err)
	}
	if group.OccurrenceCount != 3 || group.DistinctOccurrences != 3 || group.AffectedUsers != 3 {
		t.Fatalf("pending occurrences not claimed: %+v", group)
	}
	if !group.LastSeenAt.Equal(lastSeen) {
		t.Fatalf("last_seen_at=%s want %s", group.LastSeenAt, lastSeen)
	}

	reconciled, err := repo.ReconcileOccurrences(ctx, tenantID, group.ID, "evt_first")
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if reconciled.OccurrenceCount != 3 || reconciled.DistinctOccurrences != 3 || reconciled.AffectedUsers != 3 {
		t.Fatalf("reconcile must be idempotent: %+v", reconciled)
	}
}

func TestAlertGroupUpsertSeparatesTenants(t *testing.T) {
	db, tenantA := setupAlertGroupTestDB(t)
	_, tenantB := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()
	input := AlertGroupUpsertInput{ProjectID: "project_default", GroupKey: "same-key", Severity: "high", AlertType: "security_event", Title: "同名风险", OccurredAt: time.Now().UTC()}

	input.TenantID = tenantA
	groupA, createdA, err := repo.UpsertOpen(ctx, input)
	if err != nil || !createdA {
		t.Fatalf("tenant A upsert created=%v err=%v", createdA, err)
	}
	input.TenantID = tenantB
	groupB, createdB, err := repo.UpsertOpen(ctx, input)
	if err != nil || !createdB {
		t.Fatalf("tenant B upsert created=%v err=%v", createdB, err)
	}
	if groupA.ID == groupB.ID || groupA.TenantID == groupB.TenantID {
		t.Fatalf("tenants should have independent groups: A=%+v B=%+v", groupA, groupB)
	}
}

func TestAlertGroupResolvedGroupDoesNotBlockNewOpenGroup(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()
	input := AlertGroupUpsertInput{TenantID: tenantID, ProjectID: "project_default", GroupKey: "repeat-after-close", Severity: "high", AlertType: "security_event", Title: "复发风险", OccurredAt: time.Now().UTC()}

	closed, _, err := repo.UpsertOpen(ctx, input)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := repo.UpdateStatus(ctx, tenantID, closed.ID, AlertGroupStatusResolved, "user_1", "已处理"); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	reopened, created, err := repo.UpsertOpen(ctx, input)
	if err != nil || !created {
		t.Fatalf("upsert after resolved created=%v err=%v", created, err)
	}
	if reopened.ID == closed.ID || reopened.Status != AlertGroupStatusOpen {
		t.Fatalf("resolved group should not absorb recurrence: closed=%+v reopened=%+v", closed, reopened)
	}
}

func TestAlertGroupListFiltersStatusSeverityAndTenant(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()
	_, otherTenant := setupAlertGroupTestDB(t)

	_, _, _ = repo.UpsertOpen(ctx, AlertGroupUpsertInput{TenantID: tenantID, GroupKey: "high-open", Severity: "high", AlertType: "security_event", Title: "高危", OccurredAt: time.Now().UTC()})
	resolved, _, _ := repo.UpsertOpen(ctx, AlertGroupUpsertInput{TenantID: tenantID, GroupKey: "critical-resolved", Severity: "critical", AlertType: "security_event", Title: "已处理", OccurredAt: time.Now().UTC()})
	_, _ = repo.UpdateStatus(ctx, tenantID, resolved.ID, AlertGroupStatusResolved, "user_1", "done")
	_, _, _ = repo.UpsertOpen(ctx, AlertGroupUpsertInput{TenantID: otherTenant, GroupKey: "high-open", Severity: "high", AlertType: "security_event", Title: "其他租户", OccurredAt: time.Now().UTC()})

	groups, err := repo.List(ctx, AlertGroupListFilter{TenantID: tenantID, Status: AlertGroupStatusOpen, Severity: "high", Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(groups) != 1 || groups[0].TenantID != tenantID || groups[0].Status != AlertGroupStatusOpen || groups[0].Severity != "high" {
		t.Fatalf("unexpected filtered groups: %+v", groups)
	}
}

func TestListGroupEventsConversationViewAndPhysicalDrilldown(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()
	startedAt := time.Date(2026, 7, 28, 8, 0, 0, 0, time.UTC)
	userID := "user_" + tenantID
	projectID := "project_" + tenantID
	if _, err := db.Exec(ctx, `
		INSERT INTO users (id, tenant_id, username, role, status)
		VALUES ($1, $2, $1, 'developer', 'active')
	`, userID, tenantID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO projects (id, tenant_id, name, owner_user_id, status)
		VALUES ($1, $2, $1, $3, 'active')
	`, projectID, tenantID, userID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	group, _, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{
		TenantID:              tenantID,
		ProjectID:             projectID,
		GroupKey:              "conversation-collapse",
		Severity:              "high",
		AlertType:             "security_event",
		Title:                 "长任务安全告警",
		RepresentativeEventID: "evt_conv_a_1",
		RequestID:             "req_conv_a_1",
		OccurredAt:            startedAt,
		BodyJSON:              map[string]any{"event_id": "evt_conv_a_1"},
	})
	if err != nil {
		t.Fatalf("create alert group: %v", err)
	}

	rows := []struct {
		id              string
		requestID       string
		conversationKey string
		severity        string
		action          string
		createdAt       time.Time
	}{
		{
			id:              "evt_conv_a_1",
			requestID:       "req_conv_a_1",
			conversationKey: "ck_a",
			severity:        "high",
			action:          "mask",
			createdAt:       startedAt,
		},
		{
			id:              "evt_conv_a_2",
			requestID:       "req_conv_a_2",
			conversationKey: "ck_a",
			severity:        "critical",
			action:          "audit",
			createdAt:       startedAt.Add(time.Minute),
		},
		{
			id:              "evt_conv_b_1",
			requestID:       "req_conv_b_1",
			conversationKey: "ck_b",
			severity:        "medium",
			action:          "security_audit_only",
			createdAt:       startedAt.Add(2 * time.Minute),
		},
		{
			id:        "evt_request_only",
			requestID: "req_request_only",
			severity:  "low",
			action:    "security_audit_only",
			createdAt: startedAt.Add(3 * time.Minute),
		},
	}
	for _, row := range rows {
		if _, err := db.Exec(ctx, `
			INSERT INTO request_logs (
				id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status, created_at
			)
			VALUES ($1, $2, $3, $4, $5, 'chat_completions', 'success', $6)
		`, "log_"+row.id, row.requestID, tenantID, projectID, userID, row.createdAt); err != nil {
			t.Fatalf("insert request log %s: %v", row.requestID, err)
		}
		if _, err := db.Exec(ctx, `
			INSERT INTO security_events (
				id, request_id, tenant_id, project_id, event_type, severity,
				action_taken, matched_summary, created_at, principal_key, user_id,
				conversation_key, alert_group_id
			)
			VALUES ($1, $2, $3, $4, 'security_check', $5, $6, '{}'::jsonb, $7, $8, $9, $10, $11)
		`, row.id, row.requestID, tenantID, projectID, row.severity, row.action, row.createdAt, userID, userID, row.conversationKey, group.ID); err != nil {
			t.Fatalf("insert event %s: %v", row.id, err)
		}
	}

	conversations, total, err := repo.ListGroupEvents(ctx, tenantID, group.ID, AlertGroupEventListFilter{
		View:  AlertGroupEventViewConversations,
		Limit: 20,
	})
	if err != nil {
		t.Fatalf("list conversations: %v", err)
	}
	if total != 3 || len(conversations) != 3 {
		t.Fatalf("expected 3 conversation rows, total=%d items=%d", total, len(conversations))
	}
	var conversationA *AlertGroupEvent
	for _, item := range conversations {
		if item.RowKey == "ck_a" {
			conversationA = item
			break
		}
	}
	if conversationA == nil || conversationA.EventCount != 2 || conversationA.Severity != "critical" || conversationA.ActionTaken != "mask" {
		t.Fatalf("unexpected ck_a aggregate: %+v", conversationA)
	}

	events, eventTotal, err := repo.ListGroupEvents(ctx, tenantID, group.ID, AlertGroupEventListFilter{
		View:            AlertGroupEventViewEvents,
		ConversationKey: "ck_a",
		Limit:           20,
	})
	if err != nil {
		t.Fatalf("list physical events: %v", err)
	}
	if eventTotal != 2 || len(events) != 2 {
		t.Fatalf("expected 2 physical events, total=%d items=%d", eventTotal, len(events))
	}
}
func TestAlertGroupUpsertKeepsHigherRiskRepresentative(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()
	firstSeen := time.Date(2026, 8, 4, 15, 0, 0, 0, time.UTC)

	first, created, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{
		TenantID:              tenantID,
		ProjectID:             "project_default",
		GroupKey:              "representative-risk-order",
		Severity:              "critical",
		AlertType:             "security_event",
		Title:                 "real secret leak",
		RepresentativeEventID: "evt_critical",
		RequestID:             "req_critical",
		OccurredAt:            firstSeen,
		BodyJSON:              map[string]any{"event_id": "evt_critical", "class_key": "openai_key"},
	})
	if err != nil || !created {
		t.Fatalf("critical representative create failed: created=%v err=%v", created, err)
	}

	updated, created, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{
		TenantID:              tenantID,
		ProjectID:             "project_default",
		GroupKey:              "representative-risk-order",
		Severity:              "high",
		AlertType:             "security_event",
		Title:                 "low-risk observation",
		RepresentativeEventID: "evt_observation",
		RequestID:             "req_observation",
		OccurredAt:            firstSeen.Add(time.Minute),
		BodyJSON:              map[string]any{"event_id": "evt_observation", "class_key": "phone_cn"},
	})
	if err != nil || created {
		t.Fatalf("lower-risk fold failed: created=%v err=%v", created, err)
	}
	if updated.ID != first.ID || updated.Severity != "critical" {
		t.Fatalf("fold changed group risk: %+v", updated)
	}
	if updated.RepresentativeEventID != "evt_critical" || updated.Title != "real secret leak" {
		t.Fatalf("lower-risk event replaced representative: %+v", updated)
	}
	if got, _ := updated.BodyJSON["event_id"].(string); got != "evt_critical" {
		t.Fatalf("lower-risk body replaced representative body: %+v", updated.BodyJSON)
	}
}
