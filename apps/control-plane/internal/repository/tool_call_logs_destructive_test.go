package repository

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildDestructiveToolCallLogInsertUsesTenantLifecycleUpsert(t *testing.T) {
	entry := &ToolCallLog{
		ID: "evt-public", RequestID: "req-1", TenantID: "tenant-1",
		ToolName: "shell_command", ToolType: "system", RiskLevel: "high",
		Status: "blocked", OperationID: "op-1", EventType: "tool_attempt_blocked",
		RiskCategory: "destructive_change", RiskSubcategory: "filesystem_delete",
		FinalAction: "block", NotificationRequired: true, NotificationStatus: "pending",
	}
	query, args, err := buildToolCallLogInsert(entry)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"operation_id", "event_type", "risk_category", "risk_subcategory",
		"public_event_id", "application_id", "agent_type", "model", "protocol",
		"notification_required", "discardable_path_matched", "execution_forwarded",
		"ON CONFLICT (tenant_id, operation_id, event_type)",
		"WHERE operation_id IS NOT NULL", "DO UPDATE SET",
		"execution_forwarded", "result_observed", "RETURNING id",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("insert query missing %q: %s", fragment, query)
		}
	}
	if !strings.Contains(toolCallLogSelectColumns, "application_id") ||
		!strings.Contains(toolCallLogSelectColumns, "agent_type") ||
		!strings.Contains(toolCallLogSelectColumns, "model") ||
		!strings.Contains(toolCallLogSelectColumns, "public_event_id") ||
		!strings.Contains(toolCallLogSelectColumns, "protocol") {
		t.Fatalf("destructive context missing from select columns: %s", toolCallLogSelectColumns)
	}
	if len(args) < 50 {
		t.Fatalf("destructive fields missing from args: len=%d args=%v", len(args), args)
	}
}
func TestPublicDestructiveEventIDIsStableAndOpaque(t *testing.T) {
	got := PublicDestructiveEventID("tenant-1", "op-1", "tool_attempt_blocked")
	if got == "" || !strings.HasPrefix(got, "evt_") ||
		got != PublicDestructiveEventID("tenant-1", "op-1", "tool_attempt_blocked") {
		t.Fatalf("unstable public event id: %q", got)
	}
	for _, changed := range []string{
		PublicDestructiveEventID("tenant-2", "op-1", "tool_attempt_blocked"),
		PublicDestructiveEventID("tenant-1", "op-2", "tool_attempt_blocked"),
		PublicDestructiveEventID("tenant-1", "op-1", "tool_destructive_intent"),
	} {
		if changed == got {
			t.Fatalf("public event id collision: %q", changed)
		}
	}
	for _, internal := range []string{"tenant-1", "op-1", "tool_attempt_blocked"} {
		if strings.Contains(got, internal) {
			t.Fatalf("public event id exposed internal input %q: %s", internal, got)
		}
	}
}
func TestDestructiveToolCallLogCreateIsIdempotentWithinTenant(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	repo := NewToolCallLogRepository(db)
	first := &ToolCallLog{
		RequestID: "req-1", TenantID: "tenant-1", ToolName: "shell_command", ToolType: "system",
		ApplicationID: "application-1", AgentType: "codex", Model: "gpt-5", Protocol: "responses",
		RiskLevel: "high", Status: "recorded", EventKind: "invocation_proposed",
		OperationID: "op-1", EventType: "tool_destructive_intent",
		RiskCategory: "destructive_change", RiskSubcategory: "filesystem_delete",
		FinalAction: "alert_allow", NotificationRequired: true, NotificationStatus: "pending",
	}
	if err := repo.Create(ctx, first); err != nil {
		t.Fatal(err)
	}
	duplicate := *first
	duplicate.ID = ""
	duplicate.RequestID = "req-reconnect"
	if err := repo.Create(ctx, &duplicate); err != nil {
		t.Fatal(err)
	}
	if duplicate.ID != first.ID || duplicate.PublicEventID != first.PublicEventID ||
		first.PublicEventID != PublicDestructiveEventID(first.TenantID, first.OperationID, first.EventType) {
		t.Fatalf("idempotent identity mismatch: first=%+v duplicate=%+v", first, duplicate)
	}
	var count int
	var storedPublicID string
	var forwarded, observed, resultObserved bool
	if err := db.QueryRow(ctx, `
		SELECT count(*), max(public_event_id), bool_or(COALESCE(execution_forwarded, false)),
		       bool_or(COALESCE(execution_observed, false)), bool_or(COALESCE(result_observed, false))
		FROM tool_call_logs
		WHERE tenant_id=$1 AND operation_id=$2 AND event_type=$3
	`, first.TenantID, first.OperationID, first.EventType).Scan(&count, &storedPublicID, &forwarded, &observed, &resultObserved); err != nil {
		t.Fatal(err)
	}
	if count != 1 || storedPublicID != first.PublicEventID || forwarded || observed || resultObserved {
		t.Fatalf("intent facts count=%d forwarded=%t observed=%t result=%t", count, forwarded, observed, resultObserved)
	}
	listed, err := repo.ListByRequest(ctx, first.TenantID, first.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ApplicationID != "application-1" ||
		listed[0].AgentType != "codex" || listed[0].Model != "gpt-5" ||
		listed[0].Protocol != "responses" {
		t.Fatalf("destructive context roundtrip = %+v", listed)
	}

	execution := &ToolCallLog{
		RequestID: "req-1", TenantID: "tenant-1", ToolName: "demo__run_shell", ToolType: "mcp",
		RiskLevel: "high", Status: "forwarded", EventKind: "execution_forwarded",
		ExecutionForwarded: true, ExecutionObserved: true,
		OperationID: "op-1", EventType: "tool_execution_risk",
		RiskCategory: "destructive_change", RiskSubcategory: "filesystem_delete",
		FinalAction: "alert_allow", NotificationRequired: true, NotificationStatus: "pending",
	}
	if err := repo.Create(ctx, execution); err != nil {
		t.Fatal(err)
	}
	executionResult := *execution
	executionResult.ID = ""
	executionResult.Status = "success"
	executionResult.ResultObserved = true
	if err := repo.Create(ctx, &executionResult); err != nil {
		t.Fatal(err)
	}
	replayedExecution := *execution
	replayedExecution.ID = ""
	if err := repo.Create(ctx, &replayedExecution); err != nil {
		t.Fatal(err)
	}
	if executionResult.ID != execution.ID || executionResult.PublicEventID != execution.PublicEventID {
		t.Fatalf("execution event identity mismatch: first=%+v result=%+v", execution, executionResult)
	}
	var storedStatus string
	if err := db.QueryRow(ctx, `
		SELECT count(*), bool_or(COALESCE(execution_forwarded, false)),
		       bool_or(COALESCE(execution_observed, false)), bool_or(COALESCE(result_observed, false)),
		       max(status)
		FROM tool_call_logs
		WHERE tenant_id=$1 AND operation_id=$2 AND event_type=$3
	`, execution.TenantID, execution.OperationID, execution.EventType).Scan(&count, &forwarded, &observed, &resultObserved, &storedStatus); err != nil {
		t.Fatal(err)
	}
	if count != 1 || !forwarded || !observed || !resultObserved || storedStatus != "success" {
		t.Fatalf("execution facts count=%d forwarded=%t observed=%t result=%t status=%q", count, forwarded, observed, resultObserved, storedStatus)
	}

	otherTenant := *first
	otherTenant.ID = ""
	otherTenant.TenantID = "tenant-2"
	if err := repo.Create(ctx, &otherTenant); err != nil {
		t.Fatal(err)
	}
	if otherTenant.ID == first.ID || otherTenant.PublicEventID == first.PublicEventID {
		t.Fatalf("tenant isolation failed: first=%+v other=%+v", first, otherTenant)
	}
}
func TestBuildDestructiveNotificationOutboxInsertUsesEnabledTenantChannelsAndOpaquePayload(t *testing.T) {
	entry := &ToolCallLog{
		TenantID: "tenant-1", RequestID: "req-1", TraceID: "trace-1",
		OperationID: "op-1", EventType: "tool_attempt_blocked",
		PublicEventID: "evt-public", RiskCategory: "destructive_change",
		RiskSubcategory: "filesystem_delete", ReasonSummary: "deterministic_destructive_operation",
		TargetSummary: "filesystem_delete:1-targets", FinalAction: "block",
		NotificationRequired: true, NotifyChannelIDs: []string{"channel-selected"},
	}
	query, args, err := buildDestructiveNotificationOutboxInsert(entry)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"INSERT INTO outbox_events", "FROM notify_channels", "tenant_id = $1",
		"enabled = true", "ON CONFLICT (id) DO NOTHING", "public_event_id",
		"operation_id", "event_type", "channel_id", "target_summary",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("outbox query missing %q: %s", fragment, query)
		}
	}
	for _, forbidden := range []string{"config_json", "url", "headers", "cookie", "token"} {
		if strings.Contains(strings.ToLower(query), forbidden) {
			t.Fatalf("outbox query includes sensitive connector material %q: %s", forbidden, query)
		}
	}
	if len(args) != 11 || args[0] != entry.TenantID || args[3] != entry.PublicEventID || args[10].([]string)[0] != "channel-selected" {
		t.Fatalf("outbox args = %#v", args)
	}
}

func TestBuildDestructiveNotificationOutboxInsertTargetsSelectedChannels(t *testing.T) {
	entry := &ToolCallLog{
		TenantID: "tenant-1", OperationID: "op-1", EventType: "tool_attempt_blocked",
		PublicEventID: "evt-public", NotifyChannelIDs: []string{"channel-selected"},
	}
	query, args, err := buildDestructiveNotificationOutboxInsert(entry)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(query, "ch.id = ANY($11)") {
		t.Fatalf("outbox query does not target selected channels: %s", query)
	}
	if len(args) != 11 {
		t.Fatalf("outbox args = %#v", args)
	}
	channels, ok := args[10].([]string)
	if !ok || len(channels) != 1 || channels[0] != "channel-selected" {
		t.Fatalf("selected channels = %#v", args[10])
	}
}

func TestDestructiveNotificationOutboxIsIdempotentAndTenantScopedInPostgres(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	if _, err := db.Exec(ctx, `
		CREATE TABLE notify_channels (
			id varchar(64) PRIMARY KEY,
			tenant_id varchar(64) NOT NULL,
			config_json jsonb NOT NULL,
			enabled boolean NOT NULL
		);
		CREATE TABLE outbox_events (
			id varchar(96) PRIMARY KEY,
			tenant_id varchar(64) NOT NULL,
			event_type varchar(128) NOT NULL,
			schema_version varchar(16) NOT NULL,
			request_id varchar(64),
			trace_id varchar(128),
			payload_json jsonb NOT NULL,
			status varchar(16) NOT NULL,
			available_at timestamptz NOT NULL,
			created_at timestamptz NOT NULL,
			updated_at timestamptz NOT NULL
		);
		INSERT INTO notify_channels (id, tenant_id, config_json, enabled) VALUES
			('channel-enabled', 'tenant-1', '{"url":"https://example.invalid","token":"must-not-leak"}', true),
			('channel-unselected', 'tenant-1', '{}', true),
			('channel-disabled', 'tenant-1', '{"url":"https://disabled.invalid"}', false),
			('channel-other-tenant', 'tenant-2', '{"url":"https://other.invalid"}', true);
	`); err != nil {
		t.Fatal(err)
	}
	entry := &ToolCallLog{
		TenantID: "tenant-1", RequestID: "req-1", TraceID: "trace-1",
		OperationID: "op-1", EventType: "tool_attempt_blocked",
		PublicEventID: "evt-public", RiskCategory: "destructive_change",
		RiskSubcategory: "filesystem_delete", ReasonSummary: "deterministic_destructive_operation",
		TargetSummary: "filesystem_delete:1-targets", FinalAction: "block",
		NotifyChannelIDs:     []string{"channel-enabled"},
		NotificationRequired: true, Confidence: 1,
	}
	repo := NewToolCallLogRepository(db)
	rows, err := repo.EnqueueDestructiveNotifications(ctx, entry)
	if err != nil || rows != 1 {
		t.Fatalf("first enqueue rows=%d err=%v", rows, err)
	}
	reconnect := *entry
	reconnect.RequestID = "req-reconnect"
	rows, err = repo.EnqueueDestructiveNotifications(ctx, &reconnect)
	if err != nil || rows != 0 {
		t.Fatalf("reconnect enqueue rows=%d err=%v", rows, err)
	}
	distinct := *entry
	distinct.RequestID = "req-distinct"
	distinct.OperationID = "op-2"
	distinct.PublicEventID = "evt-distinct"
	rows, err = repo.EnqueueDestructiveNotifications(ctx, &distinct)
	if err != nil || rows != 1 {
		t.Fatalf("distinct enqueue rows=%d err=%v", rows, err)
	}
	var count int
	var tenantID, eventType, payload string
	if err := db.QueryRow(ctx, `
		SELECT count(*), min(tenant_id), min(event_type), min(payload_json::text)
		FROM outbox_events
	`).Scan(&count, &tenantID, &eventType, &payload); err != nil {
		t.Fatal(err)
	}
	if count != 2 || tenantID != "tenant-1" || eventType != "notify.agent_destructive" {
		t.Fatalf("outbox identity count=%d tenant=%q type=%q", count, tenantID, eventType)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"public_event_id": "evt-public", "operation_id": "op-1",
		"event_type": "tool_attempt_blocked", "channel_id": "channel-enabled",
	} {
		if got, ok := decoded[key].(string); !ok || got != want {
			t.Fatalf("outbox payload field %q = %#v, want string %q", key, decoded[key], want)
		}
	}
	for _, required := range []string{"evt-public", "op-1", "tool_attempt_blocked", "channel-enabled"} {
		if !strings.Contains(payload, required) {
			t.Fatalf("outbox payload missing %q: %s", required, payload)
		}
	}
	for _, forbidden := range []string{"must-not-leak", "example.invalid", "channel-disabled", "channel-other-tenant"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("outbox payload leaked %q: %s", forbidden, payload)
		}
	}
}

func TestDestructiveNotificationStatusTerminalAndPendingStatesDoNotRegress(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	repo := NewToolCallLogRepository(db)
	entry := &ToolCallLog{
		RequestID: "req-status", TenantID: "tenant-status", ToolName: "shell_command", ToolType: "system",
		RiskLevel: "high", Status: "blocked", EventKind: "invocation_proposed",
		OperationID: "op-status", EventType: "tool_attempt_blocked",
		RiskCategory: "destructive_change", FinalAction: "block",
		NotificationRequired: true, NotificationStatus: "pending",
	}
	if err := repo.Create(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetDestructiveNotificationStatus(ctx, entry.TenantID, entry.OperationID, entry.EventType, "sent"); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetDestructiveNotificationStatus(ctx, entry.TenantID, entry.OperationID, entry.EventType, "pending"); err != nil {
		t.Fatal(err)
	}
	sentReplay := *entry
	sentReplay.ID = ""
	sentReplay.NotificationStatus = "failed"
	if err := repo.Create(ctx, &sentReplay); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := db.QueryRow(ctx, `
		SELECT notification_status FROM tool_call_logs
		WHERE tenant_id=$1 AND operation_id=$2 AND event_type=$3
	`, entry.TenantID, entry.OperationID, entry.EventType).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "sent" {
		t.Fatalf("sent terminal status regressed to %q", status)
	}

	dead := *entry
	dead.ID = ""
	dead.OperationID = "op-dead"
	if err := repo.Create(ctx, &dead); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetDestructiveNotificationStatus(ctx, dead.TenantID, dead.OperationID, dead.EventType, "dead"); err != nil {
		t.Fatal(err)
	}
	deadReplay := dead
	deadReplay.ID = ""
	deadReplay.NotificationStatus = "pending"
	if err := repo.Create(ctx, &deadReplay); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `
		SELECT notification_status FROM tool_call_logs
		WHERE tenant_id=$1 AND operation_id=$2 AND event_type=$3
	`, dead.TenantID, dead.OperationID, dead.EventType).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "dead" {
		t.Fatalf("dead terminal status regressed to %q", status)
	}

	pending := *entry
	pending.ID = ""
	pending.OperationID = "op-pending"
	pending.NotificationStatus = "pending"
	if err := repo.Create(ctx, &pending); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetDestructiveNotificationStatus(ctx, pending.TenantID, pending.OperationID, pending.EventType, "skipped"); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `
		SELECT notification_status FROM tool_call_logs
		WHERE tenant_id=$1 AND operation_id=$2 AND event_type=$3
	`, pending.TenantID, pending.OperationID, pending.EventType).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("duplicate enqueue skipped regressed pending status to %q", status)
	}
}
func TestRefreshDestructiveNotificationStatusUsesExistingOutboxOnReconnect(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	if _, err := db.Exec(ctx, `
		CREATE TABLE outbox_events (
			id varchar(96) PRIMARY KEY,
			tenant_id varchar(64) NOT NULL,
			event_type varchar(128) NOT NULL,
			payload_json jsonb NOT NULL,
			status varchar(16) NOT NULL
		)
	`); err != nil {
		t.Fatal(err)
	}
	repo := NewToolCallLogRepository(db)
	entry := &ToolCallLog{
		RequestID: "req-refresh", TenantID: "tenant-refresh", ToolName: "shell_command", ToolType: "system",
		RiskLevel: "high", Status: "blocked", EventKind: "invocation_proposed",
		OperationID: "op-refresh", EventType: "tool_attempt_blocked",
		RiskCategory: "destructive_change", FinalAction: "block",
		NotificationRequired: true, NotificationStatus: "pending",
	}
	if err := repo.Create(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO outbox_events (id, tenant_id, event_type, payload_json, status)
		VALUES (
			'outbox-refresh', $1, 'notify.agent_destructive',
			jsonb_build_object('operation_id', $2::text, 'event_type', $3::text, 'channel_id', 'channel-1'),
			'pending'
		)
		ON CONFLICT (id) DO NOTHING
	`, entry.TenantID, entry.OperationID, entry.EventType); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		status, err := repo.RefreshDestructiveNotificationStatus(ctx, entry.TenantID, entry.OperationID, entry.EventType)
		if err != nil {
			t.Fatal(err)
		}
		if status != "pending" {
			t.Fatalf("refresh %d after reconnect = %q, want pending", i, status)
		}
	}

	noChannels := *entry
	noChannels.ID = ""
	noChannels.OperationID = "op-no-channels"
	if err := repo.Create(ctx, &noChannels); err != nil {
		t.Fatal(err)
	}
	status, err := repo.RefreshDestructiveNotificationStatus(ctx, noChannels.TenantID, noChannels.OperationID, noChannels.EventType)
	if err != nil {
		t.Fatal(err)
	}
	if status != "skipped" {
		t.Fatalf("no-channel notification status = %q, want skipped", status)
	}
}
