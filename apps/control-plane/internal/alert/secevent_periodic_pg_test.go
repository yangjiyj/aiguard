package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/alertconfig"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"testing"
	"time"
)

// TestAgentEndpointSecurityEventBridgePostgres verifies the real endpoint ingest ->
// security_events -> existing alert_groups/inbox pipeline with no request log.
func TestAgentEndpointSecurityEventBridgePostgres(t *testing.T) {
	dsn := os.Getenv("AGENT_ENDPOINT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AGENT_ENDPOINT_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var dbName string
	if err := db.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil || dbName != "jjdguard_dev" {
		t.Fatalf("refusing non-development database %q: %v", dbName, err)
	}
	tenant := fmt.Sprintf("agent_bridge_%d", time.Now().UnixNano())
	endpoint := tenant + "_endpoint"
	eventID := tenant + "_event"
	tokenHash := repository.HashAgentToken(tenant)
	must := func(q string, args ...any) {
		t.Helper()
		if _, e := db.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	must(`INSERT INTO tenants(id,name,is_test) VALUES($1,$1,true)`, tenant)
	t.Cleanup(func() {
		for _, table := range []string{"alert_inbox", "security_event_occurrences", "agent_alerts", "security_events", "alert_groups", "agent_events", "agent_sessions", "agent_endpoints"} {
			_, _ = db.Exec(context.Background(), "DELETE FROM "+table+" WHERE tenant_id=$1", tenant)
		}
		_, _ = db.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant)
	})
	must(`INSERT INTO agent_endpoints(id,tenant_id,machine_id,hostname,os,arch,agent_product,token_hash) VALUES($1,$2,$3,'host','linux','amd64','test',$4)`, endpoint, tenant, tenant+"_machine", tokenHash)
	raw, _ := json.Marshal(map[string]any{
		"event_id": eventID, "event_type": "tool.pre", "session_id": tenant + "_session",
		"occurred_at": time.Now().UTC().Format(time.RFC3339Nano), "tool_call_id": eventID,
		"tool_name": "shell", "tool_type": "system", "risk_level": "high",
		"local_decision": map[string]any{"effective_decision": "block"},
	})
	repo := repository.NewAgentEndpointRepository(db)
	result, err := repo.AcceptEventBatch(ctx, tenant, endpoint, repository.AgentEventBatchRequest{SchemaVersion: "events.v1", Events: []json.RawMessage{raw}})
	if err != nil || len(result.Accepted) != 1 {
		t.Fatalf("ingest result=%+v err=%v", result, err)
	}
	t.Setenv("SECEVENT_ALERT_GRACE_SECONDS", "0")
	groups := repository.NewAlertGroupRepository(db)
	bridge := NewSecEventBridge(repository.NewSecurityEventRepository(db), NewInboxService(repository.NewAlertInboxRepository(db)), &fakeNotifier{}).WithAlertGroups(groups).WithGroupCounters(groups)
	if _, err := bridge.DrainBatches(ctx, 2); err != nil {
		t.Fatal(err)
	}
	var securityRows, groupedRows, inboxRows, legacyRows int
	if err := db.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE se.alert_group_id IS NOT NULL AND se.alerted_at IS NOT NULL AND ag.id IS NOT NULL) FROM security_events se LEFT JOIN alert_groups ag ON ag.id=se.alert_group_id AND ag.tenant_id=se.tenant_id WHERE se.tenant_id=$1 AND se.matched_summary->>'source'='agent_endpoint' AND se.severity='high'`, tenant).Scan(&securityRows, &groupedRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM alert_inbox WHERE tenant_id=$1`, tenant).Scan(&inboxRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM agent_alerts WHERE tenant_id=$1`, tenant).Scan(&legacyRows); err != nil {
		t.Fatal(err)
	}
	if securityRows != 1 || groupedRows != 1 || inboxRows != 1 || legacyRows != 0 {
		t.Fatalf("security=%d grouped=%d inbox=%d legacy_agent_alerts=%d", securityRows, groupedRows, inboxRows, legacyRows)
	}
	t.Logf("endpoint event verified: security_events=%d alert_groups=%d alert_inbox=%d agent_alerts=%d", securityRows, groupedRows, inboxRows, legacyRows)
}

func TestSecurityQualityPeriodicBridgePostgres(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	db, e := pgxpool.New(context.Background(), dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tenant := fmt.Sprintf("quality_bridge_%d", time.Now().UnixNano())
	id := tenant + "_event"
	must := func(q string, args ...any) {
		t.Helper()
		if _, e := db.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	must(`INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',true)`, tenant)
	defer func() {
		for _, table := range []string{"alert_inbox", "security_events", "security_event_occurrences", "alert_groups", "request_logs"} {
			_, _ = db.Exec(context.Background(), "DELETE FROM "+table+" WHERE tenant_id=$1", tenant)
		}
		_, _ = db.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant)
	}()
	t.Setenv("SECEVENT_BRIDGE_INTERVAL_SECONDS", "")
	t.Setenv("SECEVENT_ALERT_GRACE_SECONDS", "0")
	groups := repository.NewAlertGroupRepository(db)
	bridge := NewSecEventBridge(repository.NewSecurityEventRepository(db), NewInboxService(repository.NewAlertInboxRepository(db)), &fakeNotifier{}).WithAlertGroups(groups).WithGroupCounters(groups)
	results := make(chan error, 8)
	go bridge.RunPeriodic(ctx, 10, func(_ int, e error) { results <- e })
	select {
	case e := <-results:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("initial bridge did not start")
	}
	generated := time.Now().UTC()
	must(`INSERT INTO request_logs(id,request_id,tenant_id,project_id,endpoint_type,request_status) VALUES($1,$1,$2,'project_default','chat_completions','success')`, id, tenant)
	must(`INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary,created_at) VALUES($1,$1,$2,'project_default','prompt_injection','high','audit','{"confidence":1,"findings":[{"type":"prompt_injection","category":"classic_injection","severity":"high","confidence":1}]}',$3)`, id, tenant, generated)
	inserted := time.Now().UTC()
	select {
	case e := <-results:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(alertconfig.BridgeInterval() + 5*time.Second):
		t.Fatal("normal periodic bridge exceeded interval")
	}
	cancel()
	var alerted, grouped, inbox time.Time
	if e := db.QueryRow(context.Background(), `SELECT se.alerted_at,ag.created_at,ai.created_at FROM security_events se JOIN alert_groups ag ON ag.tenant_id=se.tenant_id AND ag.id=se.alert_group_id JOIN alert_inbox ai ON ai.tenant_id=se.tenant_id WHERE se.id=$1 LIMIT 1`, id).Scan(&alerted, &grouped, &inbox); e != nil {
		t.Fatal(e)
	}
	if inbox.Sub(generated) > alertconfig.BridgeInterval()+5*time.Second {
		t.Fatal("inbox arrived too late")
	}
	t.Logf("generated=%s inserted=%s group=%s inbox=%s alerted=%s interval=%s elapsed=%s", generated.Format(time.RFC3339Nano), inserted.Format(time.RFC3339Nano), grouped.Format(time.RFC3339Nano), inbox.Format(time.RFC3339Nano), alerted.Format(time.RFC3339Nano), alertconfig.BridgeInterval(), inbox.Sub(generated))
}
