package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type agentIngestFixture struct {
	tenant, endpoint, session string
}

func newAgentIngestFixture(t *testing.T, db *pgxpool.Pool) agentIngestFixture {
	t.Helper()
	suffix := uuid.NewString()
	f := agentIngestFixture{
		tenant:   "agent-ingest-tenant-" + suffix,
		endpoint: "agent-ingest-endpoint-" + suffix,
		session:  "agent-ingest-session-" + suffix,
	}
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,is_test) VALUES($1,$2,true)`, f.tenant, f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO agent_endpoints(id,tenant_id,machine_id,hostname,os,arch,agent_product,token_hash)
		VALUES($1,$2,$3,'host','linux','amd64','test',$4)`, f.endpoint, f.tenant, "machine-"+suffix, HashAgentToken(suffix)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = db.Exec(ctx, `DELETE FROM agent_alerts WHERE tenant_id=$1`, f.tenant)
		_, _ = db.Exec(ctx, `DELETE FROM security_events WHERE tenant_id=$1`, f.tenant)
		_, _ = db.Exec(ctx, `DELETE FROM agent_events WHERE tenant_id=$1`, f.tenant)
		_, _ = db.Exec(ctx, `DELETE FROM tool_call_logs WHERE tenant_id=$1`, f.tenant)
		_, _ = db.Exec(ctx, `DELETE FROM agent_turns WHERE tenant_id=$1`, f.tenant)
		_, _ = db.Exec(ctx, `DELETE FROM agent_sessions WHERE tenant_id=$1`, f.tenant)
		_, _ = db.Exec(ctx, `DELETE FROM agent_endpoint_assets WHERE tenant_id=$1`, f.tenant)
		_, _ = db.Exec(ctx, `DELETE FROM agent_endpoints WHERE tenant_id=$1`, f.tenant)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, f.tenant)
	})
	return f
}

func agentRawEvent(id, typ string, occurredAt time.Time, fields map[string]any) json.RawMessage {
	event := map[string]any{
		"event_id": id, "event_type": typ, "occurred_at": occurredAt.UTC().Format(time.RFC3339Nano),
	}
	for key, value := range fields {
		event[key] = value
	}
	body, _ := json.Marshal(event)
	return body
}

func acceptAgentEvents(t *testing.T, repo *AgentEndpointRepository, f agentIngestFixture, events ...json.RawMessage) (*AgentEventBatchResult, error) {
	t.Helper()
	return repo.AcceptEventBatch(context.Background(), f.tenant, f.endpoint, AgentEventBatchRequest{SchemaVersion: "events.v1", Events: events})
}

func TestAgentEventBatchIngestLifecycleDuplicateConflictAndDerivedRows(t *testing.T) {
	db := agentEndpointTestDB(t)
	f := newAgentIngestFixture(t, db)
	repo := NewAgentEndpointRepository(db)
	occurredAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	pre := agentRawEvent("event-pre-"+uuid.NewString(), "tool.pre", occurredAt, map[string]any{
		"session_id": f.session, "prompt_id": "prompt-1", "tool_call_id": "call-1",
		"tool_name": "shell", "tool_type": "system", "risk_level": "high",
		"local_decision": map[string]any{"effective_decision": "block", "risk_level": "high"},
		"asset_type":     "skill", "asset_name": "deploy", "asset_hash": "sha256:asset",
		"asset_present": true, "asset_version": "1", "asset_source": "hook",
		"asset_evidence": map[string]any{"category": "tool"},
	})
	post := agentRawEvent("event-post-"+uuid.NewString(), "tool.post", occurredAt.Add(time.Second), map[string]any{
		"session_id": f.session, "prompt_id": "prompt-1", "tool_call_id": "call-1",
		"tool_name": "shell", "tool_type": "system", "risk_level": "high",
		"status": "blocked", "result": "denied",
	})
	result, err := acceptAgentEvents(t, repo, f, pre, post)
	if err != nil || len(result.Accepted) != 2 || len(result.Duplicates) != 0 {
		t.Fatalf("first batch result=%+v err=%v", result, err)
	}
	result, err = acceptAgentEvents(t, repo, f, pre, post)
	if err != nil || len(result.Accepted) != 0 || len(result.Duplicates) != 2 {
		t.Fatalf("duplicate batch result=%+v err=%v", result, err)
	}
	var storedOccurred time.Time
	var eventCount, sessionEventCount, sessionTurnCount, sessionToolCount, sessionBlockedCount int
	var endpointEventCount, endpointToolCount, endpointBlockedCount int
	if err = db.QueryRow(context.Background(), `SELECT occurred_at FROM agent_events WHERE tenant_id=$1 AND id=$2`, f.tenant, result.Duplicates[0]).Scan(&storedOccurred); err != nil {
		t.Fatal(err)
	}
	if !storedOccurred.Equal(occurredAt) {
		t.Fatalf("stored occurred_at=%s want=%s", storedOccurred, occurredAt)
	}
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM agent_events WHERE tenant_id=$1`, f.tenant).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(context.Background(), `SELECT event_count,turn_count,tool_call_count,blocked_count FROM agent_sessions WHERE tenant_id=$1 AND session_id=$2`, f.tenant, f.session).
		Scan(&sessionEventCount, &sessionTurnCount, &sessionToolCount, &sessionBlockedCount); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(context.Background(), `SELECT event_count,tool_call_count,blocked_count FROM agent_endpoints WHERE tenant_id=$1 AND id=$2`, f.tenant, f.endpoint).
		Scan(&endpointEventCount, &endpointToolCount, &endpointBlockedCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 2 || sessionEventCount != 2 || sessionTurnCount != 1 || sessionToolCount != 1 || sessionBlockedCount != 2 || endpointEventCount != 2 || endpointToolCount != 1 || endpointBlockedCount != 2 {
		t.Fatalf("counts events=%d session=%d/%d/%d/%d endpoint=%d/%d/%d", eventCount, sessionEventCount, sessionTurnCount, sessionToolCount, sessionBlockedCount, endpointEventCount, endpointToolCount, endpointBlockedCount)
	}
	var toolRows int
	var kind, status, resultText string
	var executionObserved, resultObserved bool
	if err = db.QueryRow(context.Background(), `SELECT count(*),max(event_kind),max(status),max(result),bool_or(execution_observed),bool_or(result_observed)
		FROM tool_call_logs WHERE tenant_id=$1 AND tool_call_id='call-1'`, f.tenant).
		Scan(&toolRows, &kind, &status, &resultText, &executionObserved, &resultObserved); err != nil {
		t.Fatal(err)
	}
	if toolRows != 1 || kind != "result_observed" || status != "blocked" || resultText != "denied" || !executionObserved || !resultObserved {
		t.Fatalf("tool rows=%d kind=%q status=%q result=%q execution=%v resultObserved=%v", toolRows, kind, status, resultText, executionObserved, resultObserved)
	}
	var assetRows int
	var present bool
	if err = db.QueryRow(context.Background(), `SELECT count(*),bool_or(present) FROM agent_endpoint_assets WHERE tenant_id=$1`, f.tenant).Scan(&assetRows, &present); err != nil {
		t.Fatal(err)
	}
	// P0-2：端点风险/阻断事件改写入 security_events（agent_endpoint 源），不再写 agent_alerts。
	// 修正后：pre 带有效决策 block → action_taken=block；post 仅 status=blocked 无有效决策，按 risk=high
	// 走风险分支 → action_taken=flag（不再误用工具 status 当阻断判据）。
	var secRows int
	var eventType, severity string
	var blockRows, flagRows int
	if err = db.QueryRow(context.Background(), `SELECT count(*), max(event_type), max(severity),
		count(*) FILTER (WHERE action_taken='block'), count(*) FILTER (WHERE action_taken='flag')
		FROM security_events WHERE tenant_id=$1 AND COALESCE(matched_summary->>'source','')='agent_endpoint'`, f.tenant).
		Scan(&secRows, &eventType, &severity, &blockRows, &flagRows); err != nil {
		t.Fatal(err)
	}
	if assetRows != 1 || !present || secRows != 2 {
		t.Fatalf("assetRows=%d present=%v secRows=%d", assetRows, present, secRows)
	}
	if eventType != "tool_execution_risk" || severity != "high" || blockRows != 1 || flagRows != 1 {
		t.Fatalf("endpoint security event eventType=%q severity=%q blockRows=%d flagRows=%d", eventType, severity, blockRows, flagRows)
	}

	conflict := agentRawEvent(result.Duplicates[0], "tool.pre", occurredAt, map[string]any{"tool_name": "different", "tool_type": "system"})
	freshID := "fresh-rollback-" + uuid.NewString()
	fresh := agentRawEvent(freshID, "tool.pre", occurredAt, map[string]any{"tool_name": "read", "tool_type": "file"})
	_, err = acceptAgentEvents(t, repo, f, fresh, conflict)
	var batchErr *AgentEventBatchError
	if !errors.As(err, &batchErr) || batchErr.Code != "event_conflict" {
		t.Fatalf("conflict err=%v", err)
	}
	var freshRows int
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM agent_events WHERE tenant_id=$1 AND id=$2`, f.tenant, freshID).Scan(&freshRows); err != nil {
		t.Fatal(err)
	}
	if freshRows != 0 {
		t.Fatalf("fresh rows after conflict rollback=%d", freshRows)
	}
}

func TestAgentEventBatchRollsBackWhenDerivedWriteFails(t *testing.T) {
	db := agentEndpointTestDB(t)
	f := newAgentIngestFixture(t, db)
	repo := NewAgentEndpointRepository(db)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `ALTER TABLE tool_call_logs ENABLE ALWAYS TRIGGER USER`); err != nil {
		_ = err
	}
	trigger := "agent_ingest_fail_" + fmt.Sprintf("%x", time.Now().UnixNano())
	function := trigger + "_fn"
	if _, err := db.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id=%s THEN RAISE EXCEPTION 'forced derived write failure'; END IF; RETURN NEW; END $$`,
		function, quoteLiteral(f.tenant))); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT OR UPDATE ON tool_call_logs FOR EACH ROW EXECUTE FUNCTION %s()`, trigger, function)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON tool_call_logs`, trigger))
		_, _ = db.Exec(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, function))
	})
	id := "derived-fail-" + uuid.NewString()
	event := agentRawEvent(id, "tool.pre", time.Now().UTC(), map[string]any{
		"session_id": f.session, "tool_call_id": "call-fail", "tool_name": "shell", "tool_type": "system",
	})
	if _, err := acceptAgentEvents(t, repo, f, event); err == nil {
		t.Fatal("expected derived write failure")
	}
	var events, sessions int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM agent_events WHERE tenant_id=$1`, f.tenant).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM agent_sessions WHERE tenant_id=$1`, f.tenant).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if events != 0 || sessions != 0 {
		t.Fatalf("derived failure committed events=%d sessions=%d", events, sessions)
	}
}

func quoteLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func TestAgentRetentionProtectsActiveSessionsAndPresentAssets(t *testing.T) {
	db := agentEndpointTestDB(t)
	f := newAgentIngestFixture(t, db)
	repo := NewAgentEndpointRepository(db)
	ctx := context.Background()
	old := time.Now().UTC().AddDate(0, 0, -120)
	inactiveSession := f.session + "-ended"
	activeEvent := "active-old-" + uuid.NewString()
	inactiveEvent := "inactive-old-" + uuid.NewString()
	mustExec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(`INSERT INTO agent_sessions(id,tenant_id,session_id,endpoint_id,source,status,started_at,last_request_at,created_at,updated_at) VALUES($1,$2,$3,$4,'endpoint_hook','active',$5,$5,$5,$5)`, deterministicAgentID("as_", f.tenant, f.session), f.tenant, f.session, f.endpoint, old)
	mustExec(`INSERT INTO agent_sessions(id,tenant_id,session_id,endpoint_id,source,status,started_at,ended_at,last_request_at,created_at,updated_at) VALUES($1,$2,$3,$4,'endpoint_hook','ended',$5,$5,$5,$5,$5)`, deterministicAgentID("as_", f.tenant, inactiveSession), f.tenant, inactiveSession, f.endpoint, old)
	mustExec(`INSERT INTO agent_turns(id,tenant_id,session_id,prompt_id,started_at,ended_at) VALUES($1,$2,$3,'p',$4,$4)`, deterministicAgentID("at_", f.tenant, inactiveSession, "p"), f.tenant, inactiveSession, old)
	mustExec(`INSERT INTO agent_events(id,tenant_id,endpoint_id,session_id,event_type,occurred_at,payload) VALUES($1,$2,$3,$4,'tool.pre',$5,'{}')`, activeEvent, f.tenant, f.endpoint, f.session, old)
	mustExec(`INSERT INTO agent_events(id,tenant_id,endpoint_id,session_id,event_type,occurred_at,payload) VALUES($1,$2,$3,$4,'tool.pre',$5,'{}')`, inactiveEvent, f.tenant, f.endpoint, inactiveSession, old)
	mustExec(`INSERT INTO agent_endpoint_assets(id,tenant_id,endpoint_id,asset_type,name,hash,last_seen,present) VALUES($1,$2,$3,'skill','present','h1',$4,true),($5,$2,$3,'skill','absent','h2',$4,false)`, "present-"+uuid.NewString(), f.tenant, f.endpoint, old, "absent-"+uuid.NewString())
	result, err := repo.DeleteRetainedData(ctx, 90)
	if err != nil {
		t.Fatal(err)
	}
	if result.Events != 1 || result.Turns != 1 || result.Sessions != 1 || result.Assets != 1 {
		t.Fatalf("retention result=%+v", result)
	}
	var activeEvents, activeSessions, presentAssets int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM agent_events WHERE tenant_id=$1 AND id=$2`, f.tenant, activeEvent).Scan(&activeEvents); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, `SELECT count(*) FROM agent_sessions WHERE tenant_id=$1 AND session_id=$2`, f.tenant, f.session).Scan(&activeSessions); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, `SELECT count(*) FROM agent_endpoint_assets WHERE tenant_id=$1 AND present`, f.tenant).Scan(&presentAssets); err != nil {
		t.Fatal(err)
	}
	if activeEvents != 1 || activeSessions != 1 || presentAssets != 1 {
		t.Fatalf("protected rows events=%d sessions=%d assets=%d", activeEvents, activeSessions, presentAssets)
	}
}

func TestAgentRetentionConfiguredDaysWithInjectedClock(t *testing.T) {
	db := agentEndpointTestDB(t)
	f := newAgentIngestFixture(t, db)
	repo := NewAgentEndpointRepository(db)
	ctx := context.Background()
	now := time.Date(2026, time.September, 23, 12, 0, 0, 0, time.UTC)
	oldID, recentID := "retention-old-"+uuid.NewString(), "retention-recent-"+uuid.NewString()
	for _, entry := range []struct {
		id string
		at time.Time
	}{
		{oldID, now.AddDate(0, 0, -31)},
		{recentID, now.AddDate(0, 0, -29)},
	} {
		if _, err := db.Exec(ctx, `INSERT INTO agent_events(id,tenant_id,endpoint_id,event_type,occurred_at,payload) VALUES($1,$2,$3,'tool.pre',$4,'{}')`, entry.id, f.tenant, f.endpoint, entry.at); err != nil {
			t.Fatal(err)
		}
	}
	// The configured 30-day window deletes the 31-day row but protects the 29-day row.
	result, err := repo.deleteRetainedDataAt(ctx, 30, now)
	if err != nil {
		t.Fatal(err)
	}
	var oldCount, recentCount int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM agent_events WHERE tenant_id=$1 AND id=$2`, f.tenant, oldID).Scan(&oldCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM agent_events WHERE tenant_id=$1 AND id=$2`, f.tenant, recentID).Scan(&recentCount); err != nil {
		t.Fatal(err)
	}
	if result.Events != 1 || oldCount != 0 || recentCount != 1 {
		t.Fatalf("retention 30 days: result=%+v old=%d recent=%d", result, oldCount, recentCount)
	}
}

func TestAgentEventSecurityEventDecision(t *testing.T) {
	cases := []struct {
		name       string
		sev, risk  string
		decision   string
		status     string
		wantSev    string
		wantAction string
		wantWrite  bool
	}{
		{"would_block excluded even if critical risk", "low", "critical", "would_block", "", "critical", "", false},
		{"would-block variant excluded", "low", "high", "would-block", "", "high", "", false},
		{"block forces high severity", "low", "low", "block", "", "high", "block", true},
		{"blocked decision forces high", "medium", "low", "blocked", "", "high", "block", true},
		{"deny is block", "low", "low", "deny", "", "high", "block", true},
		{"confirm forces high to clear inbox floor", "low", "low", "confirm", "", "high", "confirm", true},
		{"risk high surfaces", "low", "high", "allow", "", "high", "flag", true},
		{"risk critical surfaces", "low", "critical", "allow", "", "critical", "flag", true},
		{"low risk not alerted", "low", "low", "allow", "", "low", "", false},
		{"medium not alerted", "medium", "low", "allow", "", "medium", "", false},
		// 修正"合并 severity 触发"：authored severity=high 但 risk=low 且未阻断/确认，不得误告警。
		{"severity high risk low allow not alerted", "high", "low", "allow", "", "high", "", false},
		{"low severity must not mask high risk", "low", "high", "allow", "", "high", "flag", true},
		// 修正"误用工具 status 触发"：status=blocked 但有效决策为 allow（effective allow），不告警。
		{"status blocked with effective allow not alerted", "medium", "low", "allow", "blocked", "medium", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &agentEventRecord{Severity: c.sev, RiskLevel: c.risk, Decision: c.decision, Status: c.status}
			sev, act, write := agentEventSecurityEventDecision(r)
			if sev != c.wantSev || act != c.wantAction || write != c.wantWrite {
				t.Fatalf("got (sev=%s, action=%s, write=%v); want (sev=%s, action=%s, write=%v)",
					sev, act, write, c.wantSev, c.wantAction, c.wantWrite)
			}
		})
	}
}

// TestAgentEventDecisionResolution 验证 agentEventDecision 的有效决策解析优先级：
//   - effective_decision 优先于 decision/raw_decision（无论来自哪一源）。
//   - raw_decision=block 但 effective_decision=would_block 时，解析为 would_block（仅计数不告警）。
//   - 决策解析只看 effective_decision/decision/raw_decision，不参考工具 status。
func TestAgentEventDecisionResolution(t *testing.T) {
	cases := []struct {
		name                          string
		event, payload, local, server map[string]any
		want                          string
	}{
		{
			name:  "effective would_block beats raw block",
			event: map[string]any{"effective_decision": "would_block", "raw_decision": "block"},
			want:  "would_block",
		},
		{
			name:  "effective block beats raw would_block",
			event: map[string]any{"effective_decision": "block", "raw_decision": "would_block"},
			want:  "block",
		},
		{
			name:  "raw block with no effective resolves to block",
			event: map[string]any{"raw_decision": "block"},
			want:  "block",
		},
		{
			name:    "status blocked with allow decision resolves to allow",
			event:   map[string]any{"decision": "allow"},
			payload: map[string]any{"status": "blocked"},
			want:    "allow",
		},
		{
			name:   "local effective would_block overrides server raw block",
			local:  map[string]any{"effective_decision": "would_block"},
			server: map[string]any{"raw_decision": "block"},
			want:   "would_block",
		},
		{
			name:    "server overrides local/event/payload",
			event:   map[string]any{"raw_decision": "allow"},
			payload: map[string]any{"raw_decision": "deny"},
			local:   map[string]any{"raw_decision": "confirm"},
			server:  map[string]any{"raw_decision": "block"},
			want:    "block",
		},
		{
			name:    "local overrides event/payload when no server",
			event:   map[string]any{"raw_decision": "allow"},
			payload: map[string]any{"raw_decision": "deny"},
			local:   map[string]any{"raw_decision": "confirm"},
			want:    "confirm",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := agentEventDecision(c.event, c.payload, c.local, c.server); got != c.want {
				t.Fatalf("agentEventDecision = %q; want %q", got, c.want)
			}
		})
	}
}

func TestAgentEventSeverityHelpers(t *testing.T) {
	if got := agentEventMaxSeverity("low", "high"); got != "high" {
		t.Fatalf("agentEventMaxSeverity(low,high)=%s want high", got)
	}
	if got := agentEventMaxSeverity("", "critical"); got != "critical" {
		t.Fatalf("agentEventMaxSeverity(empty,critical)=%s want critical", got)
	}
	if got := agentEventMaxSeverity("medium", "low"); got != "medium" {
		t.Fatalf("agentEventMaxSeverity(medium,low)=%s want medium", got)
	}
	if r := agentEventSeverityRank("critical"); r != 3 {
		t.Fatalf("agentEventSeverityRank(critical)=%d want 3", r)
	}
	if agentEventBlocked("", "blocked") != true {
		t.Fatalf("agentEventBlocked(status=blocked) should be true")
	}
}
