package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Run against an isolated disposable PostgreSQL, never an application database.
func TestAlertOccurrencesPostgres(t *testing.T) {
	db := verifiedModelsTestDB(t)
	ctx := context.Background()
	_, err := db.Exec(ctx, `
ALTER TABLE request_logs ADD COLUMN project_id TEXT, ADD COLUMN user_id TEXT,
 ADD COLUMN client_id TEXT, ADD COLUMN session_id TEXT, ADD COLUMN agent_type TEXT,
 ADD COLUMN source_ip TEXT, ADD COLUMN proxy_source_ip TEXT, ADD COLUMN proxy_mode TEXT,
 ADD COLUMN principal_context_json JSONB, ADD COLUMN proxy_target_host TEXT;
CREATE TABLE security_events (
 id TEXT PRIMARY KEY, request_id TEXT, tenant_id TEXT, project_id TEXT, user_id TEXT,
 event_type TEXT, severity TEXT, rule_id TEXT, action_taken TEXT, matched_summary JSONB,
 principal_key TEXT, conversation_key TEXT, alert_group_id TEXT, evidence_ref TEXT,
 created_at TIMESTAMPTZ DEFAULT now(), agent_instance_id varchar(128));
CREATE TABLE users(id TEXT PRIMARY KEY, tenant_id TEXT, username TEXT, department_id TEXT);
CREATE TABLE internal_keys(id TEXT PRIMARY KEY, tenant_id TEXT, user_id TEXT, name TEXT, key_hash TEXT, agent_instance_id varchar(128));
CREATE TABLE teams(id TEXT PRIMARY KEY, tenant_id TEXT, name TEXT);
CREATE TABLE team_members(team_id TEXT, user_id TEXT, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE access_content_logs(id TEXT PRIMARY KEY, tenant_id TEXT, request_id TEXT, conversation_id TEXT, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE agent_events(id TEXT PRIMARY KEY, tenant_id TEXT, endpoint_id TEXT, session_id TEXT,
 tool_use_id TEXT, event_type TEXT, tool_name TEXT, tool_type TEXT, local_decision JSONB,
 security_event_id TEXT);
CREATE TABLE alert_groups(id TEXT PRIMARY KEY, tenant_id TEXT, status TEXT);
CREATE TABLE rule_sets (id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64), source_type VARCHAR(32), published BOOLEAN DEFAULT TRUE);
CREATE TABLE rules (id VARCHAR(64) PRIMARY KEY, name VARCHAR(255), rule_type VARCHAR(64), rule_set_id VARCHAR(64), scope_json JSONB DEFAULT '{}');
CREATE TABLE audit_dispositions(id text DEFAULT md5(random()::text),tenant_id TEXT, subject_type TEXT, subject_id TEXT, status TEXT,note text,operator_id text,operator_name text,created_at timestamptz DEFAULT now(),updated_at timestamptz DEFAULT now(),case_seen_through timestamptz,UNIQUE(tenant_id,subject_type,subject_id));
INSERT INTO tenants(id,name) VALUES('t1','T1'),('t2','T2');
INSERT INTO providers(id,tenant_id,name,provider_type) VALUES('model-provider','t1','Test provider','openai'),('foreign-provider','t2','Foreign provider','openai');
INSERT INTO models(id,provider_id,model_name) VALUES('model-local','model-provider','gpt-5.6-luna'),('model-foreign','foreign-provider','foreign-private-model');
INSERT INTO users VALUES('actor','t1','Alice','dept'),('owner','t1','Key owner','dept'),('foreign','t2','Foreign person','foreign-dept');
INSERT INTO teams VALUES('dept','t1','Risk'),('foreign-dept','t2','Foreign department');
INSERT INTO internal_keys VALUES('key','t1','owner','Shared application key','synthetic'),('foreign-key','t2','foreign','Foreign key','other');
INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,client_id,session_id,agent_type,principal_context_json) VALUES
 ('log1','req1','t1','p1','actor','key','same-session','codex','{"trust_level":"authenticated","actor_user_id":"actor","actor_department_ids":["dept"],"key_owner_user_id":"owner","key_id":"key","identity_source":"session"}'),
 ('log2','req2','t1','p1','owner','key','same-session','codex','{"trust_level":"key_bound","key_owner_user_id":"owner","key_id":"key","identity_source":"api_key"}'),
 ('log3','req3','t1','p2','actor',NULL,NULL,NULL,'{}'),
 ('log4','req4','t2','p1','foreign','foreign-key','foreign-session',NULL,'{}'),
 ('foreign-collision','missing-request','t2','p1','foreign','foreign-key','foreign-session',NULL,'{}');
UPDATE request_logs SET model_id='model-local' WHERE id='log1';
UPDATE request_logs SET model_id='model-foreign' WHERE id='log2';
INSERT INTO alert_groups VALUES('old-group','t1','false_positive');
INSERT INTO tenants(id,name) VALUES('rules','Rules'),('links','Links');
INSERT INTO rule_sets(id,tenant_id,source_type,published) VALUES('rs_rules','rules','custom',TRUE),('rs_links','links','custom',TRUE),('rs_draft','links','custom',FALSE),('rs_sys','`+SystemTenantID+`','builtin',TRUE);
INSERT INTO rules(id,name,rule_type,rule_set_id) VALUES('rule_997bd32c','密钥相关','regex','rs_rules'),('rule_x','项目代号','keyword','rs_rules');
`)
	if err != nil {
		t.Fatal(err)
	}
	insert := func(id, request, tenant, project, kind, severity, summary string) {
		t.Helper()
		_, err := db.Exec(ctx, `INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary,conversation_key) VALUES($1,$2,$3,$4,$5,$6,'block',$7::jsonb,'same-conversation')`, id, request, tenant, project, kind, severity, summary)
		if err != nil {
			t.Fatal(err)
		}
	}
	finding := func(index int, category, severity string) map[string]any {
		return map[string]any{"type": "pii", "category": category, "severity": severity, "rule_id": "rule-a", "message_index": index, "stage": "input", "content_source": "user", "matched_location": "content[2:12]", "action": "audit", "redacted_evidence": "a***@example.invalid", "raw_evidence": "alice@example.invalid", "evidence_context": "before alice@example.invalid after", "evidence_reason": "synthetic reason"}
	}
	encode := func(v any) string {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	findings := []any{}
	for i := 0; i < 420; i++ {
		findings = append(findings, map[string]any{"type": "system", "category": "security_check_failed", "severity": "critical", "message_index": i, "counts_as_security_finding": false, "evidence_kind": "runtime"})
	}
	critical := finding(422, "destructive_command", "critical")
	critical["raw_evidence"] = "synthetic critical sentence"
	critical["evidence_context"] = "critical context only"
	critical["evidence_reason"] = "critical reason only"
	findings = append(findings, finding(421, "email", "medium"), critical, finding(423, "email", "low"))
	dup := finding(421, "email", "high")
	dup["rule_id"] = "rule-b"
	findings = append(findings, dup)
	insert("event-a", "req1", "t1", "p1", "security_check", "critical", encode(map[string]any{"stage": "input", "findings": findings}))
	insert("event-b", "req1", "t1", "p1", "security_check", "critical", encode(map[string]any{"findings": []any{finding(421, "email", "high")}}))
	insert("event-turn2", "req2", "t1", "p1", "security_check", "critical", encode(map[string]any{"findings": []any{finding(421, "email", "high")}}))
	insert("event-project2", "req3", "t1", "p2", "security_check", "high", encode(map[string]any{"findings": []any{finding(1, "email", "high")}}))
	insert("event-foreign", "req4", "t2", "p1", "security_check", "high", encode(map[string]any{"findings": []any{finding(1, "email", "high")}}))
	insert("event-legacy", "missing-request", "t1", "p1", "security_check", "low", `{"category":"legacy_risk"}`)
	if _, err := db.Exec(ctx, `UPDATE security_events SET conversation_key=NULL WHERE id='event-legacy';
INSERT INTO access_content_logs VALUES('foreign-content','t2','missing-request','foreign-conversation',now())`); err != nil {
		t.Fatal(err)
	}
	insert("event-fault", "req1", "t1", "p1", "security_check_failed", "low", `{}`)
	insert("event-observations", "req1", "t1", "p1", "security_check", "critical", `{"findings":[],"observations":[{"category":"injection","severity":"critical"}]}`)
	insert("event-capacity", "req1", "t1", "p1", "security_check", "critical", `{"findings":[{"type":"file","category":"file_content_request_oversized","severity":"critical"}]}`)
	insert("event-passive", "req1", "t1", "p1", "security_check", "critical", `{"findings":[{"type":"agent","category":"agent_detected","rule_type":"agent_detect","action":"audit","severity":"critical"}]}`)
	suppressed := finding(424, "email", "high")
	suppressed["exception_id"] = "exception-1"
	insert("event-suppressed", "req1", "t1", "p1", "security_check", "high", encode(map[string]any{"findings": []any{suppressed}}))
	repo := NewAlertOccurrenceRepository(db)
	filter := AlertOccurrenceFilter{TenantID: "t1", Limit: 100, CanReadEvidence: true, IncludeRaw: true}

	t.Run("native alert evidence requires the exact tenant endpoint session and event link", func(t *testing.T) {
		defer db.Exec(ctx, `DELETE FROM agent_events WHERE security_event_id LIKE 'native-alert-%'; DELETE FROM security_events WHERE id LIKE 'native-alert-%'`)
		makeNativeSummary := func(agentEventID, endpointID, sessionID, toolUseID string) string {
			return encode(map[string]any{
				"source": "agent_endpoint", "agent_event_id": agentEventID,
				"endpoint_id": endpointID, "session_id": sessionID,
				"event_type": "tool.pre", "tool_use_id": toolUseID,
				"tool_name": "Bash", "risk_level": "high", "decision": "block",
			})
		}
		insert("native-alert-exact", "", "t1", "", "tool_execution_risk", "high",
			makeNativeSummary("native-agent-event", "ep-native", "native-session", "tool-native"))
		if _, err := db.Exec(ctx, `INSERT INTO agent_events(
            id,tenant_id,endpoint_id,session_id,tool_use_id,event_type,tool_name,tool_type,local_decision,security_event_id)
            VALUES('native-agent-event','t1','ep-native','native-session','tool-native','tool.pre','Bash','system',
            '{"source":"local","mode":"block","effective_decision":"block","raw_decision":"block","rule_id":"local-rule","policy_version":8,"policy_checksum":"sha256:local","risk_level":"high","secret_argument":"must-not-project"}',
            'native-alert-exact')`); err != nil {
			t.Fatal(err)
		}

		insert("native-alert-mismatch", "", "t1", "", "tool_execution_risk", "high",
			makeNativeSummary("native-agent-mismatch", "ep-native", "native-session", "tool-native"))
		if _, err := db.Exec(ctx, `INSERT INTO agent_events(
            id,tenant_id,endpoint_id,session_id,tool_use_id,event_type,tool_name,tool_type,local_decision,security_event_id)
            VALUES('native-agent-mismatch','t1','ep-other','native-session','tool-native','tool.pre','Bash','system',
            '{"source":"local","mode":"block","effective_decision":"block","policy_version":9}',
            'native-alert-mismatch')`); err != nil {
			t.Fatal(err)
		}

		insert("native-alert-foreign", "", "t1", "", "tool_execution_risk", "high",
			makeNativeSummary("foreign-agent-event", "ep-native", "native-session", "tool-native"))
		if _, err := db.Exec(ctx, `INSERT INTO agent_events(
            id,tenant_id,endpoint_id,session_id,tool_use_id,event_type,tool_name,tool_type,local_decision,security_event_id)
            VALUES('foreign-agent-event','t2','ep-native','native-session','tool-native','tool.pre','Bash','system',
            '{"source":"local","mode":"block","effective_decision":"block","policy_version":10}',
            'native-alert-foreign')`); err != nil {
			t.Fatal(err)
		}

		matched, err := repo.List(ctx, AlertOccurrenceFilter{
			TenantID: "t1", EventID: "native-alert-exact", SessionID: "native-session", Limit: 10,
		})
		if err != nil {
			t.Fatal(err)
		}
		if matched.Total != 1 || len(matched.Items) != 1 {
			t.Fatalf("exact native alert filter: %+v", matched)
		}
		evidence := matched.Items[0].AgentEndpointEvidence
		if evidence == nil || evidence.Status != "matched" || evidence.AgentEventID != "native-agent-event" ||
			evidence.EndpointID != "ep-native" || evidence.SessionID != "native-session" ||
			evidence.EventType != "tool.pre" || evidence.ToolUseID != "tool-native" || evidence.ToolName != "Bash" ||
			evidence.ToolType != "system" || matched.Items[0].AgentSessionID != "native-session" {
			t.Fatalf("exact native identity lost: occurrence=%+v evidence=%+v", matched.Items[0], evidence)
		}
		if evidence.LocalDecision["source"] != "local" || evidence.LocalDecision["mode"] != "block" ||
			evidence.LocalDecision["effective_decision"] != "block" || evidence.LocalDecision["raw_decision"] != "block" ||
			evidence.LocalDecision["rule_id"] != "local-rule" || evidence.LocalDecision["policy_version"] != float64(8) ||
			evidence.LocalDecision["policy_checksum"] != "sha256:local" || evidence.LocalDecision["risk_level"] != "high" {
			t.Fatalf("allowlisted local decision missing: %+v", evidence.LocalDecision)
		}
		if _, leaked := evidence.LocalDecision["secret_argument"]; leaked {
			t.Fatalf("non-display local decision field projected: %+v", evidence.LocalDecision)
		}

		for _, eventID := range []string{"native-alert-mismatch", "native-alert-foreign"} {
			page, err := repo.List(ctx, AlertOccurrenceFilter{
				TenantID: "t1", EventID: eventID, SessionID: "native-session", Limit: 10,
			})
			if err != nil {
				t.Fatal(err)
			}
			if page.Total != 1 || len(page.Items) != 1 {
				t.Fatalf("source-scoped session lookup for %s: %+v", eventID, page)
			}
			item := page.Items[0]
			if item.AgentSessionID != "" || item.AgentEndpointEvidence == nil || item.AgentEndpointEvidence.Status != "unmatched" ||
				len(item.AgentEndpointEvidence.LocalDecision) != 0 {
				t.Fatalf("mismatched/foreign native evidence became linkable for %s: %+v", eventID, item)
			}
		}
	})
	t.Run("agent session links require an endpoint source and stay tenant scoped", func(t *testing.T) {
		category := "agent_session_projection_test"
		for _, row := range []struct{ id, request, tenant, source, agentSession string }{
			{"agent-link", "req1", "t1", "agent_endpoint", "agent-session-real"},
			{"ordinary-link", "req2", "t1", "proxy", "agent-session-forged"},
			{"endpoint-no-session", "req3", "t1", "agent_endpoint", ""},
			{"foreign-agent-link", "req4", "t2", "agent_endpoint", "agent-session-foreign"},
		} {
			agentEventID, endpointID, toolUseID := "agent-event-"+row.id, "endpoint-"+row.id, "tool-"+row.id
			summary := map[string]any{"source": row.source, "session_id": row.agentSession,
				"agent_event_id": agentEventID, "endpoint_id": endpointID, "event_type": "tool.pre", "tool_use_id": toolUseID,
				"findings": []any{map[string]any{"type": "pii", "category": category, "severity": "low", "rule_id": "session-test"}}}
			insert(row.id, row.request, row.tenant, "p1", "security_check", "low", encode(summary))
			if row.source == "agent_endpoint" && row.agentSession != "" {
				if _, err := db.Exec(ctx, `INSERT INTO agent_events(id,tenant_id,endpoint_id,session_id,tool_use_id,event_type,security_event_id) VALUES($1,$2,$3,$4,$5,'tool.pre',$6)`, agentEventID, row.tenant, endpointID, row.agentSession, toolUseID, row.id); err != nil {
					t.Fatal(err)
				}
			}
		}
		defer db.Exec(ctx, `DELETE FROM security_events WHERE id IN ('agent-link','ordinary-link','endpoint-no-session','foreign-agent-link')`)
		p, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "t1", Category: category, Limit: 20})
		if err != nil {
			t.Fatal(err)
		}
		if p.Total != 3 || len(p.Items) != 3 {
			t.Fatalf("tenant-scoped hits: %+v", p)
		}
		byEvent := make(map[string]AlertOccurrence)
		for _, item := range p.Items {
			byEvent[item.EventID] = item
		}
		if got := byEvent["agent-link"]; got.AgentSessionID != "agent-session-real" || got.SessionID != "same-session" {
			t.Fatalf("endpoint identity or ordinary request session lost: %+v", got)
		}
		if got := byEvent["ordinary-link"]; got.AgentSessionID != "" || got.SessionID != "same-session" {
			t.Fatalf("ordinary request spoofed an agent link: %+v", got)
		}
		if got := byEvent["endpoint-no-session"]; got.AgentSessionID != "" || got.SessionID != "" {
			t.Fatalf("missing endpoint session invented a link: %+v", got)
		}
		byAgent, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "t1", Category: category, SessionID: "agent-session-real", Limit: 20})
		if err != nil {
			t.Fatal(err)
		}
		if len(byAgent.Items) != 1 || byAgent.Items[0].EventID != "agent-link" {
			t.Fatalf("endpoint session filter changed: %+v", byAgent)
		}
		foreign, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "t2", Category: category, Limit: 20})
		if err != nil {
			t.Fatal(err)
		}
		if len(foreign.Items) != 1 || foreign.Items[0].AgentSessionID != "agent-session-foreign" {
			t.Fatalf("foreign tenant scoped hit changed: %+v", foreign)
		}
		groups, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "t1", Category: category, Grouping: "cases", Limit: 20})
		if err != nil {
			t.Fatal(err)
		}
		if groups.Total == 0 {
			t.Fatal("expected endpoint case")
		}
		for _, item := range groups.Items {
			if item.AgentSessionID == "agent-session-foreign" {
				t.Fatalf("case crossed tenant boundary: %+v", item)
			}
			members, memberErr := repo.List(ctx, AlertOccurrenceFilter{TenantID: "t1", Category: category, CaseID: item.CaseID, Limit: 20})
			if memberErr != nil {
				t.Fatal(memberErr)
			}
			for _, member := range members.Items {
				if member.AgentSessionID == "agent-session-foreign" {
					t.Fatalf("member crossed tenant boundary: %+v", member)
				}
			}
		}
	})

	t.Run("verified endpoint tool risk without findings is visible", func(t *testing.T) {
		for _, row := range []struct{ id, tenant, source, kind, risk, decision, action string }{
			{"endpoint-confirm-real-shape", "t1", "agent_endpoint", "tool_execution_risk", "high", "confirm", "confirm"},
			{"endpoint-block-real-shape", "t2", "agent_endpoint", "tool_execution_risk", "high", "block", "block"},
			{"endpoint-nontool-confirm", "t1", "agent_endpoint", "agent_endpoint_risk", "low", "confirm", "confirm"},
			{"endpoint-high-risk-flag", "t1", "agent_endpoint", "agent_endpoint_risk", "high", "allow", "flag"},
			{"ordinary-fake-endpoint", "t1", "proxy", "tool_execution_risk", "high", "confirm", "confirm"},
			{"endpoint-low-risk", "t1", "agent_endpoint", "tool_execution_risk", "low", "allow", "flag"},
			{"endpoint-would-block", "t1", "agent_endpoint", "tool_execution_risk", "high", "would_block", "flag"},
			{"endpoint-generic-event", "t1", "agent_endpoint", "security_check", "high", "confirm", "confirm"},
			{"endpoint-observation-only", "t1", "agent_endpoint", "tool_execution_risk", "high", "confirm", "confirm"},
		} {
			summary := map[string]any{"source": row.source, "session_id": "endpoint-session-verified", "stage": "tool", "risk_level": row.risk, "decision": row.decision}
			if row.source == "agent_endpoint" {
				agentEventID, endpointID, toolUseID := "agent-event-"+row.id, "endpoint-"+row.id, "tool-"+row.id
				summary["agent_event_id"], summary["endpoint_id"], summary["event_type"], summary["tool_use_id"] = agentEventID, endpointID, "tool.pre", toolUseID
				if _, err := db.Exec(ctx, `INSERT INTO agent_events(id,tenant_id,endpoint_id,session_id,tool_use_id,event_type,security_event_id) VALUES($1,$2,$3,'endpoint-session-verified',$4,'tool.pre',$5)`, agentEventID, row.tenant, endpointID, toolUseID, row.id); err != nil {
					t.Fatal(err)
				}
			}
			if row.id == "endpoint-observation-only" {
				summary["observations"] = []any{map[string]any{"category": "runtime"}}
			}
			_, err := db.Exec(ctx, `INSERT INTO security_events(id,tenant_id,event_type,severity,action_taken,matched_summary) VALUES($1,$2,$3,'high',$4,$5::jsonb)`, row.id, row.tenant, row.kind, row.action, encode(summary))
			if err != nil {
				t.Fatal(err)
			}
		}
		defer db.Exec(ctx, `DELETE FROM security_events WHERE id IN ('endpoint-confirm-real-shape','endpoint-block-real-shape','endpoint-nontool-confirm','endpoint-high-risk-flag','ordinary-fake-endpoint','endpoint-low-risk','endpoint-would-block','endpoint-generic-event','endpoint-observation-only')`)
		p, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "t1", EventID: "endpoint-confirm-real-shape", Limit: 20})
		if err != nil {
			t.Fatal(err)
		}
		if p.Total != 1 || len(p.Items) != 1 || p.Items[0].AgentSessionID != "endpoint-session-verified" || p.Items[0].Category != "tool_execution_risk" {
			t.Fatalf("endpoint risk lost: %+v", p)
		}
		for _, id := range []string{"endpoint-nontool-confirm", "endpoint-high-risk-flag"} {
			got, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "t1", EventID: id, Limit: 20})
			if err != nil {
				t.Fatal(err)
			}
			if got.Total != 1 || len(got.Items) != 1 {
				t.Fatalf("valid endpoint risk %s missing: %+v", id, got)
			}
		}
		for _, id := range []string{"ordinary-fake-endpoint", "endpoint-low-risk", "endpoint-would-block", "endpoint-generic-event", "endpoint-observation-only"} {
			got, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "t1", EventID: id, Limit: 20})
			if err != nil {
				t.Fatal(err)
			}
			if got.Total != 0 {
				t.Fatalf("non-finding %s leaked into alerts: %+v", id, got)
			}
		}
		other, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "t2", EventID: "endpoint-block-real-shape", Limit: 20})
		if err != nil {
			t.Fatal(err)
		}
		if other.Total != 1 || len(other.Items) != 1 {
			t.Fatalf("other tenant endpoint risk lost: %+v", other)
		}
		cross, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "t1", EventID: "endpoint-block-real-shape", Limit: 20})
		if err != nil {
			t.Fatal(err)
		}
		if cross.Total != 0 {
			t.Fatalf("endpoint risk crossed tenant: %+v", cross)
		}
	})

	t.Run("credential evidence contract and policy duplicates", func(t *testing.T) {
		f1 := map[string]any{"type": "secret", "category": "plain_password", "severity": "medium", "rule_id": "policy-one", "content_source": "model_output", "matched_location": "content[0:20]", "raw_evidence_sha256": strings.Repeat("a", 64), "matched_text_preview": "syn***tic", "triage": map[string]any{"validation_status": "literal_candidate", "credential_validity": "unknown", "confidence_kind": "heuristic_rule_score", "review_status": "not_requested"}}
		f2 := map[string]any{}
		for k, v := range f1 {
			f2[k] = v
		}
		f2["rule_id"] = "policy-two"
		f2["severity"] = "critical"
		insert("event-credential-contract", "req1", "t1", "p1", "proxy_output_audit", "critical", encode(map[string]any{"stage": "output", "findings": []any{f1, f2}}))
		defer db.Exec(ctx, "DELETE FROM security_events WHERE id='event-credential-contract'")
		p, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "t1", Category: "plain_password", Limit: 20, CanReadEvidence: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Items) != 1 {
			t.Fatalf("same evidence duplicated: %+v", p)
		}
		got := p.Items[0]
		if got.DuplicateCount != 2 || len(got.RuleIDs) != 2 || got.Severity != "critical" {
			t.Fatalf("policy details lost: %+v", got)
		}
		if got.ValidationStatus != "literal_candidate" || got.ModelReviewStatus != "not_requested" || got.CredentialValidity != "unknown" || got.ConfidenceKind != "heuristic_rule_score" {
			t.Fatalf("assessment lost: %+v", got)
		}
		if got.RedactedEvidence != "syn***tic" || got.MatchedLocation != "content[0:20]" || got.LocationStatus != "available" {
			t.Fatalf("legacy preview or location lost: %+v", got)
		}
		if got.RawEvidence != "" {
			t.Fatal("invented raw evidence")
		}
		grouped, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "t1", Grouping: "cases", Category: "plain_password", Limit: 20, CanReadEvidence: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(grouped.Items) != 1 || grouped.Items[0].HitCount != 1 || grouped.Items[0].RequestCount != 1 {
			t.Fatalf("policy copies inflated case counts: %+v", grouped)
		}
		members, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "t1", CaseID: grouped.Items[0].CaseID, Limit: 20, CanReadEvidence: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(members.Items) != 1 || len(members.Items[0].RuleIDs) != 2 {
			t.Fatalf("case members lost policy links: %+v", members)
		}

	})
	page, err := repo.List(ctx, filter)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 6 || len(page.Items) != 6 || page.Counts.Total != 7 || page.Counts.Suppressed != 1 {
		t.Fatalf("unexpected page: %+v", page)
	}
	if page.Operational.EventCount != 3 {
		t.Fatalf("fault, capacity and mixed-event gaps must remain visible separately: %+v", page.Operational)
	}
	var email, turn, legacy *AlertOccurrence
	for i := range page.Items {
		row := &page.Items[i]
		if row.RequestID == "req1" && row.MessageIndex != nil && *row.MessageIndex == 421 {
			email = row
		}
		if row.RequestID == "req2" {
			turn = row
		}
		if row.EventID == "event-legacy" {
			legacy = row
		}
	}
	if email == nil || email.Severity != "medium" || email.ActionTaken != "audit" || email.EventActionTaken != "block" || email.DuplicateCount != 3 {
		t.Fatalf("finding severity/action crossed rows: %+v", email)
	}
	if email.FindingIndex == nil || *email.FindingIndex != 420 || email.ActorUserID != "actor" || email.ActorName != "Alice" || email.DepartmentName != "Risk" || email.KeyOwnerUserID != "owner" || email.CredentialID != "key" {
		t.Fatalf("attribution/index lost: %+v", email)
	}
	if email.RawEvidence != "alice@example.invalid" || email.EvidenceContext != "before alice@example.invalid after" {
		t.Fatalf("raw windows changed: %+v", email)
	}
	if turn == nil || turn.Severity != "high" || turn.ID == email.ID || turn.ActorUserID != "" || turn.KeyOwnerUserID != "owner" || turn.IdentityReliability != "credential" {
		t.Fatalf("turns merged or credential owner fabricated as actor: %+v", turn)
	}
	if legacy == nil || legacy.MessageIndex != nil || legacy.FindingIndex != nil || legacy.EvidenceStatus != "missing" || legacy.SessionID != "" || legacy.ActorName != "" || legacy.ConversationKey != "" || legacy.ConversationID != "" || legacy.ConversationReliability != "unknown" {
		t.Fatalf("legacy missing anchors/cross-tenant join: %+v", legacy)
	}

	if email.ModelName != "gpt-5.6-luna" || turn.ModelName != "" {
		t.Fatalf("model display lookup missing or leaked cross-tenant model: local=%q foreign=%q", email.ModelName, turn.ModelName)
	}

	t.Run("pagination-and-counts-after-expansion", func(t *testing.T) {
		seen := map[string]bool{}
		for offset := 0; offset < page.Total; offset += 2 {
			f := filter
			f.Limit = 2
			f.Offset = offset
			p, e := repo.List(ctx, f)
			if e != nil {
				t.Fatal(e)
			}
			if p.Total != page.Total || len(p.Items) != 2 {
				t.Fatalf("bad page: %+v", p)
			}
			for _, r := range p.Items {
				if seen[r.ID] {
					t.Fatalf("duplicate on pages: %s", r.ID)
				}
				seen[r.ID] = true
			}
		}
		f := filter
		f.Offset = 999
		p, e := repo.List(ctx, f)
		if e != nil || p.Total != 6 || len(p.Items) != 0 {
			t.Fatalf("empty page lost total: %+v %v", p, e)
		}
	})
	t.Run("scopes-and-row-severity", func(t *testing.T) {
		f := filter
		f.ProjectIDs = []string{"p1"}
		f.Severity = "medium"
		p, e := repo.List(ctx, f)
		if e != nil || p.Total != 1 || p.Items[0].ID != email.ID {
			t.Fatalf("row severity filter: %+v %v", p, e)
		}
		f.Severity = ""
		f.ProjectIDs = []string{}
		p, e = repo.List(ctx, f)
		if e != nil || p.Total != 0 || p.Counts.Total != 0 || p.Operational.EventCount != 0 {
			t.Fatalf("empty scope leaked: %+v %v", p, e)
		}
		f = filter
		f.TenantID = "t2"
		p, e = repo.List(ctx, f)
		if e != nil || p.Total != 1 || p.Items[0].EventID != "event-foreign" {
			t.Fatalf("tenant filter: %+v %v", p, e)
		}
	})
	t.Run("redaction-and-suppression", func(t *testing.T) {
		f := filter
		f.CanReadEvidence = false
		f.IncludeRaw = true // SQL must also enforce permission, even for a mistaken caller.
		f.RequestID = "req1"
		f.IncludeSuppressed = true
		p, e := repo.List(ctx, f)
		if e != nil || p.Total != 4 {
			t.Fatalf("suppression filter: %+v %v", p, e)
		}
		for _, r := range p.Items {
			if r.RawEvidence != "" || r.EvidenceContext != "" || r.Reason != "" || r.RawEvidenceStatus != "restricted" {
				t.Fatalf("raw leak: %+v", r)
			}
		}
	})
	t.Run("historical-preview-and-missing-finding-severity", func(t *testing.T) {
		f1 := finding(0, "own_unknown", "high")
		delete(f1, "severity")
		delete(f1, "raw_evidence")
		delete(f1, "evidence_context")
		f1["matched_text_preview"] = "historical preview only"
		insert("event-preview", "req1", "t1", "p1", "security_check", "critical", encode(map[string]any{"findings": []any{f1}}))
		f := filter
		f.Category = "own_unknown"
		p, e := repo.List(ctx, f)
		if e != nil || p.Total != 1 {
			t.Fatalf("preview query: %+v %v", p, e)
		}
		r := p.Items[0]
		if r.Severity != "unknown" || r.RawEvidence != "" || r.RawEvidenceStatus != "missing" || r.MatchedTextPreview != "historical preview only" {
			t.Fatalf("preview was promoted or severity inherited: %+v", r)
		}
		f.CanReadEvidence = false
		p, e = repo.List(ctx, f)
		if e != nil || p.Items[0].MatchedTextPreview != "" || p.Items[0].RawEvidence != "" {
			t.Fatalf("preview leaked: %+v %v", p, e)
		}
	})
	t.Run("unknown-anchors-stay-distinct", func(t *testing.T) {
		f1 := finding(0, "unknown_location", "high")
		delete(f1, "message_index")
		f2 := finding(0, "unknown_location", "low")
		delete(f2, "message_index")
		insert("event-unknown", "req1", "t1", "p1", "security_check", "critical", encode(map[string]any{"findings": []any{f1, f2}}))
		f := filter
		f.Category = "unknown_location"
		p, e := repo.List(ctx, f)
		if e != nil || p.Total != 2 {
			t.Fatalf("unknown anchors merged: %+v %v", p, e)
		}
		for _, r := range p.Items {
			if r.MessageIndex != nil || r.LocationStatus != "missing" {
				t.Fatalf("fabricated anchor: %+v", r)
			}
		}
	})
	t.Run("zero-index-attachments-and-stages", func(t *testing.T) {
		rows := []any{}
		for i := 0; i < 3; i++ {
			r := finding(0, "zero", "high")
			r["attachment_index"] = i
			rows = append(rows, r)
		}
		r := finding(0, "zero", "low")
		r["stage"] = "output"
		rows = append(rows, r)
		insert("event-zero", "req1", "t1", "p1", "security_check", "critical", encode(map[string]any{"findings": rows}))
		f := filter
		f.Category = "zero"
		p, e := repo.List(ctx, f)
		if e != nil || p.Total != 4 {
			t.Fatalf("zero index/stage lost: %+v %v", p, e)
		}
		for _, r := range p.Items {
			if r.MessageIndex == nil || *r.MessageIndex != 0 {
				t.Fatalf("zero index invalid: %+v", r)
			}
		}
	})
	t.Run("operational-gaps-are-separate-scoped-events", func(t *testing.T) {
		insert("op-status", "req1", "t1", "p1", "security_check", "critical", `{"semantic_status":"incomplete","semantic_reason":"private source text","findings":[]}`)
		insert("op-engine", "req1", "t1", "p1", "security_check", "critical", `{"findings":[{"type":"engine_runtime","category":"detector_timeout","severity":"critical","raw_evidence":"private"}]}`)
		insert("op-regex", "req1", "t1", "p1", "security_check", "critical", `{"findings":[{"type":"regex_timeout","category":"regex_timeout","severity":"high"}]}`)
		insert("op-completed", "req1", "t1", "p1", "security_inspection_completed", "low", `{"inspection_status":"completed"}`)
		insert("op-observation", "req1", "t1", "p1", "security_check", "low", `{"findings":[{"type":"semantic","category":"observation","counts_as_security_finding":false}]}`)
		insert("op-foreign", "req4", "t2", "p1", "security_check_failed", "low", `{}`)
		insert("op-other-project", "req3", "t1", "p2", "security_check_failed", "low", `{}`)
		f := filter
		f.ProjectIDs = []string{"p1"}
		f.RequestID = "req1"
		f.Severity = "medium"
		f.Category = "email"
		p, e := repo.List(ctx, f)
		if e != nil || p.Total != 1 || p.Operational.EventCount != 6 {
			t.Fatalf("risk filter hid gaps or gap became attack: %+v %v", p, e)
		}
		f.SessionID = "same-session"
		f.UserID = "actor"
		p, e = repo.List(ctx, f)
		if e != nil || p.Operational.EventCount != 6 {
			t.Fatalf("operational identity/session scope drift: %+v %v", p, e)
		}
		f.Severity = ""
		f.Category = ""
		f.Limit = 2
		seen := map[string]bool{}
		for offset := 0; offset < 6; offset += 2 {
			f.Offset = offset
			ops, e := repo.ListOperational(ctx, f)
			if e != nil || ops.Total != 6 || len(ops.Items) != 2 {
				t.Fatalf("operational pagination: %+v %v", ops, e)
			}
			for _, op := range ops.Items {
				if seen[op.EventID] || op.RequestID != "req1" || op.ProjectID != "p1" {
					t.Fatalf("duplicate or unscoped gap: %+v", op)
				}
				seen[op.EventID] = true
			}
			data, _ := json.Marshal(ops)
			if strings.Contains(string(data), "private") {
				t.Fatalf("operational metadata leaked raw diagnostic: %s", data)
			}
		}
		f.Offset = 99
		ops, e := repo.ListOperational(ctx, f)
		if e != nil || ops.Total != 6 || len(ops.Items) != 0 {
			t.Fatalf("past-end total: %+v %v", ops, e)
		}
		f.ProjectIDs = []string{}
		ops, e = repo.ListOperational(ctx, f)
		if e != nil || ops.Total != 0 {
			t.Fatalf("empty project scope leaked operational events: %+v %v", ops, e)
		}
		f = filter
		f.TenantID = "t2"
		ops, e = repo.ListOperational(ctx, f)
		if e != nil || ops.Total != 1 || ops.Items[0].EventID != "op-foreign" {
			t.Fatalf("cross-tenant operational count: %+v %v", ops, e)
		}
	})

	t.Run("durable-retry-status-does-not-remove-history", func(t *testing.T) {
		for _, status := range []string{"retry_pending", "rechecked_complete", "retry_exhausted", "retry_not_saved"} {
			summary := encode(map[string]any{"semantic_status": "incomplete", "semantic_reason": "judge_unavailable", "remediation": map[string]any{"status": status}})
			insert("op-retry-status", "req1", "t1", "p1", "security_check_failed", "low", summary)
			p, e := repo.ListOperational(ctx, AlertOccurrenceFilter{TenantID: "t1", EventID: "op-retry-status", Limit: 10})
			if e != nil || len(p.Items) != 1 || p.Items[0].RemediationStatus != status {
				t.Fatalf("retry status lost %+v %v", p, e)
			}
			db.Exec(ctx, "DELETE FROM security_events WHERE id='op-retry-status'")
		}
	})

	t.Run("disposition-tabs-filter-before-pagination-and-keep-scope-counts", func(t *testing.T) {
		for _, id := range []string{"tab-open", "tab-done", "tab-fp"} {
			insert(id, "tab-request", "t1", "p1", "security_check", "high", `{"findings":[{"type":"pii","category":"email","severity":"high"}]}`)
		}
		defer db.Exec(ctx, `DELETE FROM security_events WHERE request_id='tab-request'; DELETE FROM audit_dispositions WHERE subject_id IN ('tab-done','tab-fp')`)
		_, err := db.Exec(ctx, `INSERT INTO audit_dispositions(tenant_id,subject_type,subject_id,status) VALUES('t1','security_event','tab-done','resolved'),('t1','security_event','tab-fp','false_positive')`)
		if err != nil {
			t.Fatal(err)
		}
		for _, status := range []string{"pending", "handled", "false_positive", "all"} {
			f := filter
			f.RequestID = "tab-request"
			f.IncludeSuppressed = true
			f.Disposition = status
			f.Limit = 1
			rows, err := repo.List(ctx, f)
			want := 1
			if status == "all" {
				want = 3
			}
			if err != nil || rows.Total != want || len(rows.Items) != 1 || rows.Counts.Pending != 1 || rows.Counts.Handled != 1 || rows.Counts.FalsePositive != 1 || rows.Counts.Last24h != 3 {
				t.Fatalf("tab %s: %+v %v", status, rows, err)
			}
			if status == "pending" && rows.Items[0].EventID != "tab-open" {
				t.Fatalf("pending got %+v", rows.Items[0])
			}
			if status == "false_positive" && rows.Items[0].EventID != "tab-fp" {
				t.Fatal("false positive missing")
			}
		}
	})

	t.Run("event-source-ip-survives-expired-request-log", func(t *testing.T) {
		insert("retained-ip", "retained-ip-request", "t1", "p1", "proxy_input_audit", "high", `{"source_ip":"192.0.2.77","findings":[{"type":"pii","category":"email","severity":"high"}]}`)
		defer db.Exec(ctx, `DELETE FROM security_events WHERE id='retained-ip'`)
		f := filter
		f.RequestID = "retained-ip-request"
		rows, err := repo.List(ctx, f)
		if err != nil || rows.Total != 1 {
			t.Fatalf("event identity: %+v %v", rows, err)
		}
		if rows.Items[0].SourceIP != "192.0.2.77" || rows.Items[0].ActorUserID != "" {
			t.Fatalf("retain source identity without inventing a user: %+v", rows.Items[0])
		}
	})

	t.Run("legacy-input-timeout-keeps-safe-reason-and-stage", func(t *testing.T) {
		insert("legacy-timeout", "legacy-timeout-req", "t1", "p1", "security_check", "low", `{"summary":"input security pipeline unavailable; first_failed_message=3 (failure_mode=close, attachments=0, timeout=true)","findings_count":0}`)
		_, err := db.Exec(ctx, `UPDATE security_events SET action_taken='security_check_failed' WHERE id='legacy-timeout'`)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Exec(ctx, `DELETE FROM security_events WHERE id='legacy-timeout'`)
		f := filter
		f.RequestID = "legacy-timeout-req"
		f.Reason = "security_pipeline_timeout"
		ops, err := repo.ListOperational(ctx, f)
		if err != nil || ops.Total != 1 {
			t.Fatalf("legacy timeout: %+v %v", ops, err)
		}
		if got := ops.Items[0]; got.Stage != "input" || got.Blocked || got.Reason != "security_pipeline_timeout" {
			t.Fatalf("timeout does not prove request blocked: %+v", got)
		}
		data, _ := json.Marshal(ops)
		if strings.Contains(string(data), "failure_mode") {
			t.Fatalf("raw diagnostic leaked: %s", data)
		}
	})

	t.Run("operational-reasons-and-breakdown-follow-scope", func(t *testing.T) {
		insert("gap-json", "req1", "t1", "p1", "security_check_failed", "low", `{"stage":"input","semantic_status":"incomplete","semantic_reason":"inspection_invalid_json","findings":[]}`)
		insert("gap-deferred", "req1", "t1", "p1", "security_check_failed", "low", `{"stage":"input","semantic_status":"incomplete","semantic_reason":"judge_capacity_deferred","findings":[]}`)
		insert("gap-overflow", "req1", "t1", "p1", "security_check", "critical", `{"stage":"input","semantic_status":"incomplete","semantic_reason":"judge_capacity_overflow","findings":[{"type":"semantic_telemetry","category":"semantic_capacity_overflow","evidence_kind":"runtime","counts_as_security_finding":false}]}`)
		insert("gap-durable", "req1", "t1", "p1", "proxy_input_audit", "low", `{"stage":"input","inspection_status":"failed","findings":[]}`)
		insert("gap-old", "req1", "t1", "p1", "security_check_failed", "low", `{"stage":"input","semantic_status":"incomplete","semantic_reason":"inspection_invalid_json","findings":[]}`)
		insert("gap-foreign-reason", "req4", "t2", "p1", "security_check_failed", "low", `{"semantic_reason":"inspection_invalid_json","findings":[]}`)
		insert("gap-action-only", "req1", "t1", "p1", "security_check", "low", `{"summary":"engine unavailable: private detail","findings_count":0}`)
		if _, err := db.Exec(ctx, `UPDATE security_events SET action_taken='audit' WHERE id IN ('gap-deferred','gap-overflow','gap-durable');
UPDATE security_events SET action_taken='security_check_failed' WHERE id='gap-action-only';
UPDATE security_events SET created_at=now()-interval '3 days' WHERE id='gap-old'`); err != nil {
			t.Fatal(err)
		}
		f := filter
		f.RequestID = "req1"
		ops, e := repo.ListOperational(ctx, f)
		if e != nil {
			t.Fatal(e)
		}
		reasons := map[string]AlertOperationalEvent{}
		for _, op := range ops.Items {
			reasons[op.EventID] = op
		}
		// Free-text diagnostics never become a reason identifier.
		for id, want := range map[string]string{"gap-json": "inspection_invalid_json", "gap-deferred": "judge_capacity_deferred", "gap-overflow": "judge_capacity_overflow", "gap-durable": "inspection_failed", "op-engine": "detector_timeout", "op-regex": "regex_timeout", "event-fault": "security_check_failed", "op-status": "semantic_incomplete", "gap-action-only": "security_check_failed"} {
			if got := reasons[id]; got.Reason != want {
				t.Fatalf("%s reason=%q want %q (%+v)", id, got.Reason, want, got)
			}
		}
		if leaked, _ := json.Marshal(ops); strings.Contains(string(leaked), "private") {
			t.Fatalf("operational reason leaked free-text diagnostic: %s", leaked)
		}
		if !reasons["gap-json"].Blocked || reasons["gap-deferred"].Blocked {
			t.Fatalf("blocked flag: %+v %+v", reasons["gap-json"], reasons["gap-deferred"])
		}
		f.Reason = "inspection_invalid_json"
		ops, e = repo.ListOperational(ctx, f)
		if e != nil || ops.Total != 2 || len(ops.Items) != 2 {
			t.Fatalf("reason filter: %+v %v", ops, e)
		}
		for _, op := range ops.Items {
			if op.Reason != "inspection_invalid_json" || op.RequestID != "req1" {
				t.Fatalf("reason filter leaked: %+v", op)
			}
		}
		f.Reason = "no_such_reason"
		if ops, e = repo.ListOperational(ctx, f); e != nil || ops.Total != 0 {
			t.Fatalf("unknown reason: %+v %v", ops, e)
		}
		f.Reason = "bad reason"
		if _, e = repo.ListOperational(ctx, f); e == nil {
			t.Fatal("invalid reason identifier accepted")
		}
		f.Reason = ""
		summary, e := repo.SummarizeOperational(ctx, f)
		if e != nil {
			t.Fatal(e)
		}
		if summary.CountUnit != "security_events" || summary.EventCount != len(reasons) {
			t.Fatalf("summary total: %+v (list=%d)", summary, len(reasons))
		}
		if summary.Last24hCount != summary.EventCount-1 || summary.BlockedCount != summary.EventCount-4 || summary.LatestAt == nil {
			t.Fatalf("summary windows: %+v", summary)
		}
		byReason := map[string]AlertOperationalReasonCount{}
		for _, r := range summary.Reasons {
			byReason[r.Reason] = r
		}
		if got := byReason["inspection_invalid_json"]; got.EventCount != 2 || got.Last24hCount != 1 || got.BlockedCount != 2 {
			t.Fatalf("invalid json breakdown: %+v", got)
		}
		if got := byReason["judge_capacity_deferred"]; got.EventCount != 1 || got.BlockedCount != 0 {
			t.Fatalf("deferred breakdown: %+v", got)
		}
		if _, ok := byReason["judge_capacity_overflow"]; !ok {
			t.Fatalf("overflow reason missing: %+v", summary.Reasons)
		}
		if summary.Reasons[0].EventCount < summary.Reasons[len(summary.Reasons)-1].EventCount {
			t.Fatalf("reasons must be ordered by count: %+v", summary.Reasons)
		}
		t2 := AlertOccurrenceFilter{TenantID: "t2"}
		if s, e := repo.SummarizeOperational(ctx, t2); e != nil || s.EventCount != 2 || len(s.Reasons) != 2 {
			t.Fatalf("cross-tenant summary: %+v %v", s, e)
		}
		empty := f
		empty.ProjectIDs = []string{}
		if s, e := repo.SummarizeOperational(ctx, empty); e != nil || s.EventCount != 0 || len(s.Reasons) != 0 || s.LatestAt != nil {
			t.Fatalf("empty scope summary: %+v %v", s, e)
		}
		before := time.Now().Add(-time.Hour).UTC()
		older := f
		older.EndTime = &before
		if s, e := repo.SummarizeOperational(ctx, older); e != nil || s.EventCount != 1 || s.Last24hCount != 0 || s.Reasons[0].Reason != "inspection_invalid_json" {
			t.Fatalf("time-scoped summary: %+v %v", s, e)
		}
		if _, err := db.Exec(ctx, `DELETE FROM security_events WHERE id IN ('gap-json','gap-deferred','gap-overflow','gap-durable','gap-old','gap-foreign-reason','gap-action-only')`); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("empty-and-remediated-findings-never-resurrect-event-risk", func(t *testing.T) {
		cases := []struct {
			name, summary string
			want          int
		}{
			{"empty", `{"findings":[]}`, 0},
			{"empty-with-stale-root", `{"findings":[],"category":"email","severity":"critical","raw_evidence":"stale original risk"}`, 0},
			{"remediated", `{"category":"email","severity":"critical","findings":[{"type":"pii","category":"email","severity":"critical","counts_as_security_finding":false},{"type":"secret","category":"secret_leak","severity":"high","counts_as_security_finding":"false"}]}`, 0},
			{"legacy-bare", `{}`, 0},
			{"legacy-null-without-risk", `{"findings":null,"severity":"critical","stage":"input"}`, 0},
			{"legacy-nonstructured-without-risk", `{"findings":{}}`, 0},
			{"legacy-explicit-risk", `{"findings":null,"category":"email","severity":"medium","redacted_evidence":"a***@example.invalid"}`, 1},
		}
		for _, tc := range cases {
			insert("shape-"+tc.name, "shape-"+tc.name, "shapes", "p1", "security_check", "critical", tc.summary)
			f := AlertOccurrenceFilter{TenantID: "shapes", RequestID: "shape-" + tc.name, IncludeSuppressed: true, Limit: 20}
			p, e := repo.List(ctx, f)
			if e != nil || p.Total != tc.want || p.Counts.Total != tc.want || len(p.Items) != tc.want {
				t.Fatalf("%s invented or lost risk: %+v %v", tc.name, p, e)
			}
			if tc.want == 1 && (p.Items[0].FindingIndex != nil || p.Items[0].Severity != "medium") {
				t.Fatalf("legacy fallback lost its own explicit evidence: %+v", p.Items[0])
			}
		}
	})
	t.Run("model-review-labels-cannot-hide-active-findings", func(t *testing.T) {
		cases := []struct {
			name, kind, category, state, position string
			confidence                            float64
		}{
			{"pii-generic-fp", "pii", "id_card_cn", "likely_false_positive", "triage", 0.95},
			{"pii-low-confidence", "pii", "email", "benign", "triage", 0.2},
			{"shadow-fp", "prompt_injection", "injection", "false_positive", "triage", 0.95},
			{"catalog-suppressed-label", "catalog_policy", "prompt_leak_internal_rules", "suppressed", "triage", 0.95},
			{"custom-finding-label", "custom", "prompt_leak_internal_rules", "likely_false_positive", "finding", 0.95},
			{"legacy-root-label", "pii", "email", "benign", "event", 0.95},
			{"pending-review", "pii", "email", "review_pending", "triage", 0},
			{"pending-event-review", "prompt_injection", "injection", "review_pending", "event", 0},
			{"unavailable-review", "pii", "email", "unavailable", "triage", 0},
			{"needs-review", "pii", "email", "needs_review", "triage", 0},
			{"protected-secret", "secret", "openai_key", "likely_false_positive", "triage", 0.95},
			{"protected-data", "data_leak", "code_leak", "benign", "triage", 0.95},
		}
		wantStates := map[string]string{}
		for i, tc := range cases {
			hit := finding(i, tc.category, "high")
			hit["type"] = tc.kind
			hit["counts_as_security_finding"] = true
			if tc.name == "legacy-root-label" {
				delete(hit, "counts_as_security_finding")
			}
			summary := map[string]any{"findings": []any{hit}}
			switch tc.position {
			case "triage":
				hit["triage"] = map[string]any{"verdict": tc.state, "confidence": tc.confidence, "review_mode": "shadow", "review_status": "incomplete"}
			case "finding":
				hit["review_state"] = tc.state
			case "event":
				summary["review_state"] = tc.state
			}
			id := "advisory-" + tc.name
			wantStates[id] = tc.state
			insert(id, id, "advisory", "p1", "security_check", "critical", encode(summary))
		}
		f := AlertOccurrenceFilter{TenantID: "advisory", ProjectIDs: []string{"p1"}, Limit: 100, CanReadEvidence: true, IncludeRaw: true}
		p, e := repo.List(ctx, f)
		if e != nil {
			t.Fatal(e)
		}
		if p.Total != len(cases) || len(p.Items) != len(cases) || p.Counts.Active != len(cases) || p.Counts.Suppressed != 0 || p.Counts.Pending != len(cases) || p.Counts.High != len(cases) || p.Counts.Critical != 0 {
			t.Fatalf("advisory labels changed visibility/counts: %+v", p)
		}
		ids := map[string]bool{}
		for _, row := range p.Items {
			if row.Suppressed || row.SuppressionReason != "" || row.ReviewState != wantStates[row.EventID] || row.Severity != "high" || row.ActionTaken != "audit" || row.RawEvidence != "alice@example.invalid" {
				t.Fatalf("model opinion changed the finding or its evidence: %+v", row)
			}
			ids[row.ID] = true
		}
		f.IncludeSuppressed = true
		p, e = repo.List(ctx, f)
		if e != nil || p.Total != len(cases) {
			t.Fatalf("include_suppressed changed advisory-only rows: %+v %v", p, e)
		}
		for _, row := range p.Items {
			if !ids[row.ID] {
				t.Fatalf("advisory row identity changed: %s", row.ID)
			}
		}
	})
	t.Run("explicit-decisions-remain-authoritative", func(t *testing.T) {
		for _, name := range []string{"event", "request", "group", "exception", "flag", "disabled", "model-only"} {
			hit := finding(0, "email", "high")
			hit["counts_as_security_finding"] = name != "disabled"
			hit["triage"] = map[string]any{"verdict": "confirmed_risk", "confidence": 0.99}
			if name == "model-only" {
				hit["triage"] = map[string]any{"verdict": "likely_false_positive", "confidence": 0.99}
			}
			if name == "exception" {
				hit["exception_id"] = "approved-exception"
			}
			if name == "flag" {
				hit["suppressed"] = true
			}
			id := "decision-" + name
			insert(id, id, "decisions", "p1", "security_check", "critical", encode(map[string]any{"findings": []any{hit}}))
		}
		_, e := db.Exec(ctx, `INSERT INTO audit_dispositions(tenant_id,subject_type,subject_id,status) VALUES
('decisions','security_event','decision-event','false_positive'),
('decisions','request','decision-request','ignored'),
('unrelated','security_event','decision-model-only','false_positive');
INSERT INTO alert_groups VALUES('decision-group-id','decisions','false_positive');
UPDATE security_events SET alert_group_id='decision-group-id' WHERE tenant_id='decisions' AND id='decision-group'`)
		if e != nil {
			t.Fatal(e)
		}
		f := AlertOccurrenceFilter{TenantID: "decisions", ProjectIDs: []string{"p1"}, Limit: 100}
		p, e := repo.List(ctx, f)
		if e != nil || p.Total != 1 || len(p.Items) != 1 || p.Items[0].EventID != "decision-model-only" || p.Counts.Active != 1 || p.Counts.Suppressed != 5 || p.Counts.Total != 6 || p.Counts.Pending != 1 {
			t.Fatalf("explicit suppression or tenant isolation changed: %+v %v", p, e)
		}
		f.IncludeSuppressed = true
		p, e = repo.List(ctx, f)
		if e != nil || p.Total != 6 || len(p.Items) != 6 {
			t.Fatalf("explicit decisions not inspectable: %+v %v", p, e)
		}
		want := map[string]string{"decision-event": "false_positive", "decision-request": "ignored", "decision-group": "false_positive", "decision-exception": "policy_exception", "decision-flag": "finding_suppressed", "decision-model-only": ""}
		for _, row := range p.Items {
			reason, ok := want[row.EventID]
			if !ok || row.SuppressionReason != reason || row.Suppressed != (reason != "") {
				t.Fatalf("wrong suppression authority or disabled finding resurrected: %+v", row)
			}
		}
	})
	t.Run("pending-means-open-and-unsuppressed", func(t *testing.T) {
		// 待处置 = disposition 未闭环且无抑制，不是"未抑制"的代名词：resolved 处置后
		// 仍为有效告警（active）但不再是待办，false_positive 处置连同抑制一起离开两口径。
		for _, name := range []string{"open", "resolved", "false-positive"} {
			hit := finding(0, "email", "high")
			id := "pending-" + name
			insert(id, id, "pending", "p1", "security_check", "high", encode(map[string]any{"findings": []any{hit}}))
		}
		_, e := db.Exec(ctx, `INSERT INTO audit_dispositions(tenant_id,subject_type,subject_id,status) VALUES
('pending','security_event','pending-resolved','resolved'),
('pending','security_event','pending-false-positive','false_positive')`)
		if e != nil {
			t.Fatal(e)
		}
		f := AlertOccurrenceFilter{TenantID: "pending", ProjectIDs: []string{"p1"}, Limit: 100}
		p, e := repo.List(ctx, f)
		if e != nil || p.Total != 2 || p.Counts.Total != 3 || p.Counts.Active != 2 || p.Counts.Suppressed != 1 || p.Counts.Pending != 1 {
			t.Fatalf("pending must be disposition-open and unsuppressed, not active: %+v %v", p, e)
		}
		if len(p.Items) != 2 || p.Items[0].EventID == "pending-false-positive" || p.Items[1].EventID == "pending-false-positive" {
			t.Fatalf("default view hides suppressed rows while keeping the backlog visible: %+v", p.Items)
		}
	})
	t.Run("audit-snapshot-volume-with-isolated-synthetic-data", func(t *testing.T) {
		// Reproduce the reported scale, never the customer's data or live database.
		_, e := db.Exec(ctx, `INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary)
SELECT 'scale-gap-'||g,'scale-request-'||g,'scale','p1','security_check_failed','low','audit','{"semantic_status":"incomplete"}'::jsonb
FROM generate_series(1,118149) g;
INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary)
SELECT 'scale-complete-'||g,'scale-request-'||g,'scale','p1','security_inspection_completed','low','audit','{}'::jsonb
FROM generate_series(1,45913) g`)
		if e != nil {
			t.Fatal(e)
		}
		insert("scale-finding", "scale-request", "scale", "p1", "security_check", "critical", encode(map[string]any{"findings": []any{finding(0, "email", "medium")}}))
		f := AlertOccurrenceFilter{TenantID: "scale", Limit: 20}
		started := time.Now()
		p, e := repo.List(ctx, f)
		if e != nil || p.Total != 1 || len(p.Items) != 1 || p.Operational.EventCount != 118149 {
			t.Fatalf("scale count/page: %+v %v", p, e)
		}
		t.Logf("164063 synthetic events: one finding page + operational count in %s", time.Since(started))
		ops, e := repo.ListOperational(ctx, f)
		if e != nil || ops.Total != 118149 || len(ops.Items) != 20 {
			t.Fatalf("scale operational page: %+v %v", ops, e)
		}

		// Event count alone was a misleading performance fixture: the failing
		// default page had tens of thousands of findings with long source windows.
		// Exercise unscoped admin pagination, counts and evidence on that shape.
		_, e = db.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('scale','Synthetic scale');
INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,session_id)
SELECT 'wide-log-'||g,'wide-request-'||g,'scale','p1','scale-actor','wide-session-'||(g/10)
FROM generate_series(1,30000) g;
INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary)
SELECT 'wide-event-'||g,'wide-request-'||g,'scale','p1','security_check','critical','audit',
 jsonb_build_object('semantic_status',CASE WHEN g%7=0 THEN 'incomplete' ELSE 'completed' END,
   'findings',jsonb_build_array(jsonb_build_object('type','pii','category','synthetic_leak',
     'severity','medium','rule_id','wide-rule','message_index',g%10,'stage','input','content_source','user',
     'matched_location','content[2:12]','counts_as_security_finding',g%10<>0,
     'redacted_evidence','synthetic masked hit','raw_evidence','synthetic hit '||g,
     'evidence_context',repeat(md5(g::text),768))))
FROM generate_series(1,30000) g;
ANALYZE security_events; ANALYZE request_logs;`)
		if e != nil {
			t.Fatal(e)
		}
		largeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		started = time.Now()
		p, e = repo.List(largeCtx, f)
		if e != nil {
			t.Fatal(e)
		}
		if p.Total != 27001 || len(p.Items) != 20 || p.Operational.EventCount != 118149+4285 {
			t.Fatalf("wide history counts: total=%d items=%d operational=%d", p.Total, len(p.Items), p.Operational.EventCount)
		}
		t.Logf("194063 events / 30000 long-context findings, default page: %s", time.Since(started))
		ids := map[string]bool{}
		for _, row := range p.Items {
			ids[row.ID] = true
			if row.RawEvidence != "" || row.EvidenceContext != "" || row.ActorUserID != "scale-actor" {
				t.Fatal("list evidence boundary or late actor lookup changed")
			}
		}
		f.Offset = 20
		second, e := repo.List(ctx, f)
		if e != nil || second.Total != p.Total || len(second.Items) != 20 {
			t.Fatalf("wide history second page: %v", e)
		}
		for _, row := range second.Items {
			if ids[row.ID] {
				t.Fatal("default pages overlap")
			}
		}
		f.Offset, f.RequestID, f.IncludeRaw, f.CanReadEvidence = 0, p.Items[0].RequestID, true, true
		detail, e := repo.List(ctx, f)
		if e != nil || detail.Total != 1 || len(detail.Items) != 1 {
			t.Fatalf("wide history exact evidence: %v", e)
		}
		if detail.Items[0].ID != p.Items[0].ID || len(detail.Items[0].EvidenceContext) != 32*768 || detail.Items[0].RawEvidence != "synthetic hit "+strings.TrimPrefix(f.RequestID, "wide-request-") {
			t.Fatal("late evidence lookup changed the selected occurrence")
		}
	})
	t.Run("cases-count-rule-names-and-carry-policy-links", func(t *testing.T) {
		_, err := db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,client_id,session_id,created_at) VALUES
('rn-r1','rn-r1','rules','p1','actor','key','rn-convo',now());`)
		if err != nil {
			t.Fatal(err)
		}
		insert("ev-rn-1", "rn-r1", "rules", "p1", "security_check", "high", `{"stage":"input","findings":[
{"category":"customer_sensitive_data","severity":"high","content_source":"user","rule_id":"rule_997bd32c","rule_name":"密钥相关","rule_type":"regex","policy_code":"custom.secret","triage":{"severity_downgrade_reason":""}},
{"category":"customer_sensitive_data","severity":"medium","content_source":"user","rule_id":"rule_x","rule_name":"项目代号","rule_type":"keyword","triage":{"severity_downgrade_reason":"只命中字段名，未见真实值"}}]}`)
		page, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "rules", Grouping: "cases", IncludeSuppressed: true, Limit: 100})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("cases: %+v %v", page, err)
		}
		item := page.Items[0]
		if item.RuleNameCount != 2 || item.RuleName != "密钥相关" || item.RuleType != "regex" {
			t.Fatalf("case rule names: count=%d representative=%q type=%q", item.RuleNameCount, item.RuleName, item.RuleType)
		}
		if item.PolicyCode != "custom.secret" {
			t.Fatalf("policy code must come from the representative hit: %q", item.PolicyCode)
		}
		if item.PolicyLink == nil || item.PolicyLink.Path != "/security/policies?policy=rule_997bd32c" {
			t.Fatalf("policy link: %+v", item.PolicyLink)
		}
		lane, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "rules", Grouping: "cases", LaneAware: true, Lane: "action", IncludeSuppressed: true, Limit: 100})
		if err != nil || len(lane.Items) != 1 || lane.Items[0].RuleNameCount != 2 || lane.Items[0].RuleName != "密钥相关" {
			t.Fatalf("lane view rule names: %+v %v", lane, err)
		}
		hits, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "rules", CaseID: item.CaseID, Grouping: "hits", IncludeSuppressed: true, Limit: 100})
		if err != nil || len(hits.Items) != 2 {
			t.Fatalf("hits: %+v %v", hits, err)
		}
		reasons := map[string]string{}
		for _, hit := range hits.Items {
			reasons[hit.RuleName] = hit.SeverityDowngradeReason
		}
		if reasons["项目代号"] != "只命中字段名，未见真实值" || reasons["密钥相关"] != "" {
			t.Fatalf("downgrade reasons: %+v", reasons)
		}
	})
	t.Run("policy-links-follow-rule-visibility", func(t *testing.T) {
		_, err := db.Exec(ctx, `INSERT INTO rules(id,name,rule_type,rule_set_id,scope_json) VALUES
('rule_live','存活规则','regex','rs_links','{}'),
('rule_tomb','已删规则','regex','rs_links','{"deleted_at":"2026-11-13T00:00:00Z"}'),
('rule_draft','草稿规则','regex','rs_draft','{}'),
('rule_foreign','别家规则','regex','rs_rules','{}'),
('rule_sys','预置规则','keyword','rs_sys','{}');
INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,client_id,session_id,created_at) VALUES
('lk-r1','lk-r1','links','p1','actor','key','lk-convo',now());`)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]string{"rule_live": "存活规则", "rule_tomb": "已删规则", "rule_draft": "草稿规则", "rule_foreign": "别家规则", "rule_sys": "预置规则", "rule_gone": "物理删除规则"}
		findings := []string{}
		for id, name := range names {
			findings = append(findings, fmt.Sprintf(`{"category":"c_%s","severity":"high","content_source":"user","rule_id":%q,"rule_name":%q,"rule_type":"regex"}`, id, id, name))
		}
		findings = append(findings, `{"category":"c_cat","severity":"high","content_source":"user","rule_id":"catalog_x","rule_name":"目录规则","rule_type":"builtin"}`)
		insert("ev-lk-1", "lk-r1", "links", "p1", "security_check", "high", `{"stage":"input","findings":[`+strings.Join(findings, ",")+`]}`)
		hits, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "links", Grouping: "hits", IncludeSuppressed: true, Limit: 100})
		if err != nil || len(hits.Items) != 7 {
			t.Fatalf("hits: %+v %v", hits, err)
		}
		got := map[string]*PolicyLink{}
		for _, hit := range hits.Items {
			got[hit.RuleID] = hit.PolicyLink
		}
		for _, id := range []string{"rule_live", "rule_sys"} {
			if l := got[id]; l == nil || l.Kind != "policy" || l.Path != "/security/policies?policy="+id {
				t.Fatalf("%s should link: %+v", id, l)
			}
		}
		for _, id := range []string{"rule_tomb", "rule_draft", "rule_foreign", "rule_gone"} {
			if l := got[id]; l == nil || l.Kind != "deleted" || l.Path != "" || l.Label != names[id] {
				t.Fatalf("%s should read as deleted: %+v", id, l)
			}
		}
		if got["catalog_x"] != nil {
			t.Fatalf("catalog rule must not link: %+v", got["catalog_x"])
		}
		// 规则表查不到时，列表照常返回，链接降为空，不标“已删除”。
		restore := func() {
			if _, err := db.Exec(ctx, `ALTER TABLE IF EXISTS rules_renamed RENAME TO rules`); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.Exec(ctx, `ALTER TABLE rules RENAME TO rules_renamed`); err != nil {
			t.Fatal(err)
		}
		defer restore()
		hits, err = repo.List(ctx, AlertOccurrenceFilter{TenantID: "links", Grouping: "hits", IncludeSuppressed: true, Limit: 100})
		if err != nil || len(hits.Items) != 7 {
			t.Fatalf("list must survive a failing visibility lookup: %+v %v", hits, err)
		}
		for _, hit := range hits.Items {
			if hit.PolicyLink != nil {
				t.Fatalf("%s: unknown visibility must not claim a link or a deletion: %+v", hit.RuleID, hit.PolicyLink)
			}
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		items := []AlertOccurrence{{RuleID: "rule_live", RuleType: "regex"}}
		if err := repo.attachAlertPolicyLinks(canceled, "links", items); err == nil {
			t.Fatal("a canceled context must still return the error")
		}
	})
	t.Run("triage-cases-group-repeat-findings-preserve-evidence-and-scope", func(t *testing.T) {
		_, err := db.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('cases','Cases');
INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,client_id,session_id,created_at) VALUES
('case-r1','case-r1','cases','p1','actor','key','case-convo',date_trunc('day',now())),
('case-r2','case-r2','cases','p1','actor','key','case-convo',date_trunc('day',now())+interval '1 minute'),
('case-old','case-old','cases','p1','actor','key','old-convo',now()-interval '2 days');`)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"case-r1", "case-r2", "case-old"} {
			insert("ev-"+id, id, "cases", "p1", "security_check", "high", `{"stage":"input","findings":[{"category":"email","severity":"high","content_source":"user","raw_evidence":"first@example.invalid"},{"category":"email","severity":"low","content_source":"user","raw_evidence":"second@example.invalid"},{"category":"credential","severity":"critical","content_source":"user","raw_evidence":"synthetic-credential"}]}`)
		}
		if _, err := db.Exec(ctx, `UPDATE security_events SET conversation_key='old-conversation' WHERE id='ev-case-old'`); err != nil {
			t.Fatal(err)
		}
		f := AlertOccurrenceFilter{TenantID: "cases", Grouping: "cases", IncludeSuppressed: true, Limit: 100}
		page, err := repo.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if page.Operational.CountKnown || page.CountUnit != "triage_cases" || page.Total != 4 || page.Counts.RawHits != 9 || page.Counts.Last24h != 2 || page.Counts.Delayed24h != 2 {
			t.Fatalf("case counters: %+v", page)
		}
		var selected AlertOccurrence
		for _, item := range page.Items {
			if item.Category == "pii_email" && item.HitCount == 4 {
				selected = item
			}
		}
		if selected.CaseID == "" || selected.RequestCount != 2 || selected.Severity != "high" {
			t.Fatalf("group summary: %+v", selected)
		}
		members, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "cases", CaseID: selected.CaseID, Grouping: "hits", IncludeSuppressed: true, CanReadEvidence: true, IncludeRaw: true, Limit: 100})
		if err != nil || members.Total != 4 {
			t.Fatalf("members: %+v %v", members, err)
		}
		if members.Items[0].RawEvidence == "" {
			t.Fatal("exact member evidence missing")
		}
		auth := NewAuditDispositionRepository(db)
		if _, err := auth.UpsertAuthorized(ctx, &AuditDisposition{TenantID: "cases", SubjectType: "alert_case", SubjectID: selected.CaseID, Status: "resolved"}, nil, "", ""); err == nil {
			t.Fatal("missing review snapshot accepted")
		}
		future := time.Now().Add(time.Minute)
		if _, err := auth.UpsertAuthorized(ctx, &AuditDisposition{TenantID: "cases", SubjectType: "alert_case", SubjectID: selected.CaseID, Status: "resolved", CaseSeenThrough: &future}, nil, "", ""); err == nil {
			t.Fatal("future review snapshot accepted")
		}
		through := *selected.LastDetectedAt
		if _, err := auth.UpsertAuthorized(ctx, &AuditDisposition{TenantID: "cases", SubjectType: "alert_case", SubjectID: selected.CaseID, Status: "false_positive", CaseSeenThrough: &through}, []string{"p2"}, "", ""); err != ErrNotFound {
			t.Fatalf("project scope escaped: %v", err)
		}
		if _, err := auth.UpsertAuthorized(ctx, &AuditDisposition{TenantID: "t2", SubjectType: "alert_case", SubjectID: selected.CaseID, Status: "false_positive", CaseSeenThrough: &through}, nil, "", ""); err != ErrNotFound {
			t.Fatalf("tenant scope escaped: %v", err)
		}
		if _, err := auth.UpsertAuthorized(ctx, &AuditDisposition{TenantID: "cases", SubjectType: "alert_case", SubjectID: selected.CaseID, Status: "false_positive", CaseSeenThrough: &through}, nil, "", ""); err != nil {
			t.Fatal(err)
		}
		page, err = repo.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if page.Counts.FalsePositive != 1 || page.Counts.Pending != 3 {
			t.Fatalf("review must not close sibling credential risk: %+v", page.Counts)
		}
		insert("case-identical-repeat", "case-r2", "cases", "p1", "security_check", "high", `{"stage":"input","findings":[{"category":"email","severity":"high","content_source":"user","raw_evidence":"first@example.invalid","evidence_context":"another explanatory context around the same literal"}]}`)
		page, err = repo.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if page.Counts.FalsePositive != 1 {
			t.Fatalf("identical old evidence must not reopen: %+v", page.Counts)
		}
		insert("case-new-hit", "case-r2", "cases", "p1", "security_check", "high", `{"stage":"input","findings":[{"category":"email","severity":"high","content_source":"user","raw_evidence":"new@example.invalid"}]}`)
		if _, e := auth.UpsertAuthorized(ctx, &AuditDisposition{TenantID: "cases", SubjectType: "alert_case", SubjectID: selected.CaseID, Status: "resolved", CaseSeenThrough: &through}, nil, "", ""); e != ErrStaleCaseSnapshot {
			t.Fatalf("stale review must not report success: %v", e)
		}
		page, err = repo.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if page.Counts.Pending != 4 || page.Counts.FalsePositive != 0 {
			t.Fatalf("new unseen evidence must reopen: %+v", page.Counts)
		}
		_, err = db.Exec(ctx, `UPDATE request_logs SET created_at=now()-interval '2 days' WHERE request_id='case-r1'; UPDATE security_events SET created_at=now()-interval '2 days' WHERE id='ev-case-r1'`)
		if err != nil {
			t.Fatal(err)
		}
		page, err = repo.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != 4 || page.Counts.Last24h != 0 || page.Counts.Delayed24h != 2 {
			t.Fatalf("same conversation must not restart first occurrence on a new day: %+v", page.Counts)
		}

	})

	t.Run("case-identity-distinguishes-keys-with-one-owner", func(t *testing.T) {
		_, err := db.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('case-keys','Cases');
 INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,client_id,session_id,principal_context_json) VALUES
 ('key-r1','key-r1','case-keys','p1','owner','key-A','one-session','{"trust_level":"key_bound","key_id":"key-A"}'),
 ('key-r2','key-r2','case-keys','p1','owner','key-B','one-session','{"trust_level":"key_bound","key_id":"key-B"}');`)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"key-r1", "key-r2"} {
			insert(id, id, "case-keys", "p1", "security_check", "high", `{"findings":[{"category":"email","severity":"high","raw_evidence":"same@example.invalid"}]}`)
		}
		_, err = db.Exec(ctx, `UPDATE security_events SET principal_key='owner' WHERE tenant_id='case-keys'`)
		if err != nil {
			t.Fatal(err)
		}
		page, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "case-keys", Grouping: "cases", Limit: 20})
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != 2 {
			t.Fatalf("different credentials must not be conflated with their owner: %+v", page)
		}
	})

	t.Run("case-members-retain-all-original-finding-indices", func(t *testing.T) {
		_, err := db.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('case-indices','I');INSERT INTO request_logs(id,request_id,tenant_id,project_id,client_id) VALUES('indices-r','indices-r','case-indices','p','key');`)
		if err != nil {
			t.Fatal(err)
		}
		insert("indices-event", "indices-r", "case-indices", "p", "security_check", "high", `{"findings":[{"category":"email","severity":"high","message_index":1,"matched_location":"content[0:10]","raw_evidence":"same@example.invalid"},{"category":"email","severity":"low","message_index":1,"matched_location":"content[0:10]","raw_evidence":"same@example.invalid"}]}`)
		page, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "case-indices", Grouping: "cases", Limit: 20})
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != 1 || page.Items[0].HitCount != 2 {
			t.Fatalf("original records collapsed inside case: %+v", page)
		}
		rows, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "case-indices", EventID: "indices-event", IncludeRaw: true, CanReadEvidence: true, Limit: 20})
		if err != nil {
			t.Fatal(err)
		}
		if rows.Total != 2 || len(rows.Items) != 2 {
			t.Fatalf("an exact finding index became unreadable: %+v", rows)
		}
	})

	t.Run("legacy-forward-proxy-display-keeps-tenant-and-project-boundaries", func(t *testing.T) {
		_, err := db.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('identity-display','Display');
ALTER TABLE request_logs ADD COLUMN proxy_access_type TEXT, ADD COLUMN proxy_access_type_resolved TEXT, ADD COLUMN proxy_product TEXT;
INSERT INTO request_logs(id,request_id,tenant_id,project_id,source_ip,proxy_mode,proxy_target_host,proxy_access_type,proxy_access_type_resolved,proxy_product) VALUES
 ('display-r','display-r','identity-display',NULL,'192.0.2.20','forward','copilot.example.invalid','unknown','ai_ide','codebuddy'),
 ('display-wrong-project','display-wrong-project','identity-display','other-project','192.0.2.99','forward','wrong.example.invalid','web','web','wrong'),
 ('display-foreign','display-foreign','t2',NULL,'192.0.2.98','forward','foreign.example.invalid','web','web','foreign'),
 ('display-api','display-api','identity-display',NULL,'192.0.2.97','chat_completion','','','','');`)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range []struct{ id, request, project string }{
			{"display-default", "display-r", "project_default"},
			{"display-other", "display-r", "private-project"},
			{"display-wrong-project", "display-wrong-project", "project_default"},
			{"display-foreign", "display-foreign", "project_default"},
			{"display-nonproxy", "display-api", "project_default"},
		} {
			insert(v.id, v.request, "identity-display", v.project, "security_check", "high", `{"access_type":"ai_ide","product":"codebuddy","findings":[{"category":"email","severity":"high"}]}`)
			page, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "identity-display", EventID: v.id, Limit: 20})
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Items) != 1 {
				t.Fatalf("missing event %s", v.id)
			}
			item := page.Items[0]
			if v.id == "display-default" {
				if item.SourceIP != "192.0.2.20" || item.AccessDirection != "forward" || item.AccessType != "ai_ide" || item.ClientProduct != "codebuddy" || item.TargetHost != "copilot.example.invalid" {
					t.Fatalf("missing or wrong request metadata: %+v", item)
				}
			} else if item.SourceIP != "" || item.AccessDirection != "" {
				t.Fatalf("crossed project or transport boundary: %+v", item)
			}
		}
	})

	t.Run("reverse-proxy-events-with-default-project-still-find-their-request", func(t *testing.T) {
		// 反向代理的请求日志 project_id 为空，而它的安全事件写的是 project_default。
		// 事件必须能关联到自己的请求（来源 IP、客户端、传输方式），否则告警页会满屏"未记录"。
		// 同时保住三条边界：不跨租户、不跨具名项目、不串到无关传输方式。
		if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('rp-display','RP') ON CONFLICT DO NOTHING;
INSERT INTO request_logs(id,request_id,tenant_id,project_id,source_ip,proxy_source_ip,proxy_mode,agent_type,client_id) VALUES
 ('rp-ok','rp-ok','rp-display',NULL,'192.0.2.31','192.0.2.30','reverse','openai-codex','caller_abc'),
 ('rp-named','rp-named','rp-display','private-project','192.0.2.41',NULL,'reverse','openai-codex','caller_named'),
 ('rp-foreign','rp-foreign','t2',NULL,'192.0.2.51',NULL,'reverse','openai-codex','caller_foreign'),
 ('rp-api','rp-api','rp-display',NULL,'192.0.2.61',NULL,'chat_completion','openai-codex','caller_api');`); err != nil {
			t.Fatal(err)
		}
		cases := []struct{ id, request, project string; wantIP, wantAgent string }{
			{"rp-e-ok", "rp-ok", "project_default", "192.0.2.30", "openai-codex"},
			{"rp-e-named", "rp-named", "project_default", "", ""},
			{"rp-e-foreign", "rp-foreign", "project_default", "", ""},
			{"rp-e-api", "rp-api", "project_default", "", ""},
			{"rp-e-same", "rp-ok", "private-project", "", ""},
		}
		for _, v := range cases {
			insert(v.id, v.request, "rp-display", v.project, "security_check", "high", `{"findings":[{"category":"email","severity":"high"}]}`)
			page, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "rp-display", EventID: v.id, Limit: 20})
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Items) != 1 {
				t.Fatalf("missing event %s", v.id)
			}
			item := page.Items[0]
			if item.SourceIP != v.wantIP || item.AgentType != v.wantAgent {
				t.Errorf("%s: source_ip=%q agent=%q want %q/%q", v.id, item.SourceIP, item.AgentType, v.wantIP, v.wantAgent)
			}
		}
	})

	t.Run("recent-cases-cap-counts-tabs-and-pages-without-truncating-hits", func(t *testing.T) {
		_, err := db.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('recent-cases','Recent');
INSERT INTO request_logs(id,request_id,tenant_id,project_id,session_id,created_at)
 SELECT 'recent-r-'||i,'recent-r-'||i,'recent-cases','recent-project','recent-session-'||i,now()-i*interval '1 day' FROM generate_series(1,105) i;
INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary,created_at)
 SELECT 'recent-e-'||i,'recent-r-'||i,'recent-cases','recent-project','security_check','high','audit',
 '{"findings":[{"category":"email","severity":"high","message_index":1},{"category":"email","severity":"low","message_index":2}]}'::jsonb,
 now()-i*interval '1 minute' FROM generate_series(1,105) i;`)
		if err != nil {
			t.Fatal(err)
		}
		f := AlertOccurrenceFilter{TenantID: "recent-cases", Grouping: "cases", RecentLimit: 100, IncludeSuppressed: true, Limit: 10}
		page, err := repo.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != 100 || page.Counts.Total != 100 || page.Counts.RawHits != 200 || len(page.Items) != 10 || page.Items[0].RequestID != "recent-r-1" {
			t.Fatalf("wrong recent scope: %+v", page)
		}
		caseID := page.Items[0].CaseID
		_, err = db.Exec(ctx, `INSERT INTO audit_dispositions(tenant_id,subject_type,subject_id,status) VALUES('recent-cases','alert_case',$1,'resolved')`, caseID)
		if err != nil {
			t.Fatal(err)
		}
		f.Disposition = "pending"
		page, err = repo.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != 99 || page.Counts.Total != 100 || page.Counts.Handled != 1 {
			t.Fatalf("tabs changed recent set: %+v", page)
		}
		f.Disposition = "all"
		f.Offset = 90
		page, err = repo.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 10 || page.Items[9].RequestID != "recent-r-100" {
			t.Fatalf("last page or hidden 90-day cutoff: %+v", page)
		}
		f.Offset = 100
		page, err = repo.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 0 || page.Total != 100 {
			t.Fatalf("cap did not hold across pagination: %+v", page)
		}
		f.Offset = 0
		f.RecentLimit = 0
		page, err = repo.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != 105 {
			t.Fatalf("time-range mode lost older cases: %+v", page)
		}
		f.RecentLimit = 100
		f.ProjectIDs = []string{"other-project"}
		page, err = repo.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != 0 {
			t.Fatalf("recent scope bypassed projects: %+v", page)
		}
		f.ProjectIDs = nil
		f.Grouping = "hits"
		f.CaseID = caseID
		page, err = repo.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != 2 {
			t.Fatalf("case members truncated: %+v", page)
		}
	})

	t.Run("lanes-split-cases-by-trusted-evaluation-key-and-severity", func(t *testing.T) {
		// 车道只信管理员标记的 internal_keys.traffic_class；凭据改名、请求头都不能让告警逃进测评/观察车道。
		if _, err := db.Exec(ctx, `ALTER TABLE internal_keys ADD COLUMN IF NOT EXISTS traffic_class TEXT NOT NULL DEFAULT '';
INSERT INTO tenants(id,name) VALUES('lanes','Lanes');
INSERT INTO internal_keys(id,tenant_id,name,key_hash,traffic_class) VALUES
 ('lane-eval','lanes','评测目标','h-eval','evaluation'),
 ('lane-prod','lanes','正常业务','h-prod',''),
 ('lane-spoof','lanes','lse-spoofed-name','h-spoof',''),
 ('lane-coding','lanes','编程助手','h-coding','coding');
INSERT INTO request_logs(id,request_id,tenant_id,project_id,client_id)
 SELECT 'l-'||r.id,'lane-r'||r.id,'lanes','lane-project',r.client FROM (VALUES
 (1,'lane-eval'),(2,'lane-eval'),(3,'lane-eval'),(4,'lane-prod'),(5,'lane-prod'),(6,'lane-prod'),(7,'lane-prod'),
 (8,'lane-spoof'),(9,'lane-prod'),(10,'lane-coding'),(11,'lane-coding'),(12,'lane-coding')) r(id,client);
INSERT INTO request_logs(id,request_id,tenant_id,project_id,client_id) VALUES
 ('l-13','lane-r13','lanes','project_upgrade_verify_0123456789abcdef','lane-prod'),
 ('l-14','lane-r14','lanes','project_upgrade_verify_0123456789abcdef','lane-prod'),
 ('l-15','lane-r15','lanes','projectXupgradeXverifyX0123456789','lane-prod');`); err != nil {
			t.Fatal(err)
		}
		putIn := func(project string, n int, typ, category, severity string, extra string) {
			t.Helper()
			summary := `{"findings":[{"type":"` + typ + `","category":"` + category + `","severity":"` + severity + `","stage":"input","content_source":"user","message_index":0` + extra + `}]}`
			if _, err := db.Exec(ctx, `INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary,created_at)
 VALUES($1,$2,'lanes',$6,'security_check',$3,'audit',$4::jsonb,now()-($5::int*interval '1 minute'))`,
				fmt.Sprintf("lane-e%d", n), fmt.Sprintf("lane-r%d", n), severity, summary, n, project); err != nil {
				t.Fatal(err)
			}
		}
		put := func(n int, typ, category, severity string, extra string) {
			t.Helper()
			putIn("lane-project", n, typ, category, severity, extra)
		}
		put(1, "semantic_attack", "prompt_input_semantic_risk", "high", "") // 测评凭据的攻击样本
		put(2, "secret", "openai_key", "critical", "")                      // 测评凭据里出现真密钥格式：不放过
		put(3, "content_safety", "agent_canary_token_leak", "critical", "") // 测评自带的 canary
		put(4, "pii", "pii_email", "low", "")                               // 低危 PII
		put(5, "data_leak", "code_leak_password_in_code", "medium", "")     // 代码里的示例口令
		put(6, "catalog_policy", "rag_unauthorized_knowledge_query", "high", "")
		put(7, "data_leak", "code_leak_database_url", "critical", "")
		put(8, "semantic_attack", "prompt_input_semantic_risk", "high", "")     // 仅凭据名叫 lse- 不能进测评车道
		put(9, "pii", "pii_phone", "low", `,"rule_type":"hard_floor"`)          // 硬底线永远需行动
		put(10, "catalog_policy", "supply_unauthorized_model_call", "high", "") // 编程助手里的关键词命中：观察
		put(11, "secret", "plain_password", "critical", "")                     // 编程助手里的凭据格式：仍需行动
		put(12, "content_safety", "agent_canary_token_leak", "critical", "")    // 编程助手里的 canary：仍需行动
		// 升级安装器的自检请求（应用编号以 project_upgrade_verify_ 开头）归测评车道，但硬底线仍需行动；
		// 第 15 条的应用编号把下划线换成了别的字符，证明 SQL 里的 \_ 是字面下划线而不是通配符。
		putIn("project_upgrade_verify_0123456789abcdef", 13, "secret", "private_key", "critical", "")
		putIn("project_upgrade_verify_0123456789abcdef", 14, "pii", "pii_phone", "low", `,"rule_type":"hard_floor"`)
		putIn("projectXupgradeXverifyX0123456789", 15, "secret", "private_key", "critical", "")
		want := map[string]string{"lane-r1": "eval", "lane-r2": "action", "lane-r3": "eval", "lane-r4": "watch", "lane-r5": "watch",
			"lane-r6": "action", "lane-r7": "action", "lane-r8": "action", "lane-r9": "action",
			"lane-r10": "watch", "lane-r11": "action", "lane-r12": "action",
			"lane-r13": "eval", "lane-r14": "action", "lane-r15": "action"}
		count := map[string]int{}
		for _, lane := range want {
			count[lane]++
		}
		base := AlertOccurrenceFilter{TenantID: "lanes", Grouping: "cases", IncludeSuppressed: true, Limit: 100, LaneAware: true}
		page, err := repo.List(ctx, base)
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != len(want) || len(page.Items) != len(want) {
			t.Fatalf("lane-aware view must still list every case: total=%d items=%d", page.Total, len(page.Items))
		}
		for _, item := range page.Items {
			if item.Lane != want[item.RequestID] {
				t.Errorf("request %s category %s: lane %q want %q", item.RequestID, item.Category, item.Lane, want[item.RequestID])
			}
		}
		checkCounts := func(c AlertOccurrenceCounts, action, watch, eval int) {
			t.Helper()
			if c.LaneAction != action || c.LaneWatch != watch || c.LaneEval != eval {
				t.Fatalf("lane counts action/watch/eval=%d/%d/%d want %d/%d/%d", c.LaneAction, c.LaneWatch, c.LaneEval, action, watch, eval)
			}
		}
		checkCounts(page.Counts, count["action"], count["watch"], count["eval"])
		for lane, n := range count {
			f := base
			f.Lane = lane
			p, err := repo.List(ctx, f)
			if err != nil {
				t.Fatal(err)
			}
			if p.Total != n || len(p.Items) != n {
				t.Fatalf("lane %s total=%d items=%d want %d", lane, p.Total, len(p.Items), n)
			}
			for _, item := range p.Items {
				if item.Lane != lane {
					t.Fatalf("lane filter leaked %s item into %s", item.Lane, lane)
				}
			}
			// 车道页签数字不随当前选中的车道变化；其余统计只算当前车道。
			checkCounts(p.Counts, count["action"], count["watch"], count["eval"])
			if p.Counts.Total != n {
				t.Fatalf("per-lane scope counts must follow the selected lane: %+v", p.Counts)
			}
		}
		// 处置后只影响待处置计数；车道本身不变。
		var caseID string
		for _, item := range page.Items {
			if item.RequestID == "lane-r6" {
				caseID = item.CaseID
			}
		}
		if _, err := db.Exec(ctx, `INSERT INTO audit_dispositions(tenant_id,subject_type,subject_id,status) VALUES('lanes','alert_case',$1,'resolved')`, caseID); err != nil {
			t.Fatal(err)
		}
		pending := base
		pending.Lane, pending.Disposition = "action", "pending"
		p, err := repo.List(ctx, pending)
		if err != nil || p.Total != count["action"]-1 {
			t.Fatalf("pending action cases after one resolved: %+v %v", p, err)
		}
		checkCounts(p.Counts, count["action"]-1, count["watch"], count["eval"])
		// 不带 LaneAware 的老调用方：全局口径不变，Lane 字段仍随行返回，也没有车道计数。
		legacy := AlertOccurrenceFilter{TenantID: "lanes", Grouping: "cases", IncludeSuppressed: true, Limit: 100, RecentLimit: 4}
		p, err = repo.List(ctx, legacy)
		if err != nil || p.Total != 4 {
			t.Fatalf("legacy global cap must hold: total=%d err=%v", p.Total, err)
		}
		checkCounts(p.Counts, 0, 0, 0)
		// LaneAware 时每个车道各自保留最近 N 个，测评/观察样本不会把需行动告警挤出窗口。
		// 页签数字是该车道在范围内的真实总数，不能被窗口截成上限（否则三个页签都显示 N）。
		capped := base
		capped.RecentLimit = 2
		cappedPage, err := repo.List(ctx, capped)
		if err != nil {
			t.Fatal(err)
		}
		checkCounts(cappedPage.Counts, count["action"], count["watch"], count["eval"])
		for lane, n := range count {
			capped.Lane = lane
			wantN := n
			if wantN > 2 {
				wantN = 2
			}
			p, err = repo.List(ctx, capped)
			if err != nil || p.Total != wantN {
				t.Fatalf("per-lane cap lane=%s total=%d want %d err=%v", lane, p.Total, wantN, err)
			}
		}
	})

	t.Run("raw-evidence-count-respects-permission-and-tenant", func(t *testing.T) {
		// 只建 RequestIDsWithEvidence 用到的列；结束时删掉，不影响其他子用例“表不存在也不出错”的前提。
		if _, err := db.Exec(ctx, `CREATE TABLE content_raw_evidence(id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, request_id TEXT NOT NULL)`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = db.Exec(ctx, `DROP TABLE IF EXISTS content_raw_evidence`) })
		if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('rawev','RawEv'),('rawev-other','RawEvOther');
INSERT INTO request_logs(id,request_id,tenant_id,project_id,client_id) VALUES('l-rev1','rev-r1','rawev','rev-project','c'),('l-rev2','rev-r2','rawev','rev-project','c');
INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary,created_at) VALUES
 ('rev-e1','rev-r1','rawev','rev-project','security_check','high','audit','{"findings":[{"type":"semantic_attack","category":"prompt_input_semantic_risk","severity":"high","stage":"input","content_source":"user","message_index":0}]}'::jsonb,now()),
 ('rev-e2','rev-r2','rawev','rev-project','security_check','high','audit','{"findings":[{"type":"semantic_attack","category":"prompt_input_semantic_risk","severity":"high","stage":"input","content_source":"user","message_index":0}]}'::jsonb,now());
INSERT INTO content_raw_evidence(id,tenant_id,request_id) VALUES('rev-a','rawev','rev-r1'),('rev-b','rawev','rev-r1'),('rev-c','rawev-other','rev-r1');`); err != nil {
			t.Fatal(err)
		}
		counts := func(allowed bool) map[string]int {
			t.Helper()
			page, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: "rawev", Grouping: "hits", IncludeSuppressed: true, Limit: 100, CanViewRawEvidence: allowed})
			if err != nil {
				t.Fatal(err)
			}
			out := map[string]int{}
			for _, item := range page.Items {
				out[item.RequestID] = item.RawEvidenceCount
			}
			if len(out) != 2 {
				t.Fatalf("want 2 requests, got %+v", out)
			}
			return out
		}
		if got := counts(true); got["rev-r1"] != 2 || got["rev-r2"] != 0 {
			t.Fatalf("allowed: own tenant only, want r1=2 r2=0, got %+v", got)
		}
		if got := counts(false); got["rev-r1"] != 0 || got["rev-r2"] != 0 {
			t.Fatalf("not allowed: counts must stay 0, got %+v", got)
		}
	})

	t.Run("blocked-input-evidence-ids-respect-direction-disposition-and-tenant", func(t *testing.T) {
		rawRepo := NewRawEvidenceRepository(db)
		// 表不存在（迁移 994 之前）：空集合、无错误。
		if got, err := rawRepo.RequestIDsWithBlockedInputEvidence(ctx, "bi", []string{"bi-r1"}); err != nil || len(got) != 0 {
			t.Fatalf("missing table want empty set, got %v err=%v", got, err)
		}
		if _, err := db.Exec(ctx, `CREATE TABLE content_raw_evidence(id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, request_id TEXT NOT NULL, direction TEXT NOT NULL, disposition TEXT NOT NULL)`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = db.Exec(ctx, `DROP TABLE IF EXISTS content_raw_evidence`) })
		if _, err := db.Exec(ctx, `INSERT INTO content_raw_evidence(id,tenant_id,request_id,direction,disposition) VALUES
 ('bi-a','bi','bi-r1','input','blocked'),
 ('bi-a2','bi','bi-r1','input','blocked'),
 ('bi-b','bi','bi-r2','input','masked'),
 ('bi-c','bi','bi-r3','output','blocked'),
 ('bi-d','bi-other','bi-r4','input','blocked')`); err != nil {
			t.Fatal(err)
		}
		got, err := rawRepo.RequestIDsWithBlockedInputEvidence(ctx, "bi", []string{"bi-r1", "bi-r2", "bi-r3", "bi-r4"})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("only the own-tenant input/blocked request should be returned, got %v", got)
		}
		if _, ok := got["bi-r1"]; !ok {
			t.Fatalf("bi-r1 missing: %v", got)
		}
	})

	t.Run("generated-metadata-preserves-exact-results", func(t *testing.T) {
		filters := []AlertOccurrenceFilter{}
		for _, tenant := range []string{"t1", "cases"} {
			for _, group := range []string{"cases", "hits"} {
				filters = append(filters, AlertOccurrenceFilter{TenantID: tenant, Grouping: group, CanReadEvidence: true, IncludeRaw: true, IncludeSuppressed: true, Limit: 100})
			}
		}
		before := [][]byte{}
		for _, f := range filters {
			page, e := NewAlertOccurrenceRepository(db).List(ctx, f)
			if e != nil {
				t.Fatal(e)
			}
			b, _ := json.Marshal(page)
			before = append(before, b)
		}
		_, file, _, _ := runtime.Caller(0)
		migration, e := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../../deploy/migrations/850_alert_read_metadata.sql"))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec(ctx, string(migration)); e != nil {
			t.Fatal(e)
		}
		compact, e := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../../deploy/migrations/851_compact_nonfinding_read_metadata.sql"))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec(ctx, string(compact)); e != nil {
			t.Fatal(e)
		}
		optimized := NewAlertOccurrenceRepository(db)
		for i, f := range filters {
			page, e := optimized.List(ctx, f)
			if e != nil {
				t.Fatal(e)
			}
			b, _ := json.Marshal(page)
			if string(b) != string(before[i]) {
				t.Fatalf("derived metadata changed tenant=%s grouping=%s results", f.TenantID, f.Grouping)
			}
		}
		scoped := AlertOccurrenceFilter{TenantID: "t1", Grouping: "cases", Disposition: "pending", Limit: 100, CanReadEvidence: true}
		summary, e := optimized.SummarizeCases(ctx, scoped)
		if e != nil {
			t.Fatal(e)
		}
		listed, e := optimized.List(ctx, scoped)
		if e != nil {
			t.Fatal(e)
		}
		sum := 0
		for _, category := range summary.Categories {
			sum += category.Count
			f := scoped
			f.Category = category.Category
			p, e := optimized.List(ctx, f)
			if e != nil || p.Total != category.Count {
				t.Fatalf("summary/category mismatch: %+v %+v %v", category, p, e)
			}
		}
		if sum != summary.Total || summary.Total != listed.Total {
			t.Fatalf("summary/list mismatch: %+v %+v", summary, listed)
		}
		scoped.Category = "email,destructive_command"
		union, e := optimized.List(ctx, scoped)
		if e != nil {
			t.Fatal(e)
		}
		for _, item := range union.Items {
			if item.Category != "pii_email" && item.Category != "destructive_command" {
				t.Fatalf("category union leaked %s", item.Category)
			}
		}
		if union.Total < 2 {
			t.Fatal("category union dropped one side")
		}
		if !optimized.metadataAvailable {
			t.Fatal("generated metadata path not used")
		}
		// Incoming clients cannot forge the generated evidence identity.
		var actual, expected string
		if e = db.QueryRow(ctx, `SELECT jjd_alert_finding_metadata_v1('{"type":"semantic_attack","raw_evidence":"raw","evidence_context":"context","_jjd_evidence_identity":"forged"}'::jsonb)->>'_jjd_evidence_identity',encode(sha256(convert_to('context','UTF8')),'hex')`).Scan(&actual, &expected); e != nil || actual != expected {
			t.Fatalf("untrusted metadata identity: %q %q %v", actual, expected, e)
		}
	})

	t.Run("tool failure loop is an operational event and never an alert occurrence", func(t *testing.T) {
		// 网关 recordToolResultFailures 的真实写入形态：低危、不计入安全命中、证据类别 runtime。
		loop := `{"action_taken":"tool_failure_loop","stage":"tool","source":"gateway","findings_count":0,"findings":[{"type":"tool_failure_loop","category":"agent_tool_failure_loop","severity":"low","rule_name":"Bash","rule_type":"agentguard","action":"audit","matched_location":"tool_result","content_source":"tool_result","evidence_kind":"runtime","counts_as_security_finding":false,"redacted_evidence":"Bash 在窗口内失败 3 次"}]}`
		for _, id := range []string{"loop-1", "loop-2"} {
			insert(id, "req1", "t1", "p-loop", "security_check", "low", loop)
		}
		// 存量旧事件（2.9.16 及更早）：高危、计入安全命中、category=tool_risk，action_taken=tool_failure_loop。
		// 读取侧识别为运行观察，不再进需行动。
		legacy := `{"findings":[{"type":"tool_failure_loop","category":"tool_risk","severity":"high","rule_name":"Bash","action":"audit"}]}`
		legacyByAction := `{"findings":[{"type":"tool_risk","category":"tool_risk","severity":"high","rule_name":"Bash","action":"audit"}]}`
		insertLoop := func(id, action, summary string) {
			t.Helper()
			if _, e := db.Exec(ctx, `INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary,conversation_key) VALUES($1,'req1','t1','p-loop','security_check','high',$2,$3::jsonb,'same-conversation')`, id, action, summary); e != nil {
				t.Fatal(e)
			}
		}
		insertLoop("loop-legacy", "tool_failure_loop", legacy)
		insertLoop("loop-legacy-action", "tool_failure_loop", legacyByAction)
		// 其它 tool_risk 告警（动作不是 tool_failure_loop）仍是告警。
		insertLoop("tool-risk-real", "block", legacyByAction)
		// 老形态事件里混有真实命中：真实命中仍是安全告警。
		mixed := `{"findings":[{"type":"tool_failure_loop","category":"tool_risk","severity":"high","rule_name":"Bash"},{"type":"pii","category":"pii_email","severity":"high","rule_id":"rule-a","action":"block"}]}`
		insertLoop("loop-mixed", "tool_failure_loop", mixed)
		f := filter
		f.ProjectIDs = []string{"p-loop"}
		page, e := repo.List(ctx, f)
		if e != nil {
			t.Fatal(e)
		}
		got := map[string]bool{}
		for _, item := range page.Items {
			got[item.EventID] = true
		}
		if page.Total != 2 || len(page.Items) != 2 || !got["tool-risk-real"] || !got["loop-mixed"] {
			t.Fatalf("legacy loop events must leave the occurrence list; real tool_risk and the mixed real hit remain: %+v", page)
		}
		if page.Operational.EventCount != 5 {
			t.Fatalf("new loop events must be listed as operational events: %+v", page.Operational)
		}
	})

}
