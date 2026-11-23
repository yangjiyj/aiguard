package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func setupAgentOperationTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AGENT_OPERATION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AGENT_OPERATION_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("agent_operation_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	_, err = db.Exec(ctx, `
		CREATE TABLE projects (id text PRIMARY KEY, tenant_id text NOT NULL, status text NOT NULL);
		CREATE TABLE agent_sessions (id text PRIMARY KEY, tenant_id text NOT NULL, agent_type text, status text NOT NULL);
		CREATE TABLE notify_channels (id text PRIMARY KEY, tenant_id text NOT NULL, type text NOT NULL, name text NOT NULL, config_json jsonb NOT NULL, enabled boolean NOT NULL);
		CREATE TABLE agent_destructive_policies (
			id text PRIMARY KEY, tenant_id text, scope_type text NOT NULL, scope_ref text NOT NULL,
			mode text NOT NULL, action text NOT NULL, protocol text NOT NULL DEFAULT '',
			discardable_paths_json jsonb NOT NULL, notify_channel_ids_json jsonb NOT NULL,
			restricted_file_patterns_json jsonb NOT NULL DEFAULT '[]'::jsonb,
			restricted_file_action text NOT NULL DEFAULT 'block',
			restricted_file_scopes_json jsonb NOT NULL DEFAULT '["tool_call","user_mention","proxy_output"]'::jsonb,
			version bigint NOT NULL, enabled boolean NOT NULL, created_by text NOT NULL, updated_by text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
			UNIQUE (tenant_id, scope_type, scope_ref)
		);
		CREATE TABLE agent_destructive_policy_audits (
			id text PRIMARY KEY, tenant_id text, actor_id text NOT NULL, source text NOT NULL,
			scope_type text NOT NULL, scope_ref text NOT NULL, before_json jsonb NOT NULL,
			after_json jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
		);
		CREATE TABLE tool_call_logs (
			id text PRIMARY KEY, tenant_id text NOT NULL, public_event_id text, operation_id text,
			event_type text, request_id text, trace_id text, application_id text, agent_type text,
			model text, protocol text, tool_name text, tool_call_id text, target_summary text,
			risk_category text, risk_subcategory text, reason_summary text, confidence float8,
			mode_default_action text, custom_action text, final_action text,
			notification_required boolean, notification_status text, discardable_path_matched boolean,
			discardable_path_reason text, execution_forwarded boolean, result_observed boolean,
			created_at timestamptz NOT NULL DEFAULT now()
		);
		CREATE UNIQUE INDEX uq_event ON tool_call_logs(tenant_id, public_event_id) WHERE public_event_id IS NOT NULL;
		INSERT INTO projects VALUES ('app-a','tenant-a','active'), ('app-b','tenant-b','active');
		INSERT INTO agent_sessions VALUES ('session-a','tenant-a','codex-a','active'), ('session-b','tenant-b','codex-b','active');
		INSERT INTO notify_channels VALUES
			('channel-a','tenant-a','webhook','A','{"secret":"hidden"}',true),
			('channel-disabled','tenant-a','webhook','Disabled','{"secret":"hidden"}',false),
			('channel-b','tenant-b','webhook','B','{"secret":"hidden"}',true);
	`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func validAgentOperationMutation() AgentOperationPolicyMutation {
	return AgentOperationPolicyMutation{
		TenantID: "tenant-a", ActorID: "owner-a", Source: "admin_api",
		ScopeType: "application", ScopeRef: "app-a", Mode: "light", Action: "alert_allow",
		DiscardablePaths: []string{"frontend/dist"}, NotifyChannelIDs: []string{"channel-a"}, ExpectedVersion: 1,
	}
}

func TestAgentOperationPolicySaveIsTenantScopedCASAndAudited(t *testing.T) {
	db := setupAgentOperationTestDB(t)
	repo := NewAgentOperationRepository(db)
	ctx := context.Background()
	for name, mutate := range map[string]func(*AgentOperationPolicyMutation){
		"foreign application": func(m *AgentOperationPolicyMutation) { m.ScopeRef = "app-b" },
		"foreign agent":       func(m *AgentOperationPolicyMutation) { m.ScopeType, m.ScopeRef = "agent", "codex-b" },
		"foreign channel":     func(m *AgentOperationPolicyMutation) { m.NotifyChannelIDs = []string{"channel-b"} },
		"disabled channel":    func(m *AgentOperationPolicyMutation) { m.NotifyChannelIDs = []string{"channel-disabled"} },
	} {
		t.Run(name, func(t *testing.T) {
			m := validAgentOperationMutation()
			mutate(&m)
			if _, err := repo.SavePolicy(ctx, m); !errors.Is(err, ErrAgentOperationNotFound) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	stored, err := repo.SavePolicy(ctx, validAgentOperationMutation())
	if err != nil {
		t.Fatal(err)
	}
	if stored.Version != 1 || stored.ConfigSource != "application" {
		t.Fatalf("stored=%+v", stored)
	}
	update := validAgentOperationMutation()
	update.ExpectedVersion = 1
	update.Action = "block"
	updated, err := repo.SavePolicy(ctx, update)
	if err != nil || updated.Version != 2 {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	stale := validAgentOperationMutation()
	stale.Action = "record"
	if _, err := repo.SavePolicy(ctx, stale); !errors.Is(err, ErrAgentOperationConflict) {
		t.Fatalf("stale err=%v", err)
	}
	var actor, source string
	var beforeRaw, afterRaw []byte
	if err := db.QueryRow(ctx, `SELECT actor_id, source, before_json, after_json FROM agent_destructive_policy_audits WHERE tenant_id='tenant-a' ORDER BY created_at DESC LIMIT 1`).Scan(&actor, &source, &beforeRaw, &afterRaw); err != nil {
		t.Fatal(err)
	}
	if actor != "owner-a" || source != "admin_api" {
		t.Fatalf("actor/source=%s/%s", actor, source)
	}
	for _, raw := range [][]byte{beforeRaw, afterRaw} {
		var fields map[string]any
		if json.Unmarshal(raw, &fields) != nil {
			t.Fatalf("invalid audit json: %s", raw)
		}
		for _, forbidden := range []string{"id", "tenant_id", "config_json", "secret"} {
			if _, ok := fields[forbidden]; ok {
				t.Fatalf("audit leaked %s: %s", forbidden, raw)
			}
		}
	}
}

func TestAgentOperationEventLookupUsesTenantAndPublicID(t *testing.T) {
	db := setupAgentOperationTestDB(t)
	repo := NewAgentOperationRepository(db)
	ctx := context.Background()
	_, err := db.Exec(ctx, `INSERT INTO tool_call_logs
		(id,tenant_id,public_event_id,operation_id,event_type,request_id,trace_id,application_id,agent_type,model,protocol,tool_name,tool_call_id,target_summary,risk_category,risk_subcategory,reason_summary,confidence,mode_default_action,custom_action,final_action,notification_required,notification_status,discardable_path_matched,execution_forwarded,result_observed)
		VALUES ('internal-db-id','tenant-a','evt_public','op-public','tool_attempt_blocked','req-1','trace-1','app-a','codex','gpt-5','responses','shell_command','call-1','filesystem_delete:1-targets','destructive_change','filesystem_delete','deterministic',0.99,'block','block','block',true,'sent',false,false,false)`)
	if err != nil {
		t.Fatal(err)
	}
	event, err := repo.GetEvent(ctx, "tenant-a", "evt_public")
	if err != nil || event.PublicEventID != "evt_public" || event.StatusCode != "blocked" {
		t.Fatalf("event=%+v err=%v", event, err)
	}
	if _, err := repo.GetEvent(ctx, "tenant-b", "evt_public"); !errors.Is(err, ErrAgentOperationNotFound) {
		t.Fatalf("cross tenant err=%v", err)
	}
}

func TestAgentOperationEventListAndChannelsAreTenantScopedPublicProjections(t *testing.T) {
	db := setupAgentOperationTestDB(t)
	repo := NewAgentOperationRepository(db)
	ctx := context.Background()
	for _, tenantID := range []string{"tenant-a", "tenant-b"} {
		_, err := db.Exec(ctx, `INSERT INTO tool_call_logs
			(id,tenant_id,public_event_id,operation_id,event_type,request_id,trace_id,application_id,agent_type,model,protocol,tool_name,tool_call_id,target_summary,risk_category,risk_subcategory,reason_summary,confidence,mode_default_action,custom_action,final_action,notification_required,notification_status,discardable_path_matched,execution_forwarded,result_observed)
			VALUES ($1,$2,$3,'op-public','tool_attempt_blocked','req-1','trace-1','app-a','codex','gpt-5','responses','shell_command','call-1','filesystem_delete:1-targets','destructive_change','filesystem_delete','deterministic',0.99,'block','block','block',true,'sent',false,false,false)`,
			"internal-"+tenantID, tenantID, "evt-"+tenantID)
		if err != nil {
			t.Fatal(err)
		}
	}
	events, total, err := repo.ListEvents(ctx, "tenant-a", AgentOperationEventFilter{Action: "block", Limit: 10})
	if err != nil || total != 1 || len(events) != 1 || events[0].PublicEventID != "evt-tenant-a" {
		t.Fatalf("events=%+v total=%d err=%v", events, total, err)
	}
	if _, err := db.Exec(ctx, `UPDATE tool_call_logs SET execution_forwarded=true WHERE tenant_id='tenant-a' AND public_event_id='evt-tenant-a'`); err != nil {
		t.Fatal(err)
	}
	events, total, err = repo.ListEvents(ctx, "tenant-a", AgentOperationEventFilter{Status: "execution_forwarded", Limit: 10})
	if err != nil || total != 1 || len(events) != 1 || events[0].StatusCode != "execution_forwarded" {
		t.Fatalf("forwarded events=%+v total=%d err=%v", events, total, err)
	}
	channels, err := repo.ListChannels(ctx, "tenant-a", []string{"channel-a", "channel-b"})
	if err != nil || len(channels) != 1 || channels[0].ID != "channel-a" || channels[0].Name != "A" {
		t.Fatalf("channels=%+v err=%v", channels, err)
	}
}

func TestAgentOperationEffectivePolicyResolvesScopeProtocolAndFallbacks(t *testing.T) {
	db := setupAgentOperationTestDB(t)
	repo := NewAgentOperationRepository(db)
	ctx := context.Background()
	policies := []AgentOperationPolicyMutation{
		{TenantID: "tenant-a", ActorID: "owner-a", Source: "test", ScopeType: "tenant", Mode: "strict", Action: "alert_allow", ExpectedVersion: 1},
		{TenantID: "tenant-a", ActorID: "owner-a", Source: "test", ScopeType: "application", ScopeRef: "app-a", Mode: "light", Action: "block", DiscardablePaths: []string{"dist"}, NotifyChannelIDs: []string{"channel-a"}, ExpectedVersion: 1},
		{TenantID: "tenant-a", ActorID: "owner-a", Source: "test", ScopeType: "agent", ScopeRef: "codex-a", Mode: "audit", Action: "confirm", Protocol: "mcp", DiscardablePaths: []string{"tmp"}, ExpectedVersion: 1},
	}
	for _, policy := range policies {
		if _, err := repo.SavePolicy(ctx, policy); err != nil {
			t.Fatal(err)
		}
	}
	application, err := repo.ResolveEffectivePolicy(ctx, "tenant-a", AgentOperationEffectivePolicyInput{ApplicationID: "app-a", AgentType: "codex-a", Protocol: "responses", Mode: "strict"})
	if err != nil || application.Action != "block" || application.ConfigSource != "application_policy" || len(application.DiscardablePaths) != 1 || application.DiscardablePaths[0] != "dist" {
		t.Fatalf("application=%+v err=%v", application, err)
	}
	mcp, err := repo.ResolveEffectivePolicy(ctx, "tenant-a", AgentOperationEffectivePolicyInput{AgentType: "codex-a", Protocol: "mcp", Mode: "strict"})
	if err != nil || mcp.Action != "confirm" || mcp.ConfigSource != "agent_policy" || mcp.Protocol != "mcp" {
		t.Fatalf("mcp=%+v err=%v", mcp, err)
	}
	responses, err := repo.ResolveEffectivePolicy(ctx, "tenant-a", AgentOperationEffectivePolicyInput{AgentType: "codex-a", Protocol: "responses", Mode: "strict"})
	if err != nil || responses.Action != "alert_allow" || responses.ConfigSource != "tenant_policy" || len(responses.NotifyChannelIDs) != 1 || responses.NotifyChannelIDs[0] != "channel-a" {
		t.Fatalf("responses=%+v err=%v", responses, err)
	}
	preset, err := repo.ResolveEffectivePolicy(ctx, "tenant-b", AgentOperationEffectivePolicyInput{Mode: "light", Protocol: "chat"})
	if err != nil || preset.Action != "alert_allow" || preset.ConfigSource != "mode_preset" {
		t.Fatalf("preset=%+v err=%v", preset, err)
	}
	fallback, err := repo.ResolveEffectivePolicy(ctx, "tenant-b", AgentOperationEffectivePolicyInput{Protocol: "responses"})
	if err != nil || fallback.Mode != "audit" || fallback.Action != "record" || fallback.ConfigSource != "system_default" {
		t.Fatalf("fallback=%+v err=%v", fallback, err)
	}
}

func TestAgentOperationGlobalBaselineAndWildcardResolution(t *testing.T) {
	db := setupAgentOperationTestDB(t)
	repo := NewAgentOperationRepository(db)
	ctx := context.Background()

	policies := []AgentOperationPolicyMutation{
		{ActorID: "platform", Source: "test", ScopeType: "tenant", Mode: "strict", Action: "block", ExpectedVersion: 1},
		{TenantID: "tenant-a", ActorID: "owner-a", Source: "test", ScopeType: "tenant", Mode: "strict", Action: "block", ExpectedVersion: 1},
		{ActorID: "platform", Source: "test", ScopeType: "agent", ScopeRef: "*", Mode: "light", Action: "alert_allow", ExpectedVersion: 1},
		{ActorID: "platform", Source: "test", ScopeType: "agent", ScopeRef: "codex-a", Mode: "strict", Action: "block", ExpectedVersion: 1},
	}
	for _, policy := range policies {
		if _, err := repo.SavePolicy(ctx, policy); err != nil {
			t.Fatal(err)
		}
	}

	newAgent, err := repo.ResolveEffectivePolicy(ctx, "tenant-b", AgentOperationEffectivePolicyInput{AgentType: "new-agent", Protocol: "responses"})
	if err != nil || newAgent.Action != "alert_allow" || newAgent.ConfigSource != "agent_policy" {
		t.Fatalf("global wildcard=%+v err=%v", newAgent, err)
	}
	tenantOverride, err := repo.ResolveEffectivePolicy(ctx, "tenant-a", AgentOperationEffectivePolicyInput{AgentType: "new-agent", Protocol: "responses"})
	if err != nil || tenantOverride.Action != "block" || tenantOverride.ConfigSource != "tenant_policy" {
		t.Fatalf("tenant override=%+v err=%v", tenantOverride, err)
	}
	exactAgent, err := repo.ResolveEffectivePolicy(ctx, "tenant-b", AgentOperationEffectivePolicyInput{AgentType: "codex-a", Protocol: "responses"})
	if err != nil || exactAgent.Action != "block" || exactAgent.ScopeRef != "codex-a" {
		t.Fatalf("global exact agent=%+v err=%v", exactAgent, err)
	}
}

func TestAgentOperationGlobalPolicyRejectsTenantObjectsAndChannels(t *testing.T) {
	db := setupAgentOperationTestDB(t)
	repo := NewAgentOperationRepository(db)
	ctx := context.Background()
	invalid := []AgentOperationPolicyMutation{
		{ActorID: "platform", Source: "test", ScopeType: "application", ScopeRef: "app-a", Mode: "strict", Action: "block", ExpectedVersion: 1},
		{ActorID: "platform", Source: "test", ScopeType: "agent", ScopeRef: "*", Mode: "light", Action: "alert_allow", NotifyChannelIDs: []string{"channel-a"}, ExpectedVersion: 1},
	}
	for _, mutation := range invalid {
		if _, err := repo.SavePolicy(ctx, mutation); err == nil {
			t.Fatalf("invalid global policy accepted: %+v", mutation)
		}
	}
}

func TestAgentOperationGlobalNotificationFallbackUsesRequestTenant(t *testing.T) {
	db := setupAgentOperationTestDB(t)
	repo := NewAgentOperationRepository(db)
	ctx := context.Background()
	if _, err := repo.SavePolicy(ctx, AgentOperationPolicyMutation{
		ActorID: "platform", Source: "test", ScopeType: "agent", ScopeRef: "*",
		Mode: "light", Action: "alert_allow", ExpectedVersion: 1,
	}); err != nil {
		t.Fatal(err)
	}
	effective, err := repo.ResolveEffectivePolicy(ctx, "tenant-b", AgentOperationEffectivePolicyInput{AgentType: "future-agent", Protocol: "responses"})
	if err != nil || len(effective.NotifyChannelIDs) != 1 || effective.NotifyChannelIDs[0] != "channel-b" {
		t.Fatalf("tenant-scoped notification fallback=%+v err=%v", effective, err)
	}
}

func TestAgentOperationPolicySaveNormalizesNilJSONArrays(t *testing.T) {
	db := setupAgentOperationTestDB(t)
	repo := NewAgentOperationRepository(db)
	ctx := context.Background()

	if _, err := repo.SavePolicy(ctx, AgentOperationPolicyMutation{
		TenantID: "tenant-a", ActorID: "owner-a", Source: "test",
		ScopeType: "tenant", Mode: "audit", Action: "record", ExpectedVersion: 1,
	}); err != nil {
		t.Fatal(err)
	}

	var pathsJSON, channelsJSON []byte
	if err := db.QueryRow(ctx, `
		SELECT discardable_paths_json, notify_channel_ids_json
		FROM agent_destructive_policies
		WHERE tenant_id='tenant-a' AND scope_type='tenant' AND scope_ref=''
	`).Scan(&pathsJSON, &channelsJSON); err != nil {
		t.Fatal(err)
	}
	if string(pathsJSON) != "[]" || string(channelsJSON) != "[]" {
		t.Fatalf("stored arrays=%s/%s, want []/[]", pathsJSON, channelsJSON)
	}
}
