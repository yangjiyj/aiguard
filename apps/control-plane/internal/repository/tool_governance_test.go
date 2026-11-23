package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func toolGovernanceDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("TOOL_RISK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TOOL_RISK_TEST_DATABASE_URL is required for governance database validation")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("connect isolated fixture")
	}
	schema := fmt.Sprintf("tool_governance_%d", time.Now().UnixNano())
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("parse isolated fixture")
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("connect isolated schema")
	}
	t.Cleanup(func() { db.Close(); _, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE"); admin.Close() })
	_, err = db.Exec(ctx, `
	 CREATE TABLE tool_risk_config (
	  id text PRIMARY KEY,tenant_id text NOT NULL,tool_name text NOT NULL,tool_type text NOT NULL,
	  risk_level text NOT NULL,action text NOT NULL,description text NOT NULL,
	  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
	  UNIQUE(tenant_id,tool_name));
	 CREATE TABLE tool_call_logs (
	  id text PRIMARY KEY,tenant_id text NOT NULL,tool_name text NOT NULL,tool_type text NOT NULL,
	  event_kind text,execution_observed boolean DEFAULT false,result_observed boolean DEFAULT false,
	  raw_decision text,effective_decision text,mode text,result text,provenance text,protocol text,
	  parameters jsonb DEFAULT '{}'::jsonb,created_at timestamptz NOT NULL);`)
	if err != nil {
		t.Fatal(err)
	}
	return db, ctx
}

func TestToolGovernanceObservedInventoryTenantWindowFactsAndNoPayload(t *testing.T) {
	db, ctx := toolGovernanceDB(t)
	now := time.Now().UTC()
	_, err := db.Exec(ctx, `INSERT INTO tool_call_logs(id,tenant_id,tool_name,tool_type,event_kind,execution_observed,result_observed,parameters,result,created_at) VALUES
	 ('d','a','Read','file','definition_exposed',false,false,'{"secret":"never-expose"}','private-output',$1),
	 ('p','a','Read','file','invocation_proposed',false,false,'{}','',$1),
	 ('f','a','Read','network','execution_forwarded',true,false,'{}','',$1),
	 ('badf','a','Read','file','execution_forwarded',false,false,'{}','',$1),
	 ('r','a','Read','file','result_observed',false,true,'{}','',$1),
	 ('u','a','Read','file','unknown_kind',false,false,'{}','',$1),
	 ('foreign','b','SecretForeign','file','invocation_proposed',false,false,'{}','',$1),
	 ('old','a','TooOld','file','invocation_proposed',false,false,'{}','',$2),
	 ('upper','a','AtEnd','file','invocation_proposed',false,false,'{}','',$3)`, now.Add(-time.Hour), now.Add(-8*24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	items, truncated, err := NewToolCallLogRepository(db).GetObservedTools(ctx, "a", now.Add(-7*24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if truncated || len(items) != 1 {
		t.Fatalf("inventory=%+v truncated=%t", items, truncated)
	}
	item := items[0]
	if item.ToolName != "Read" || len(item.ToolTypes) != 2 || item.DefinitionExposedCount != 1 || item.InvocationProposedCount != 1 || item.ExecutionForwardedCount != 1 || item.ResultObservedCount != 1 || item.UnknownEventCount != 1 || item.EventCount != 6 {
		t.Fatalf("facts=%+v", item)
	}
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"never-expose", "private-output", "parameters", "SecretForeign", "TooOld", "AtEnd"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("private or outside-window data exposed: %s", secret)
		}
	}
}

func TestToolGovernanceObservedInventoryLimitAndInvalidWindow(t *testing.T) {
	db, ctx := toolGovernanceDB(t)
	now := time.Now().UTC()
	_, err := db.Exec(ctx, `INSERT INTO tool_call_logs(id,tenant_id,tool_name,tool_type,event_kind,created_at)
	 SELECT 'id-'||n,'a','Tool-'||n,'system','definition_exposed',$1 FROM generate_series(1,201) n`, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	repo := NewToolCallLogRepository(db)
	items, truncated, err := repo.GetObservedTools(ctx, "a", now.Add(-7*24*time.Hour), now)
	if err != nil || !truncated || len(items) != 200 {
		t.Fatalf("len=%d truncated=%t error=%v", len(items), truncated, err)
	}
	if _, _, err := repo.GetObservedTools(ctx, "a", now.Add(-8*24*time.Hour), now); err == nil {
		t.Fatal("unbounded window accepted")
	}
	if _, _, err := repo.GetObservedTools(ctx, "", now.Add(-time.Hour), now); err == nil {
		t.Fatal("empty tenant accepted")
	}
}

func TestToolGovernanceBatchPreservesExistingPolicyAndTenant(t *testing.T) {
	db, ctx := toolGovernanceDB(t)
	repo := NewToolRiskConfigRepository(db)
	old := ToolRiskConfig{TenantID: "a", ToolName: "Bash", ToolType: "system", RiskLevel: "critical", Action: "block", Description: "custom"}
	if err := repo.Create(ctx, &old); err != nil {
		t.Fatal(err)
	}
	configs := []ToolRiskConfig{{ToolName: "Bash", ToolType: "file", RiskLevel: "low", Action: "audit"}, {ToolName: "Read", ToolType: "file", RiskLevel: "medium", Action: "audit"}}
	applied, skipped, err := repo.BatchUpsertPreserving(ctx, "a", configs, true)
	if err != nil || applied != 1 || skipped != 1 {
		t.Fatalf("applied=%d skipped=%d err=%v", applied, skipped, err)
	}
	got, err := repo.GetByToolName(ctx, "a", "Bash")
	if err != nil || got.ToolType != old.ToolType || got.RiskLevel != old.RiskLevel || got.Action != old.Action || got.Description != old.Description || !got.UpdatedAt.Equal(old.UpdatedAt) {
		t.Fatalf("existing policy changed: %+v err=%v", got, err)
	}
	applied, skipped, err = repo.BatchUpsertPreserving(ctx, "b", configs[:1], true)
	if err != nil || applied != 1 || skipped != 0 {
		t.Fatalf("tenant isolation failed: %d/%d/%v", applied, skipped, err)
	}
}

func TestToolGovernanceBatchInvalidSecondCandidateMakesNoWrites(t *testing.T) {
	db, ctx := toolGovernanceDB(t)
	repo := NewToolRiskConfigRepository(db)
	for _, preserve := range []bool{false, true} {
		configs := []ToolRiskConfig{{ToolName: "Read", ToolType: "file"}, {ToolName: "Bash", ToolType: "invalid", Action: "block"}}
		if _, _, err := repo.BatchUpsertPreserving(ctx, "a", configs, preserve); err == nil {
			t.Fatal("invalid second entry accepted")
		}
		var count int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM tool_risk_config").Scan(&count); err != nil || count != 0 {
			t.Fatalf("partial writes=%d err=%v", count, err)
		}
	}
}

func TestToolGovernanceBatchRollsBackInjectedSecondWriteFailure(t *testing.T) {
	db, ctx := toolGovernanceDB(t)
	_, err := db.Exec(ctx, `CREATE FUNCTION reject_tool_config() RETURNS trigger LANGUAGE plpgsql AS $$
	 BEGIN IF NEW.tool_name='Reject' THEN RAISE EXCEPTION 'injected failure'; END IF; RETURN NEW; END $$;
	 CREATE TRIGGER reject_tool_config BEFORE INSERT ON tool_risk_config FOR EACH ROW EXECUTE FUNCTION reject_tool_config();`)
	if err != nil {
		t.Fatal(err)
	}
	repo := NewToolRiskConfigRepository(db)
	configs := []ToolRiskConfig{{ToolName: "Read", ToolType: "file"}, {ToolName: "Reject", ToolType: "system"}}
	for _, preserve := range []bool{false, true} {
		if _, _, err := repo.BatchUpsertPreserving(ctx, "a", configs, preserve); err == nil {
			t.Fatal("injected error not returned")
		}
		var count int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM tool_risk_config").Scan(&count); err != nil || count != 0 {
			t.Fatalf("partial writes=%d err=%v", count, err)
		}
	}
}

func TestToolGovernanceValidationRejectsUnsupportedAndDuplicateInputs(t *testing.T) {
	for _, config := range []ToolRiskConfig{
		{ToolName: "", ToolType: "system"}, {ToolName: "Bash\n", ToolType: "system"},
		{ToolName: "Bash", ToolType: "unknown"}, {ToolName: "Bash", ToolType: "system", RiskLevel: "danger"},
		{ToolName: "Bash", ToolType: "system", Action: "disable"}, {ToolName: strings.Repeat("x", 256), ToolType: "file"},
	} {
		if err := ValidateToolRiskConfig(&config); err == nil {
			t.Fatalf("accepted invalid candidate %+v", config)
		}
	}
	configs := []ToolRiskConfig{{ToolName: "Read", ToolType: "file"}, {ToolName: "Read", ToolType: "file"}}
	if err := validateToolRiskBatch("a", configs); err == nil {
		t.Fatal("duplicate input accepted")
	}
}
