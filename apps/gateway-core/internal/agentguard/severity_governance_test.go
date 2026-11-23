package agentguard

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

func TestSQLSeverityUsesExecutedStatements(t *testing.T) {
	for _, tc := range []struct {
		sql         string
		destructive bool
		critical    bool
	}{
		{"WITH x AS (DELETE FROM demo RETURNING *) SELECT * FROM x", true, false},
		{"WITH x AS (SELECT 1) DELETE FROM demo", true, false},
		{"WITH x AS (DELETE FROM demo RETURNING *) SELECT * FROM x WHERE id=1", true, false},
		{"EXPLAIN ANALYZE DELETE FROM demo", true, false},
		{"EXPLAIN (ANALYZE true, FORMAT JSON) DELETE FROM demo", true, false},
		{"EXPLAIN (ANALYZE false) DELETE FROM demo", false, false},
		{"EXPLAIN DELETE FROM demo", false, false},
		{"ALTER TABLE demo ADD COLUMN note TEXT", false, false},
		{"ALTER TABLE demo DROP COLUMN note", true, false},
		{"WITH x AS (SELECT 'DELETE FROM demo') SELECT * FROM x", false, false},
		{"WITH x AS (DELETE FROM demo WHERE id=1 RETURNING *) SELECT * FROM x", false, false},
		{"DROP DATABASE demo", true, true},
	} {
		t.Run(tc.sql, func(t *testing.T) {
			a := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "execute_sql", ToolType: "database", SQLDialect: "postgres", Arguments: map[string]any{"query": tc.sql}})
			if (a.Category != "") != tc.destructive {
				t.Fatalf("analysis=%+v", a)
			}
			if tc.destructive && a.RiskLevel == "low" {
				t.Fatal("destructive SQL downgraded")
			}
			d := AnalyzeSQL(tc.sql)
			if tc.destructive && (d.RiskLevel == "low" || d.RiskLevel == "medium") {
				t.Fatalf("base decision=%+v", d)
			}
			if !tc.critical && !tc.destructive && d.RiskLevel == "critical" {
				t.Fatalf("ordinary SQL critical: %+v", d)
			}
		})
	}
}

// 2.9.22：内网与云元数据是防护项；风险等级照旧区分，配成阻断时判为阻断，默认告警放行。
func TestPrivateTargetSeverityDoesNotRelaxAdmission(t *testing.T) {
	for _, tc := range []struct{ url, risk string }{{"http://127.0.0.1:3000/health", "high"}, {"http://169.254.169.254/latest/meta-data", "critical"}} {
		input := ToolCallAnalysisInput{ToolName: "fetch", ToolType: "network", Arguments: map[string]any{"url": tc.url}, Mode: ModeStrict,
			Policy: &EffectivePolicy{Mode: ModeStrict, Protections: blockingProtections(protection.GroupAgentTarget)}}
		d := AnalyzeToolCall(context.Background(), input)
		if d.RiskLevel != tc.risk || d.RawDecision != DecisionBlock {
			t.Fatalf("%s %+v", tc.url, d)
		}
		input.Policy = nil
		if byDefault := AnalyzeToolCall(context.Background(), input); byDefault.RiskLevel != tc.risk || byDefault.EffectiveDecision != DecisionAudit || !byDefault.NotificationRequired {
			t.Fatalf("%s default %+v", tc.url, byDefault)
		}
	}
}

func TestSQLReadOnlyBatchesRemainLow(t *testing.T) {
	for _, q := range []string{"SELECT 1;", "SELECT 1; SELECT 2;", "WITH x AS (SELECT 1) SELECT * FROM x;"} {
		if d := AnalyzeSQL(q); d.RiskLevel != "low" || d.RawDecision != DecisionAllow {
			t.Fatalf("%s: %+v", q, d)
		}
	}
	if d := AnalyzeSQL("SELECT 1; UPDATE demo SET note='x' WHERE id=1"); d.RiskLevel != "high" {
		t.Fatalf("scoped mutation hidden: %+v", d)
	}
}
